#!/usr/bin/env python3
"""Audit and dynamically verify the packed and obfuscated acceptance binaries.

For every frozen target the script imports the shipped binary, runs the real
agent audit (recovery tools included for packed and obfuscated images), then
executes the product runtime against the defect build and its corrected build
in the same configuration. The expected contrast is a reproduced defect on
1.0.0 and a clean result on 1.0.1.

Usage:
  py -3 scripts/audit_protected_tools.py --batch protected-acceptance-20260911-r1
  py -3 scripts/audit_protected_tools.py --batch <name> --target P1 --runtime-only
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
import uuid

from aegis import ROOT, environment
from e2e import stop

sys.path.insert(0, str(ROOT / 'tests'))
from smoke import API


CATALOG = ROOT / 'evaluation/targets/protected-tools.json'
BUILD_BATCH = 'protected-tools-20260911-r3'
BUILDS = ROOT / '.data/verification/protected-tools' / BUILD_BATCH
TERMINAL_RUN = {'COMPLETED', 'PARTIAL', 'FAILED', 'CANCELLED', 'LIMIT_REACHED'}
TERMINAL_RECORD = {'REPRODUCED', 'NOT_REPRODUCED', 'NO_CRASH_OBSERVED', 'VERIFIED_COMPONENT',
                   'INCONCLUSIVE', 'ERROR', 'CANCELLED'}

# Runtime recipe per target: adapter, observer, fixtures and the normal/defect input pair.
RUNTIME = {
    'P1': {
        'observer': 'FILE_CREATED', 'marker_path': 'escaped.txt',
        'fixtures': [{'path': 'payload.txt', 'content': 'parcel'}],
        'baseline': ['inbox', 'payload.txt', 'payload.txt'],
        'probe': ['inbox', '..\\escaped.txt', 'payload.txt'],
        'defect': 'the entry name escapes the flat inbox',
    },
    'P2': {
        'observer': 'SANITIZER', 'marker_path': '',
        'fixtures': [{'path': 'record.rv', 'content': 'RV1' + ' ' + 'A' * 32},
                     {'path': 'long.rv', 'content': 'RV1' + '`' + 'B' * 96}],
        'baseline': ['record.rv'],
        'probe': ['long.rv'],
        'defect': 'the record label write leaves the committed page',
    },
    'O1': {
        'observer': 'FILE_CREATED', 'marker_path': 'exported.txt',
        'fixtures': [{'path': 'account.txt', 'content': 'alice|secret|guest'},
                     {'path': 'record.txt', 'content': 'ledger-entry'}],
        'baseline': ['account.txt', 'alice', 'secret', 'guest', 'status', 'record.txt', 'exported.txt'],
        'probe': ['account.txt', 'alice', 'secret', 'admin', 'export', 'record.txt', 'exported.txt'],
        'defect': 'the requested role authorizes a restricted export',
    },
    'O2': {
        'observer': 'FILE_CREATED', 'marker_path': 'injected.txt',
        'fixtures': [{'path': 'doc.txt', 'content': 'report-body'},
                     {'path': 'doc.txt & copy doc.txt injected.txt', 'content': 'report-body'}],
        'baseline': ['doc.txt'],
        'probe': ['doc.txt & copy doc.txt injected.txt'],
        'defect': 'the document name reaches the command interpreter',
    },
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def state(value: str) -> str:
    return value.split('_STATE_')[-1]


def save(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    for attempt in range(6):
        try:
            temporary.replace(path)
            return
        except PermissionError:
            if attempt == 5:
                raise
            time.sleep(0.05 * (2 ** attempt))


def wait_run(api: API, run_id: str, timeout: float, on_progress=None) -> dict:
    deadline = time.monotonic() + timeout
    previous = None
    while True:
        run = api.rpc('RunService', 'GetRun', runId=run_id)['run']
        summary = json.loads(run.get('summaryJson', '{}'))
        progress = (state(run['state']), summary.get('audited_unit_count'), summary.get('finding_count'))
        if progress != previous and on_progress:
            on_progress(progress)
            previous = progress
        if state(run['state']) in TERMINAL_RUN or time.monotonic() >= deadline:
            return run
        time.sleep(4)


def wait_record(api: API, record_id: str, timeout: float) -> dict:
    deadline = time.monotonic() + timeout
    while True:
        record = api.rpc('RuntimeService', 'GetRuntime', recordId=record_id)['record']
        if record['status'] in TERMINAL_RECORD or time.monotonic() >= deadline:
            return record
        time.sleep(2)


def runtime_config(target: dict, recipe: dict, path: str) -> dict:
    return {
        'mode': 'VERIFY',
        'adapter': 'WINDOWS_ORIGINAL_PE64',
        'path': path,
        'function': '',
        'globals': {},
        'fixtures': recipe['fixtures'],
        'baseline': {'args': recipe['baseline'], 'kwargs': {}, 'stdin': ''},
        'probe': {'args': recipe['probe'], 'kwargs': {}, 'stdin': ''},
        'observer': recipe['observer'],
        'marker_path': recipe['marker_path'],
        'repeats': 2,
        'timeout_seconds': 5,
        'fuzz': {'engine': 'MUTATION', 'input_mode': 'STDIN', 'seeds': ['hello'],
                 'max_cases': 256, 'budget_seconds': 30, 'random_seed': 71413},
    }


def source_run_id(api: API, record: dict, name: str) -> str:
    """Return the run that owns the runtime record, creating a cancelled one if needed."""
    if record.get('run_id'):
        return record['run_id']
    if not record.get('source_run_id'):
        run = api.rpc('RunService', 'CreateRun', requestId=str(uuid.uuid4()),
                      snapshotId=record['snapshot_id'], scope='STRUCTURE_ANALYSIS')['run']
        record['source_run_id'] = run['id']
        api.rpc('RunService', 'CancelRun', runId=run['id'])
        api.wait('RunService', 'GetRun', 'run', ('CANCELLED', 'COMPLETED', 'PARTIAL'),
                 runId=run['id'], timeout=300)
    return record['source_run_id']


def collect_reports(api: API, run_id: str, folder: Path, document: dict, key: str) -> dict:
    output = {}
    result = document.setdefault(key, {})
    for fmt, extension in [('json', 'json'), ('html', 'html'), ('markdown', 'md')]:
        item = result.setdefault(fmt, {'request_id': str(uuid.uuid4())})
        if 'artifact_id' not in item:
            item['report'] = api.rpc('ReportService', 'CreateReport', requestId=item['request_id'],
                                     runId=run_id, format=fmt)['report']
            item['artifact_id'] = item['report']['artifactId']
        data = api.download(item['artifact_id'])
        (folder / ('report-' + fmt + '.' + extension)).write_bytes(data)
        output[fmt] = item['artifact_id']
    return output


def exercise(api: API, output: Path, targets: list[dict], static: bool, runtime: bool,
             config: dict, document: dict, resume: bool) -> None:
    api_checkpoint = lambda: save(output / 'summary.json', document)
    project = document.get('project')
    if project is None:
        project = api.rpc('ProjectService', 'CreateProject', requestId=str(uuid.uuid4()),
                          name='受保护闭源二进制验收')['project']
        document['project'] = project
        api_checkpoint()

    for entry in targets:
        spec = document['results'].setdefault(entry['id'], {'id': entry['id'], 'name': entry['name'],
                                                            'protection': entry['protection']})
        folder = output / entry['id']
        folder.mkdir(parents=True, exist_ok=True)
        for label, version in (('defect', '1.0.0'), ('corrected', '1.0.1')):
            record = spec.setdefault(label, {'version': version})
            binary = BUILDS / 'targets' / entry['id'] / version / (entry['name'] + '.exe')
            record['path'] = str(binary.relative_to(ROOT))
            record.setdefault('sha256', entry['sha256'])
            if 'snapshot_id' not in record:
                artifact = api.upload(entry['name'] + '.exe', binary.read_bytes(),
                                      'application/octet-stream')
                snapshot = api.rpc('ProjectService', 'CreateSnapshot', requestId=str(uuid.uuid4()),
                                   projectId=project['id'], name=entry['name'] + '-' + version + '.exe',
                                   kind='TARGET_KIND_BINARY', artifactId=artifact)['snapshot']
                snapshot = api.wait('ProjectService', 'GetSnapshot', 'snapshot', ('READY', 'PARTIAL'),
                                    snapshotId=snapshot['id'], timeout=900)
                record['snapshot_id'] = snapshot['id']
                record['snapshot_state'] = snapshot['state']
                record['target_sha256'] = snapshot['targetSha256']
                api_checkpoint()
            if static and label == 'defect' and not record.get('run_id') and not resume:
                run = api.rpc('RunService', 'CreateRun', requestId=str(uuid.uuid4()),
                              snapshotId=record['snapshot_id'], scope='SECURITY_AUDIT', **config)['run']
                record['run_id'] = run['id']
                record['url'] = api.base + '/#/runs/' + run['id']
                api_checkpoint()
                print(entry['id'] + ' audit: ' + record['url'], flush=True)
            if record.get('run_id') and not record.get('audit_complete'):
                run = wait_run(api, record['run_id'], config['timeoutSeconds'] + 600,
                               on_progress=lambda p, i=entry['id']: print(i + ' audit: ' + json.dumps(p), flush=True))
                audit = api.rpc('FindingService', 'GetAudit', runId=record['run_id'])
                save(folder / 'audit.json', {'run': run, 'audit': audit})
                summary = json.loads(run.get('summaryJson', '{}'))
                record['state'] = run['state']
                record['error'] = run.get('error', '')
                record['summary'] = {key: summary.get(key) for key in
                                     ('vulnerability_audit', 'independent_review', 'recovery',
                                      'audited_unit_count', 'finding_count', 'files')}
                record['findings'] = [
                    {'id': item['id'], 'category': item.get('category'),
                     'title': item.get('title'), 'review_status': item.get('reviewStatus'),
                     'verification_status': item.get('verificationStatus', ''),
                     'unit_id': item.get('unitId', ''), 'cwe': item.get('cwe', ''),
                     'severity': item.get('severity', '')}
                    for item in audit.get('findings', [])]
                record['tasks'] = {}
                for task in audit.get('tasks', []):
                    record['tasks'][task['role']] = record['tasks'].get(task['role'], 0) + 1
                record['model_calls'] = len(audit.get('modelCalls', []))
                record['reports'] = collect_reports(api, record['run_id'], folder, record, 'reports')
                record['audit_complete'] = True
                api_checkpoint()
            if runtime and not record.get('runtime_record_id') and not resume:
                source = source_run_id(api, record, entry['name'])
                config_json = runtime_config(entry, RUNTIME[entry['id']], entry['name'] + '.exe')
                runtime_record = api.rpc('RuntimeService', 'CreateRuntime', requestId=str(uuid.uuid4()),
                                         sourceRunId=source,
                                         findingId='', configJson=json.dumps(config_json))['record']
                record['runtime_record_id'] = runtime_record['id']
                record['runtime_config'] = config_json
                api_checkpoint()
            if record.get('runtime_record_id') and not record.get('runtime_complete'):
                runtime_record = wait_record(api, record['runtime_record_id'], 900)
                record['runtime_status'] = runtime_record['status']
                result = json.loads(runtime_record['resultJson']) if runtime_record.get('resultJson') else {}
                observation = result.get('observation', {})
                record['runtime'] = {
                    'status': runtime_record['status'],
                    'verdict': result.get('verdict', runtime_record['status']),
                    'trials': [{'label': trial['label'], 'exit_code': trial['exit_code'],
                                'observed': trial['observed'], 'timed_out': trial['timed_out'],
                                'crash_signature': trial.get('crashSignature', '')}
                               for trial in observation.get('trials', [])],
                    'error': observation.get('error', ''),
                }
                record['runtime_reports'] = collect_reports(api, runtime_record['runId'], folder,
                                                            record, 'runtime_reports')
                record['runtime_complete'] = True
                api_checkpoint()
            print(entry['id'] + ' ' + label + ': ' + json.dumps(
                {'state': record.get('state'), 'runtime': record.get('runtime_status')}), flush=True)


def start_services(output: Path) -> tuple[str, list, ExitStack]:
    credential = ROOT / '.data/server/deepseek.token'
    if not credential.is_file():
        raise RuntimeError('No configured local model credential')
    data = output / 'server-data'
    data.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(credential, data / 'deepseek.token')
    if (ROOT / '.data/server/model.json').is_file():
        shutil.copyfile(ROOT / '.data/server/model.json', data / 'model.json')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    suffix = '.exe' if sys.platform == 'win32' else ''
    env = environment()
    stack = ExitStack()
    server_log = stack.enter_context((output / 'server.log').open('w'))
    executor_log = stack.enter_context((output / 'executor.log').open('w'))
    flags = {'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP} if sys.platform == 'win32' else {}
    processes = []
    server = subprocess.Popen(
        [str(ROOT / 'target/debug' / ('aegis-server' + suffix)), '--bind', f'127.0.0.1:{port}',
         '--data-dir', str(data)], cwd=ROOT, env=env, stdout=server_log, stderr=subprocess.STDOUT, **flags)
    processes.append(server)
    base = f'http://127.0.0.1:{port}'
    for _ in range(200):
        try:
            API(base)
            break
        except OSError:
            if server.poll() is not None:
                raise RuntimeError('Test service exited; inspect its log')
            time.sleep(0.1)
    else:
        raise RuntimeError('Test service failed to start')
    executor = subprocess.Popen(
        [str(ROOT / 'target/debug' / ('aegis-executor' + suffix)), '--server', base,
         '--work-dir', str(output / ('executor-' + str(port))),
         '--bootstrap-file', str(data / 'executor-bootstrap.token')],
        cwd=ROOT, env=env, stdout=executor_log, stderr=subprocess.STDOUT, **flags)
    processes.append(executor)
    for _ in range(60):
        if executor.poll() is not None:
            raise RuntimeError('Executor exited during startup; inspect the batch executor log')
        capabilities = API(base).rpc('SystemService', 'GetCapabilities').get('executors', [])
        if any(item.get('capabilities') for item in capabilities):
            break
        time.sleep(0.5)
    else:
        raise RuntimeError('Executor did not register within 30 seconds')
    return base, processes, stack


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--batch', required=True)
    parser.add_argument('--server', help='Reuse a running server instead of starting an isolated one')
    parser.add_argument('--target', action='append', help='Limit to one target ID; repeatable')
    parser.add_argument('--runtime-only', action='store_true', help='Skip the agent audit stage')
    parser.add_argument('--collect-only', action='store_true', help='Export saved runs without new work')
    parser.add_argument('--max-model-calls', type=int, default=160)
    parser.add_argument('--max-units', type=int, default=12)
    parser.add_argument('--max-tool-rounds', type=int, default=10)
    parser.add_argument('--timeout-seconds', type=int, default=3600)
    parser.add_argument('--model-timeout-seconds', type=int, default=240)
    options = parser.parse_args()
    if Path(options.batch).name != options.batch:
        parser.error('--batch must be a single directory name')
    catalog = json.loads(CATALOG.read_text(encoding='utf-8'))
    builds = json.loads((BUILDS / 'build.json').read_text(encoding='utf-8'))
    hashes = {(item['id'], item['version']): item['sha256'] for item in builds['targets']}
    targets = [dict(item, sha256=hashes[(item['id'], '1.0.0')]) for item in catalog]
    if options.target:
        selected = set(options.target)
        if not selected.issubset({item['id'] for item in targets}):
            parser.error('unknown target ID')
        targets = [item for item in targets if item['id'] in selected]
    output = ROOT / '.data/verification/protected-acceptance' / options.batch
    output.mkdir(parents=True, exist_ok=True)
    path = output / 'summary.json'
    document = json.loads(path.read_text(encoding='utf-8')) if path.exists() else {
        'schema_version': 1, 'batch': options.batch, 'created_at': now(),
        'build_batch': BUILD_BATCH,
        'build_sha256': [{'id': key[0], 'version': key[1], 'sha256': value}
                         for key, value in hashes.items()],
        'scope': 'PROTECTED_BINARY_ACCEPTANCE', 'formal_acceptance': False, 'results': {},
    }
    config = {'maxModelCalls': options.max_model_calls, 'maxUnits': options.max_units,
              'maxToolRounds': options.max_tool_rounds, 'timeoutSeconds': options.timeout_seconds,
              'maxOutputTokens': 0, 'reasoningEffort': 'high',
              'modelTimeoutSeconds': options.model_timeout_seconds}
    document['audit_config'] = config
    static = not (options.runtime_only or options.collect_only)
    processes = []
    stack = ExitStack()
    try:
        if options.server:
            base = options.server
        else:
            base, processes, stack = start_services(output)
        document['server'] = base
        exercise(API(base), output, targets, static, not options.collect_only, config,
                 document, options.collect_only)
    finally:
        for process in reversed(processes):
            stop(process)
        stack.close()
        document['updated_at'] = now()
        save(output / 'summary.json', document)
    verdicts = []
    for entry in targets:
        spec = document['results'].get(entry['id'], {})
        defect = spec.get('defect', {})
        corrected = spec.get('corrected', {})
        verdicts.append({
            'id': entry['id'],
            'defect_runtime': defect.get('runtime_status'),
            'corrected_runtime': corrected.get('runtime_status'),
            'defect_findings': len(defect.get('findings', [])),
            'paired': defect.get('runtime_status') == 'REPRODUCED'
                      and corrected.get('runtime_status') == 'NOT_REPRODUCED',
        })
    document['verdicts'] = verdicts
    save(output / 'summary.json', document)
    print(json.dumps({'evidence': str(output / 'summary.json'), 'verdicts': verdicts},
                     ensure_ascii=False, indent=2))
    return 0 if all(item['paired'] for item in verdicts) else 1


if __name__ == '__main__':
    raise SystemExit(main())
