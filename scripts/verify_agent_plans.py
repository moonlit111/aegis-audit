#!/usr/bin/env python3
"""Re-run the verification recipe the agent itself proposed for each demo target.

The plans are read from a private copy of the workspace database, so the demo
instance keeps exactly its curated runs. Each plan is executed by the product
against the same immutable 1.0.0 snapshot the audit used.

Usage: py -3 scripts/verify_agent_plans.py --output-batch agent-plan-20260911
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import json
import shutil
import socket
import sqlite3
import subprocess
import sys
import time
import uuid
from pathlib import Path

from aegis import ROOT, environment
from e2e import stop

sys.path.insert(0, str(ROOT / 'tests'))
from smoke import API


TARGETS = [
    ('P1', 'ParcelDrop.exe', 'PATH_TRAVERSAL'),
    ('P2', 'RowVault.exe', 'MEMORY_BOUNDS'),
    ('O1', 'PermitLedger.exe', 'AUTHORIZATION'),
    ('O2', 'TextRelay.exe', 'INJECTION'),
]
TERMINAL = {'REPRODUCED', 'NOT_REPRODUCED', 'NO_CRASH_OBSERVED', 'VERIFIED_COMPONENT',
            'INCONCLUSIVE', 'ERROR', 'CANCELLED'}


def agent_plans(database: Path) -> dict:
    connection = sqlite3.connect('file:{}?mode=ro'.format(database.as_posix()), uri=True)
    plans = {}
    for (data,) in connection.execute('select data from agent_tasks order by created_at'):
        task = json.loads(data)
        if task['role'] != 'VERIFIER' or task['status'] != 'SUCCEEDED':
            continue
        result = task.get('result') or {}
        config = result.get('config') or {}
        name = Path(config.get('path', '')).name
        if result.get('status') == 'READY' and name:
            plans[name] = {'task_id': task['id'], 'run_id': task['run_id'],
                           'config': config, 'rationale': result.get('rationale', '')}
    return plans


def start_services(data: Path, output: Path) -> tuple[str, list, ExitStack]:
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    suffix = '.exe' if sys.platform == 'win32' else ''
    env = environment()
    stack = ExitStack()
    server_log = stack.enter_context((output / 'server.log').open('w'))
    executor_log = stack.enter_context((output / 'executor.log').open('w'))
    flags = {'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP} if sys.platform == 'win32' else {}
    processes = [
        subprocess.Popen([str(ROOT / 'target/debug' / ('aegis-server' + suffix)),
                          '--bind', f'127.0.0.1:{port}', '--data-dir', str(data)],
                         cwd=ROOT, env=env, stdout=server_log, stderr=subprocess.STDOUT, **flags)
    ]
    base = f'http://127.0.0.1:{port}'
    for _ in range(200):
        try:
            API(base)
            break
        except OSError:
            if processes[0].poll() is not None:
                raise RuntimeError('verification service exited; inspect its log')
            time.sleep(0.1)
    else:
        raise RuntimeError('verification service did not start')
    processes.append(subprocess.Popen(
        [str(ROOT / 'target/debug' / ('aegis-executor' + suffix)), '--server', base,
         '--work-dir', str(output / 'executor'),
         '--bootstrap-file', str(data / 'executor-bootstrap.token')],
        cwd=ROOT, env=env, stdout=executor_log, stderr=subprocess.STDOUT, **flags))
    for _ in range(60):
        if processes[1].poll() is not None:
            raise RuntimeError('verification executor exited; inspect its log')
        if any(item.get('capabilities') for item in API(base).rpc('SystemService', 'GetCapabilities')
               .get('executors', [])):
            break
        time.sleep(0.5)
    return base, processes, stack


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--batch', default='agent-plan-20260911')
    parser.add_argument('--wait-seconds', type=int, default=300)
    options = parser.parse_args()
    if Path(options.batch).name != options.batch:
        parser.error('--batch must be a single directory name')
    output = ROOT / '.data/verification/protected-acceptance' / options.batch
    output.mkdir(parents=True, exist_ok=True)
    data = output / 'server-data'
    data.mkdir(exist_ok=True)
    for name in ('aegis.sqlite', 'aegis.sqlite-shm', 'aegis.sqlite-wal', 'deepseek.token',
                 'model.json', 'executor-bootstrap.token'):
        source = ROOT / '.data/server' / name
        if source.is_file():
            shutil.copyfile(source, data / name)
    blobs = data / 'blobs'
    if not blobs.exists():
        shutil.copytree(ROOT / '.data/server/blobs', blobs)
    plans = agent_plans(data / 'aegis.sqlite')
    processes, stack = [], ExitStack()
    results = []
    try:
        base, processes, stack = start_services(data, output)
        api = API(base)
        connection = sqlite3.connect('file:{}?mode=ro'.format((data / 'aegis.sqlite').as_posix()),
                                     uri=True)
        for target_id, exe, category in TARGETS:
            plan = plans.get(exe)
            entry = {'id': target_id, 'target': exe, 'category': category}
            if not plan:
                entry['result'] = 'NO_PLAN'
                results.append(entry)
                print(target_id + ': no READY plan found', flush=True)
                continue
            rows = [json.loads(row[0]) for row in
                    connection.execute('select data from audit_runs where id=?', (plan['run_id'],))]
            if not rows:
                entry['result'] = 'RUN_MISSING'
                results.append(entry)
                continue
            snapshot_id = rows[0]['snapshot_id']
            record = api.rpc('RuntimeService', 'CreateRuntime', requestId=str(uuid.uuid4()),
                             sourceRunId=plan['run_id'], findingId='',
                             configJson=json.dumps(plan['config']))['record']
            deadline = time.monotonic() + options.wait_seconds
            while time.monotonic() < deadline:
                record = api.rpc('RuntimeService', 'GetRuntime', recordId=record['id'])['record']
                if record['status'] in TERMINAL:
                    break
                time.sleep(1)
            runtime_run = api.rpc('RunService', 'GetRun', runId=record['runId'])['run']
            summary = json.loads(runtime_run.get('summaryJson', '{}'))
            observation = (json.loads(record.get('resultJson') or '{}').get('observation') or {})
            entry.update({
                'result': record['status'],
                'exploitation': summary.get('exploitation', 'NOT_RUN'),
                'snapshot_id': snapshot_id,
                'record_id': record['id'],
                'run_id': record['runId'],
                'url': base + '/#/runs/' + record['runId'],
                'plan_rationale': plan['rationale'][:400],
                'config': plan['config'],
                'trials': [{'label': t['label'], 'exit_code': t['exit_code'],
                            'observed': t['observed'], 'crash_signature': t.get('crashSignature', '')}
                           for t in observation.get('trials', [])],
                'error': observation.get('error', ''),
            })
            results.append(entry)
            print(target_id + ': ' + json.dumps({k: entry[k] for k in
                                                 ('result', 'exploitation')}), flush=True)
    finally:
        for process in reversed(processes):
            stop(process)
        stack.close()
    document = {
        'schema_version': 1,
        'batch': options.batch,
        'verified_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'platform': 'windows/x64',
        'scope': 'AGENT_PLAN_VERIFICATION',
        'method': 'The agent-proposed VERIFY recipes were executed by the product against the same 1.0.0 snapshot; the workspace database was copied first.',
        'results': results,
        'passed': all(item.get('result') in ('REPRODUCED', 'VERIFIED_COMPONENT') for item in results),
    }
    path = output / 'summary.json'
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'passed': document['passed'], 'evidence': str(path)}, ensure_ascii=False))
    return 0 if document['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
