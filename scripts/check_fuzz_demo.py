#!/usr/bin/env python3
"""Import the self-authored RecordView pair and verify the real local product FUZZ workflow."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import time
from urllib.parse import urlparse
import uuid

from aegis import ROOT, require_windows
from build_fuzz_demo import configuration
from check_c_ares_cve import digest, run, write_json

sys.path.insert(0, str(ROOT / 'tests'))
from smoke import API


def replay_succeeded(item: dict, receipt: dict) -> bool:
    if not item['fixed']:
        return (receipt['exit_code'] != 0
                and 'ERROR: AddressSanitizer: heap-buffer-overflow' in receipt['stderr']
                and 'READ of size' in receipt['stderr'])
    expected = 0 if item['libfuzzer'] else 3
    return (receipt['exit_code'] == expected
            and 'AddressSanitizer:' not in receipt['stderr']
            and (item['libfuzzer'] or receipt['stdout'].startswith('Rejected:')))


def exercise(base: str, demo: Path, output: Path) -> dict:
    require_windows()
    if urlparse(base).hostname not in ('127.0.0.1', 'localhost', '::1'):
        raise ValueError('This demonstration only connects to a local control service.')
    if output.exists():
        raise ValueError('Evidence output exists; choose a new --batch.')
    manifest = json.loads((demo / 'build.json').read_text(encoding='utf-8'))
    if manifest.get('purpose') != 'SELF_AUTHORED_FUZZ_DEMONSTRATION':
        raise ValueError('Use a RecordView build produced by scripts/build_fuzz_demo.py.')
    builds = manifest['targets']
    if (len(builds) != 4
            or {(item['fixed'], item['libfuzzer']) for item in builds}
            != {(False, False), (False, True), (True, False), (True, True)}):
        raise ValueError('The demo needs both the buggy and fixed CLI and libFuzzer builds.')
    for item in builds:
        path = (demo / item['path']).resolve()
        if path.parent != demo.resolve() or digest(path) != item['sha256']:
            raise ValueError('A demonstration binary has changed since it was built.')
    targets = [item for item in builds if item['libfuzzer']]
    output.mkdir(parents=True)
    api = API(base)
    new_id = lambda: str(uuid.uuid4())
    project = api.rpc('ProjectService', 'CreateProject', requestId=new_id(),
                      name='RecordView Fuzz Demo')['project']
    summary = {'schema_version': 1, 'purpose': 'SELF_AUTHORED_FUZZ_DEMONSTRATION',
               'formal_acceptance': False, 'project_id': project['id'], 'server': base,
               'targets': [], 'status': 'RUNNING'}
    write_json(output / 'summary.json', summary)
    for item in targets:
        name = item['path']
        artifact = api.upload(name, (demo / name).read_bytes(), 'application/octet-stream')
        snapshot = api.rpc('ProjectService', 'CreateSnapshot', requestId=new_id(),
                           projectId=project['id'], name=name, kind='TARGET_KIND_BINARY',
                           artifactId=artifact)['snapshot']
        api.wait('ProjectService', 'GetSnapshot', 'snapshot', ('READY',),
                 snapshotId=snapshot['id'], timeout=180)
        source = api.rpc('RunService', 'CreateRun', requestId=new_id(), snapshotId=snapshot['id'],
                         scope='STRUCTURE_ANALYSIS')['run']
        # FUZZ needs an owning analysis record, not an expensive analysis of
        # libFuzzer/ASan internals. Only cancel the fresh record created here.
        api.rpc('RunService', 'CancelRun', runId=source['id'])
        api.wait('RunService', 'GetRun', 'run', ('CANCELLED',), runId=source['id'], timeout=180)
        config = configuration(name)
        record = api.rpc('RuntimeService', 'CreateRuntime', requestId=new_id(),
                         sourceRunId=source['id'], findingId='', configJson=json.dumps(config))['record']
        entry = {'name': name, 'fixed': item['fixed'], 'sha256': item['sha256'],
                 'snapshot_id': snapshot['id'], 'source_run_id': source['id'],
                 'runtime_id': record['id'], 'runtime_run_id': record['runId'],
                 'configure_url': f"{base}/#/runs/{source['id']}?view=fuzz",
                 'results_url': f"{base}/#/runs/{source['id']}",
                 'runtime_url': f"{base}/#/runs/{record['runId']}",
                 'config': config, 'status': record['status']}
        summary['targets'].append(entry)
        write_json(output / 'summary.json', summary)
        deadline = time.monotonic() + 300
        while record['status'] in ('QUEUED', 'WAITING_EXECUTOR', 'RUNNING', 'CANCELLING'):
            if time.monotonic() >= deadline:
                raise TimeoutError('Runtime did not finish: ' + record['runId'])
            time.sleep(0.5)
            record = api.rpc('RuntimeService', 'GetRuntime', recordId=record['id'])['record']
        entry['status'] = record['status']
        result = json.loads(record.get('resultJson') or '{}')
        write_json(output / f'{name}.record.json', record)
        write_json(output / f'{name}.result.json', result)
        write_json(output / 'summary.json', summary)
        expected = 'NO_CRASH_OBSERVED' if item['fixed'] else 'REPRODUCED'
        if record['status'] != expected:
            raise AssertionError(f'{name}: expected {expected}, got {record["status"]}')
        observation = result['observation']
        entry['crashes'] = observation['crashes']
        child = api.rpc('RunService', 'GetRun', runId=record['runId'])['run']
        child_summary = json.loads(child['summaryJson'])
        entry['artifacts'] = {key: value for key, value in child_summary.items() if key.endswith('_artifact_id')}
        for label, artifact_id in (
            ('observation', result.get('observation_artifact_id')),
            ('evidence', child_summary.get('exploitation_artifact_id')),
            ('input', child_summary.get('exploitation_input_artifact_id')),
            ('replay', child_summary.get('exploitation_runner_artifact_id')),
        ):
            if artifact_id:
                (output / f'{name}.{label}').write_bytes(api.download(artifact_id))
        report = api.rpc('ReportService', 'CreateReport', requestId=new_id(), runId=source['id'], format='json')['report']
        (output / f'{name}.report.json').write_bytes(api.download(report['artifactId']))
        write_json(output / 'summary.json', summary)

    buggy = next(item for item in summary['targets'] if not item['fixed'])
    crash = next((item for item in buggy['crashes'] if item['reproduced']), None)
    if not crash or len(crash['replays']) < 2:
        raise AssertionError('Missing a repeated crash-input receipt.')
    if not all(trial['observed'] and trial['processes_reaped'] and not trial['timed_out']
               and not trial['truncated'] for trial in crash['replays']):
        raise AssertionError('Crash replay was not valid.')
    replay_input = output / 'minimized-input.bin'
    replay_input.write_bytes(bytes.fromhex(crash['input_hex']))
    comparisons = []
    for item in builds:
        receipt = run([str(demo / item['path']), str(replay_input)], output,
                      os.environ.copy(), timeout=20)
        comparisons.append({'name': item['path'], 'fixed': item['fixed'],
                            'libfuzzer': item['libfuzzer'], **receipt})
        write_json(output / 'independent-replay.json', comparisons)
        if not replay_succeeded(item, receipt):
            raise AssertionError(f'{item["path"]}: archived input did not produce the expected result.')
    summary['independent_replay'] = [item for item in comparisons if item['libfuzzer']]
    summary['cli_replay'] = [item for item in comparisons if not item['libfuzzer']]
    summary['minimized_input_hex'] = crash['input_hex']
    summary['minimized_input_sha256'] = digest(replay_input)
    summary['status'] = 'PASSED'
    write_json(output / 'summary.json', summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--demo-dir', type=Path, required=True)
    parser.add_argument('--server', default='http://127.0.0.1:7331')
    parser.add_argument('--batch', default=time.strftime('recordview-product-%Y%m%d-%H%M%S'))
    args = parser.parse_args()
    if Path(args.batch).name != args.batch or args.batch in ('.', '..'):
        parser.error('--batch must be a single directory name')
    output = (ROOT / '.data/verification/fuzz-demo' / args.batch).resolve()
    summary = exercise(args.server.rstrip('/'), args.demo_dir.resolve(), output)
    print(json.dumps({'status': summary['status'], 'evidence': str(output / 'summary.json'),
                      'targets': [{key: item[key] for key in ('name', 'status', 'configure_url', 'results_url', 'runtime_url')}
                                  for item in summary['targets']],
                      'minimized_input_hex': summary['minimized_input_hex']}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
