#!/usr/bin/env python3
"""Compare actual agent output on development fixtures and their fixes (not R14 acceptance)."""
import argparse
from collections import Counter
import io
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
import uuid
import zipfile
from aegis import ROOT, environment
from e2e import stop

sys.path.insert(0, str(ROOT / 'tests'))
from smoke import API


def exercise(base, output):
    api = API(base)
    project = api.rpc('ProjectService', 'CreateProject', requestId=str(uuid.uuid4()), name='开发回归 · 四类语义审计')['project']['id']
    results = []
    for variant in ('source', 'fixed'):
        content = io.BytesIO()
        with zipfile.ZipFile(content, 'w', zipfile.ZIP_DEFLATED) as archive:
            for path in sorted((ROOT / 'tests/fixtures/audit' / variant).iterdir()):
                archive.writestr(path.name, path.read_bytes())
        artifact = api.upload(variant + '.zip', content.getvalue(), 'application/zip')
        snapshot = api.rpc('ProjectService', 'CreateSnapshot', requestId=str(uuid.uuid4()), projectId=project,
                           kind='TARGET_KIND_SOURCE', artifactId=artifact, name=variant + '.zip')['snapshot']
        snapshot = api.wait('ProjectService', 'GetSnapshot', 'snapshot', {'READY'}, snapshotId=snapshot['id'])
        run = api.rpc('RunService', 'CreateRun', requestId=str(uuid.uuid4()), snapshotId=snapshot['id'], scope='SECURITY_AUDIT',
                      maxModelCalls=100, maxUnits=40, maxToolRounds=5, timeoutSeconds=1200)['run']
        print(variant + ': ' + base + '/#/runs/' + run['id'], flush=True)
        last = None
        deadline = time.monotonic() + 1260
        while time.monotonic() < deadline:
            run = api.rpc('RunService', 'GetRun', runId=run['id'])['run']
            summary = json.loads(run.get('summaryJson', '{}'))
            progress = (run['state'], summary.get('audited_unit_count'), summary.get('finding_count'))
            if progress != last:
                print(variant + ': ' + json.dumps(progress), flush=True)
                last = progress
            if run['state'] not in ('RUN_STATE_QUEUED', 'RUN_STATE_RUNNING', 'RUN_STATE_WAITING_EXECUTOR', 'RUN_STATE_CANCELLING'):
                break
            time.sleep(1)
        else:
            api.rpc('RunService', 'CancelRun', runId=run['id'])
            raise RuntimeError('Audit exceeded its expected deadline; cancellation requested')
        data = api.rpc('FindingService', 'GetAudit', runId=run['id'])
        (output / (variant + '-audit.json')).write_text(json.dumps({'run': run, 'audit': data}, ensure_ascii=False, indent=2), encoding='utf-8')
        validated = Counter(f['category'] for f in data.get('findings', []) if f.get('reviewStatus') == 'VALIDATED')
        reports = {}
        for fmt in ('json', 'html', 'markdown'):
            report = api.rpc('ReportService', 'CreateReport', requestId=str(uuid.uuid4()), runId=run['id'], format=fmt)['report']
            report_bytes = api.download(report['artifactId'])
            (output / (variant + '-report.' + {'json': 'json', 'html': 'html', 'markdown': 'md'}[fmt])).write_bytes(report_bytes)
            reports[fmt] = report['artifactId']
        results.append({'variant': variant, 'run_id': run['id'], 'state': run['state'], 'validated_categories': dict(validated),
                        'findings': len(data.get('findings', [])), 'model_calls': len(data.get('modelCalls', [])),
                        'model_usage': summary.get('model_usage'), 'reports': reports})
        print(json.dumps(results[-1], ensure_ascii=False), flush=True)
    (output / 'summary.json').write_text(json.dumps({'purpose': 'development regression, not formal acceptance', 'results': results}, ensure_ascii=False, indent=2), encoding='utf-8')
    expected = {'INJECTION', 'PATH_TRAVERSAL', 'AUTHORIZATION', 'MEMORY_BOUNDS'}
    if not expected.issubset(results[0]['validated_categories']) or results[1]['validated_categories']:
        raise RuntimeError('Actual audit did not meet the development detection/fix expectations; raw results retained')
    if any(result['state'] != 'RUN_STATE_COMPLETED' for result in results):
        raise RuntimeError('Audit coverage is incomplete; inspect retained results')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--live-model', action='store_true', required=True, help='Use the configured official API and record real usage')
    parser.add_argument('--server', help='Use an existing updated server instead of an isolated test service')
    options = parser.parse_args()
    output = ROOT / '.data/verification' / ('audit-live-' + time.strftime('%Y%m%d-%H%M%S'))
    output.mkdir(parents=True, exist_ok=False)
    if options.server:
        exercise(options.server, output)
        return
    credential = ROOT / '.data/server/deepseek.token'
    if not credential.is_file():
        raise RuntimeError('No configured local model credential')
    data = output / 'server'
    data.mkdir(mode=0o700)
    shutil.copyfile(credential, data / 'deepseek.token')
    (data / 'deepseek.token').chmod(0o600)
    if (ROOT / '.data/server/model.json').is_file():
        shutil.copyfile(ROOT / '.data/server/model.json', data / 'model.json')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    suffix = '.exe' if sys.platform == 'win32' else ''
    env = environment()
    processes = []
    flags = {'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP} if sys.platform == 'win32' else {}
    with (output / 'server.log').open('w') as server_log, (output / 'executor.log').open('w') as executor_log:
        try:
            processes.append(subprocess.Popen([str(ROOT / 'target/debug' / ('aegis-server' + suffix)), '--bind', f'127.0.0.1:{port}', '--data-dir', str(data)], cwd=ROOT, env=env, stdout=server_log, stderr=subprocess.STDOUT, **flags))
            base = f'http://127.0.0.1:{port}'
            for _ in range(100):
                try:
                    API(base)
                    break
                except OSError:
                    if processes[0].poll() is not None:
                        raise RuntimeError('Test service exited; inspect its log')
                    time.sleep(0.1)
            else:
                raise RuntimeError('Test service failed to start')
            processes.append(subprocess.Popen([str(ROOT / 'target/debug' / ('aegis-executor' + suffix)), '--server', base,
                                              '--work-dir', str(output / 'executor'), '--bootstrap-file', str(data / 'executor-bootstrap.token')],
                                             cwd=ROOT, env=env, stdout=executor_log, stderr=subprocess.STDOUT, **flags))
            exercise(base, output)
        finally:
            for process in reversed(processes):
                stop(process)
    print('Evidence: ' + str(output), flush=True)


if __name__ == '__main__':
    main()
