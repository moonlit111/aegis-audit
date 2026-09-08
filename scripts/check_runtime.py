#!/usr/bin/env python3
"""Exercise real offline containers, fixed controls, fuzzing, cancellation and reports."""
import argparse
import hashlib
import io
import json
from pathlib import Path
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


def identifier():
    return str(uuid.uuid4())


def invocation(args=None, stdin=''):
    return {'args': args or [], 'kwargs': {}, 'stdin': stdin}


def configuration(path, adapter='PYTHON_CALL', **extra):
    return dict(mode='VERIFY', adapter=adapter, path=path, function='', globals={}, fixtures=[],
                baseline=invocation(), probe=invocation(), observer='RETURN_CANARY',
                marker_path='', repeats=2, timeout_seconds=5, **extra)


def cases():
    path = configuration('documents.py')
    path.update(function='read_document',
                fixtures=[{'path': 'docs/readme.txt', 'content': 'hello'},
                          {'path': 'secret.txt', 'content': '{{canary}}'}],
                baseline=invocation(['{{work}}/docs', 'readme.txt']),
                probe=invocation(['{{work}}/docs', '../secret.txt']))
    auth = configuration('accounts.py')
    auth.update(function='private_profile', globals={'PRIVATE_ACCOUNTS': {
        'alice': {'note': 'hello'}, 'bob': {'secret': '{{canary}}'}}},
        baseline=invocation([{'authenticated': True, 'user_id': 'alice'}, 'alice']),
        probe=invocation([{'authenticated': True, 'user_id': 'alice'}, 'bob']))
    command = configuration('formatter.py')
    command.update(function='format_value', observer='FILE_CREATED', marker_path='marker.txt',
                   baseline=invocation(['hello']), probe=invocation(['hello; printf marker > marker.txt']))
    memory = configuration('messages.c', 'NATIVE_SOURCE')
    memory.update(observer='SANITIZER', baseline=invocation(['hello']), probe=invocation(['A' * 64]))
    return [('PATH_TRAVERSAL', path), ('AUTHORIZATION', auth), ('INJECTION', command), ('MEMORY_BOUNDS', memory)]


def import_target(api, project, variant):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
        for folder in [ROOT / 'tests/fixtures/audit' / variant, ROOT / 'tests/fixtures/runtime' / variant]:
            for path in sorted(folder.iterdir()):
                archive.writestr(path.name, path.read_bytes())
        archive.writestr('wait.py', 'import time\n\ndef wait():\n    while True:\n        time.sleep(1)\n')
    artifact = api.upload(variant + '.zip', buffer.getvalue(), 'application/zip')
    snapshot = api.rpc('ProjectService', 'CreateSnapshot', requestId=identifier(), projectId=project,
                       kind='TARGET_KIND_SOURCE', artifactId=artifact, name=variant)['snapshot']
    snapshot = api.wait('ProjectService', 'GetSnapshot', 'snapshot', {'READY'}, snapshotId=snapshot['id'])
    run = api.rpc('RunService', 'CreateRun', requestId=identifier(), snapshotId=snapshot['id'])['run']
    return api.wait('RunService', 'GetRun', 'run', {'COMPLETED'}, runId=run['id'])


def create(api, run, config):
    request = dict(requestId=identifier(), sourceRunId=run['id'], configJson=json.dumps(config))
    record = api.rpc('RuntimeService', 'CreateRuntime', **request)['record']
    assert api.rpc('RuntimeService', 'CreateRuntime', **request)['record']['id'] == record['id']
    return record


def wait_record(api, record):
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        record = api.rpc('RuntimeService', 'GetRuntime', recordId=record['id'])['record']
        if record['status'] not in ('QUEUED', 'RUNNING', 'WAITING_EXECUTOR', 'CANCELLING'):
            return record
        time.sleep(0.3)
    raise AssertionError('Runtime deadline exceeded: ' + record['id'])


def save_record(api, output, name, record):
    result = json.loads(record.get('resultJson') or 'null')
    (output / (name + '.json')).write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding='utf-8')
    if result:
        for key in ['recipe_artifact_id', 'observation_artifact_id']:
            data = api.download(result[key])
            (output / (name + '-' + key + '.json')).write_bytes(data)
        assert json.loads(api.download(result['observation_artifact_id'])) == result['observation']
        for tool in result['tools']:
            assert tool['details']['processes_reaped'] and tool['details']['network'] == 'none'
            api.download(tool['log_artifact_id'])
        assert all(hashlib.sha256(t['input_json'].encode()).hexdigest() == t['input_sha256']
                   for t in result['observation']['trials'])
    print(name + ': ' + record['status'], flush=True)
    return result


def exercise(base, output):
    api = API(base)
    project = api.rpc('ProjectService', 'CreateProject', requestId=identifier(), name='动态执行开发回归')['project']['id']
    summary = {'purpose': 'development regression, not R14 acceptance', 'checks': []}

    def remember(name, record):
        result = save_record(api, output, name, record)
        summary['checks'].append({'case': name, 'record_id': record['id'], 'run_id': record['runId'], 'status': record['status']})
        (output / 'summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
        return result

    runs = {}
    for variant in ['source', 'fixed']:
        run = runs[variant] = import_target(api, project, variant)
        for category, config in cases():
            record = wait_record(api, create(api, run, config))
            result = remember(variant + '-' + category, record)
            expected = 'NOT_REPRODUCED' if variant == 'fixed' else ('REPRODUCED' if config['adapter'] == 'NATIVE_SOURCE' else 'VERIFIED_COMPONENT')
            assert record['status'] == expected, record
            assert len(result['observation']['trials']) == 3
        for engine in (['MUTATION', 'AFLPP'] if variant == 'source' else ['MUTATION']):
            config = configuration('input.c', 'NATIVE_SOURCE')
            config.update(mode='FUZZ', observer='SANITIZER', fuzz=dict(engine=engine, input_mode='STDIN', seeds=['hello'],
                                                                     max_cases=64, budget_seconds=10, random_seed=71413))
            record = wait_record(api, create(api, run, config))
            result = remember(variant + '-' + engine, record)
            assert result and result['observation']['fuzz']['executions'] > 0, record
            assert result['observation']['fuzz']['coverage_feedback'] == (engine == 'AFLPP')
            if engine == 'MUTATION':
                assert record['status'] == ('REPRODUCED' if variant == 'source' else 'NO_CRASH_OBSERVED'), record
            assert all(len(c['replays']) == 2 for c in result['observation']['crashes'] if c['reproduced'])
        for fmt in ['json', 'html', 'markdown']:
            report = api.rpc('ReportService', 'CreateReport', requestId=identifier(), runId=run['id'], format=fmt)['report']
            data = api.download(report['artifactId'])
            (output / (variant + '-report.' + {'json': 'json', 'html': 'html', 'markdown': 'md'}[fmt])).write_bytes(data)
            if fmt == 'json':
                document = json.loads(data)
                assert len(document['audit']['runtime']) >= 5
                assert document['checks']['exploitation'] == 'NOT_RUN'
                assert document['checks']['fuzzing'] == 'COMPLETED'
                assert document['checks']['runtime_verification'] == 'COMPLETED'
    original = api.upload('sample-elf64', (ROOT / 'tests/fixtures/binary/sample-elf64').read_bytes(), 'application/octet-stream')
    snapshot = api.rpc('ProjectService', 'CreateSnapshot', requestId=identifier(), projectId=project,
                       kind='TARGET_KIND_BINARY', artifactId=original, name='sample-elf64')['snapshot']
    snapshot = api.wait('ProjectService', 'GetSnapshot', 'snapshot', {'READY'}, snapshotId=snapshot['id'])
    manifest = json.loads(api.download(snapshot['manifestArtifactId']))
    binary_run = api.rpc('RunService', 'CreateRun', requestId=identifier(), snapshotId=snapshot['id'])['run']
    config = configuration(manifest['files'][0]['path'], 'ELF')
    config.update(observer='SANITIZER')
    record = wait_record(api, create(api, binary_run, config))
    result = remember('original-ELF', record)
    assert record['status'] == 'NOT_REPRODUCED' and result['target_scope'] == 'ORIGINAL', record
    binary_run = api.rpc('RunService', 'GetRun', runId=binary_run['id'])['run']
    if binary_run['state'] in ('RUN_STATE_QUEUED', 'RUN_STATE_RUNNING', 'RUN_STATE_WAITING_EXECUTOR'):
        api.rpc('RunService', 'CancelRun', runId=binary_run['id'])
    config = configuration('wait.py')
    config.update(function='wait', globals={'probe_value': '{{canary}}'}, timeout_seconds=15)
    record = create(api, runs['source'], config)
    api.wait('RunService', 'GetRun', 'run', {'RUNNING'}, runId=record['runId'])
    api.rpc('RunService', 'CancelRun', runId=record['runId'])
    record = wait_record(api, record)
    remember('cancellation', record)
    assert record['status'] == 'CANCELLED' and not record.get('resultJson'), record
    summary['passed'] = True
    (output / 'summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', help='Use an existing updated server/executor')
    options = parser.parse_args()
    output = ROOT / '.data/verification' / ('runtime-' + time.strftime('%Y%m%d-%H%M%S'))
    output.mkdir(parents=True)
    if options.server:
        exercise(options.server, output)
        return
    subprocess.run(['docker', 'image', 'inspect', 'aegis-runtime:0.2.0'], stdout=subprocess.DEVNULL, check=True)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    base = f'http://127.0.0.1:{port}'
    suffix = '.exe' if sys.platform == 'win32' else ''
    flags = {'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP} if sys.platform == 'win32' else {}
    processes = []
    with (output / 'server.log').open('w') as server_log, (output / 'executor.log').open('w') as executor_log:
        try:
            processes.append(subprocess.Popen([str(ROOT / 'target/debug' / ('aegis-server' + suffix)), '--bind', f'127.0.0.1:{port}', '--data-dir', str(output / 'server')], cwd=ROOT, env=environment(), stdout=server_log, stderr=subprocess.STDOUT, **flags))
            for _ in range(100):
                try:
                    API(base)
                    break
                except OSError:
                    if processes[0].poll() is not None:
                        raise RuntimeError('Test server exited; see server.log')
                    time.sleep(0.1)
            else:
                raise RuntimeError('Test server did not start')
            processes.append(subprocess.Popen([str(ROOT / 'target/debug' / ('aegis-executor' + suffix)), '--server', base, '--work-dir', str(output / 'executor'), '--bootstrap-file', str(output / 'server/executor-bootstrap.token')], cwd=ROOT, env=environment(), stdout=executor_log, stderr=subprocess.STDOUT, **flags))
            exercise(base, output)
        finally:
            for process in reversed(processes):
                stop(process)
    print('Evidence: ' + str(output), flush=True)


if __name__ == '__main__':
    main()
