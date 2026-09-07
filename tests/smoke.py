#!/usr/bin/env python3
"""Exercise a running real server + executor; never substitutes analysis results."""
import argparse
import hashlib
import http.cookiejar
import io
import json
from pathlib import Path
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile

ROOT = Path(__file__).resolve().parent.parent


class API:
    def __init__(self, base):
        self.base = base.rstrip('/')
        self.client = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        with self.client.open(self.base + '/api/session', timeout=10) as response:
            self.csrf = json.load(response)['csrf_token']

    def post(self, path, body, content_type='application/json'):
        request = urllib.request.Request(self.base + path, data=body, headers={
            'Content-Type': content_type, 'x-aegis-csrf': self.csrf,
            'Connect-Protocol-Version': '1'})
        try:
            return self.client.open(request, timeout=60)
        except urllib.error.HTTPError as error:
            raise AssertionError(f'{path}: {error.code} {error.read().decode()}') from error

    def rpc(self, service, method, **data):
        with self.post('/rpc/audit.v1.' + service + '/' + method,
                       json.dumps(data).encode()) as response:
            return json.load(response)

    def upload(self, name, data, media_type):
        query = urllib.parse.urlencode({'name': name, 'media_type': media_type})
        with self.post('/api/uploads?' + query, data, media_type) as response:
            artifact = json.load(response)
        assert artifact['sha256'] == hashlib.sha256(data).hexdigest()
        return artifact['id']

    def download(self, artifact_id):
        with self.client.open(self.base + '/api/artifacts/' + artifact_id, timeout=30) as response:
            data = response.read()
            assert hashlib.sha256(data).hexdigest() == response.headers['x-aegis-sha256']
            return data

    def events(self, run_id, after=0):
        body = json.dumps({'runId': run_id, 'afterSeq': str(after)}).encode()
        with self.post('/rpc/audit.v1.RunService/WatchRun',
                       b'\x00' + struct.pack('>I', len(body)) + body,
                       'application/connect+json') as response:
            data = response.read()
        events = []
        while data:
            flags, length = data[0], struct.unpack('>I', data[1:5])[0]
            message = json.loads(data[5:5 + length])
            data = data[5 + length:]
            if flags == 2:
                assert 'error' not in message, message
            else:
                events.append(message['event'])
        return events

    def wait(self, service, method, key, allowed, timeout=360, **request):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = self.rpc(service, method, **request)[key]
            state = value['state'].split('_STATE_')[-1]
            if state in allowed:
                return value
            assert state not in ('FAILED', 'CANCELLED', 'LIMIT_REACHED'), value
            time.sleep(0.4)
        raise AssertionError('Timed out waiting for ' + str(request))


def source_zip():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in sorted((ROOT / 'tests/fixtures/source').rglob('*')):
            if path.is_file():
                archive.write(path, path.relative_to(ROOT / 'tests/fixtures/source').as_posix())
        archive.writestr('.git/config', 'excluded fixture')
    return buffer.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', default='http://127.0.0.1:7331')
    parser.add_argument('--binary', action='store_true')
    parser.add_argument('--git', action='store_true')
    args = parser.parse_args()
    api = API(args.server)
    new_id = lambda: str(uuid.uuid4())
    project = api.rpc('ProjectService', 'CreateProject', requestId=new_id(), name='结构解析集成验证')['project']
    results = []

    def analyze(name, kind, data=None, **extra):
        started = time.monotonic()
        artifact = api.upload(name, data, 'application/octet-stream') if data else ''
        snapshot = api.rpc('ProjectService', 'CreateSnapshot', requestId=new_id(),
                           projectId=project['id'], name=name, kind=kind,
                           artifactId=artifact, **extra)['snapshot']
        snapshot = api.wait('ProjectService', 'GetSnapshot', 'snapshot', ('READY', 'PARTIAL'),
                            snapshotId=snapshot['id'])
        request_id = new_id()
        run = api.rpc('RunService', 'CreateRun', requestId=request_id, snapshotId=snapshot['id'])['run']
        repeat = api.rpc('RunService', 'CreateRun', requestId=request_id, snapshotId=snapshot['id'])['run']
        assert run['id'] == repeat['id']
        run = api.wait('RunService', 'GetRun', 'run', ('COMPLETED', 'PARTIAL'), runId=run['id'])
        units = api.rpc('ProgramService', 'ListUnits', runId=run['id'], limit=200).get('units', [])
        if kind == 'TARGET_KIND_GIT':
            assert snapshot['resolvedRevision'] == extra['gitRevision']
            assert run['state'] == 'RUN_STATE_PARTIAL' and not units
        else:
            assert units, 'Real analysis returned no units'
            detail = api.rpc('ProgramService', 'GetUnit', unitId=units[0]['id'])['unit']
            assert detail.get('code') or detail.get('quality') == 'FAILED'
        if kind == 'TARGET_KIND_BINARY':
            assert all(u.get('address', '').startswith('0x') for u in units)
        events = api.events(run['id'])
        assert events and events[-1]['kind'] == 'RUN_COMPLETED'
        seqs = [int(e['seq']) for e in events]
        assert seqs == list(range(1, len(seqs) + 1))
        assert api.events(run['id'], seqs[0]) == events[1:]
        reports = {}
        for fmt in ('json', 'html', 'markdown'):
            report = api.rpc('ReportService', 'CreateReport', requestId=new_id(), runId=run['id'], format=fmt)['report']
            output = api.download(report['artifactId'])
            assert b'NOT_RUN' in output, 'Report must not imply vulnerability verification ran'
            if fmt == 'json':
                json.loads(output)
            reports[fmt] = report['artifactId']
        result = {'name': name, 'snapshot_id': snapshot['id'], 'run_id': run['id'],
                  'state': run['state'], 'units': len(units), 'events': len(events),
                  'sha256': snapshot['targetSha256'], 'seconds': round(time.monotonic() - started, 2),
                  'reports': reports}
        results.append(result)
        print(json.dumps(result, ensure_ascii=False), flush=True)

    analyze('多语言源码.zip', 'TARGET_KIND_SOURCE', source_zip())
    if args.binary:
        for name in ('sample-pe32.exe', 'sample-pe64.exe', 'sample-elf64'):
            analyze(name, 'TARGET_KIND_BINARY', (ROOT / 'tests/fixtures/binary' / name).read_bytes())
    if args.git:
        analyze('Git 固定提交验证', 'TARGET_KIND_GIT', gitUrl='https://github.com/octocat/Hello-World.git',
                gitRevision='7fd1a60b01f91b314f59955a4e4d4e80d8edf11d')
    directory = ROOT / '.data/verification'
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'backend-smoke.json').write_text(json.dumps(results, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
