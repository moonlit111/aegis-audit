#!/usr/bin/env python3
"""Exercise a relocated Windows package with no developer tools in its PATH."""
import argparse
import ctypes
from ctypes import wintypes as w
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import socket
import stat
import subprocess
import sys
import time
import uuid
import zipfile

from aegis import ROOT, require_windows
from windows_launcher import ProcessOwner, Windows

sys.path.insert(0, str(ROOT / 'tests'))
from smoke import API


class ProcessEntry(ctypes.Structure):
    _fields_ = [('size', w.DWORD), ('usage', w.DWORD), ('pid', w.DWORD),
                ('heap', ctypes.c_size_t), ('module', w.DWORD), ('threads', w.DWORD),
                ('parent_pid', w.DWORD), ('priority', w.LONG), ('flags', w.DWORD),
                ('name', w.WCHAR * 260)]


class ProcessHandles:
    def __init__(self):
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        for name, result, args in [
            ('CreateToolhelp32Snapshot', w.HANDLE, [w.DWORD, w.DWORD]),
            ('Process32FirstW', w.BOOL, [w.HANDLE, ctypes.POINTER(ProcessEntry)]),
            ('Process32NextW', w.BOOL, [w.HANDLE, ctypes.POINTER(ProcessEntry)]),
            ('OpenProcess', w.HANDLE, [w.DWORD, w.BOOL, w.DWORD]),
            ('WaitForSingleObject', w.DWORD, [w.HANDLE, w.DWORD]),
            ('CloseHandle', w.BOOL, [w.HANDLE]),
        ]:
            function = getattr(self.kernel, name)
            function.restype, function.argtypes = result, args
        self.handles = []

    def descendants(self, parent):
        snapshot = self.kernel.CreateToolhelp32Snapshot(2, 0)
        if snapshot == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        entries = []
        try:
            entry = ProcessEntry()
            entry.size = ctypes.sizeof(entry)
            found = self.kernel.Process32FirstW(snapshot, ctypes.byref(entry))
            while found:
                entries.append({'pid': entry.pid, 'parent_pid': entry.parent_pid, 'name': entry.name})
                found = self.kernel.Process32NextW(snapshot, ctypes.byref(entry))
        finally:
            self.kernel.CloseHandle(snapshot)
        owned = {parent}
        while True:
            children = {entry['pid'] for entry in entries if entry['parent_pid'] in owned}
            expanded = owned | children
            if expanded == owned:
                return [entry for entry in entries if entry['pid'] in owned and entry['pid'] != parent]
            owned = expanded

    def track(self, entries):
        result = []
        for entry in entries:
            handle = self.kernel.OpenProcess(0x100000, False, entry['pid'])
            if handle:
                self.handles.append(handle)
                result.append((entry, handle))
        return result

    def assert_reaped(self, tracked):
        for entry, handle in tracked:
            if self.kernel.WaitForSingleObject(handle, 10000) != 0:
                raise AssertionError('Owned descendant did not exit: ' + json.dumps(entry))

    def close(self):
        for handle in self.handles:
            self.kernel.CloseHandle(handle)
        self.handles.clear()


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as source:
        for data in iter(lambda: source.read(1024 * 1024), b''):
            value.update(data)
    return value.hexdigest()


def unpack_verified(package, destination):
    with zipfile.ZipFile(package) as archive:
        entries = [entry for entry in archive.infolist() if not entry.is_dir()]
        if not entries or len(entries) > 100000 or sum(entry.file_size for entry in entries) > 8 * 1024**3:
            raise ValueError('Package is empty or exceeds the verification quota')
        members = {}
        roots = set()
        folded = set()
        for entry in entries:
            name = entry.filename
            path = PurePosixPath(name)
            if ('\\' in name or ':' in name or path.is_absolute() or len(path.parts) < 2
                    or any(part in ('', '.', '..') for part in name.split('/'))
                    or stat.S_ISLNK(entry.external_attr >> 16)):
                raise ValueError('Unsafe package path: ' + name)
            roots.add(path.parts[0])
            relative = PurePosixPath(*path.parts[1:]).as_posix()
            if relative.casefold() in folded:
                raise ValueError('Duplicate package path: ' + relative)
            folded.add(relative.casefold())
            if path.parts[1] in {'.data', '.git', 'node_modules', 'target'}:
                raise ValueError('Runtime/development data entered the package: ' + relative)
            if path.name.endswith('.token') or path.name == '.env' or path.name.startswith('.env.'):
                raise ValueError('Private configuration entered the package: ' + relative)
            members[relative] = entry
        if len(roots) != 1:
            raise ValueError('Package must have exactly one root directory')
        manifest = json.loads(archive.read(members['PACKAGE-MANIFEST.json']))
        expected = {entry['path']: entry for entry in manifest['files']}
        if len(expected) != len(manifest['files']) or set(members) != set(expected) | {'PACKAGE-MANIFEST.json'}:
            raise ValueError('Package files do not exactly match the manifest')
        destination.mkdir(parents=True, exist_ok=False)
        for name, entry in members.items():
            target = destination.joinpath(*PurePosixPath(name).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(entry) as source, target.open('xb') as output:
                shutil.copyfileobj(source, output, 1024 * 1024)
            if name in expected and (target.stat().st_size != expected[name]['size'] or digest(target) != expected[name]['sha256']):
                raise ValueError('Package checksum mismatch: ' + name)
    standalone = json.loads((destination / 'WINDOWS-STANDALONE.json').read_text(encoding='utf-8'))
    assert standalone['entrypoint'] == 'AegisAudit.exe'
    assert not standalone['api_credentials_included']
    assert not (destination / '.tools/windows-python/Scripts/semgrep.exe').exists()
    return {'package_sha256': digest(package), 'file_count': len(members), 'standalone': standalone}


def clean_environment():
    names = {'systemroot', 'windir', 'comspec', 'pathext', 'systemdrive', 'userprofile',
             'appdata', 'localappdata', 'temp', 'tmp', 'username', 'userdomain',
             'computername', 'programdata', 'public', 'os', 'processor_architecture',
             'number_of_processors', 'sessionname'}
    environment = {key: value for key, value in os.environ.items() if key.lower() in names}
    environment['PATH'] = str(Path(os.environ['SystemRoot']) / 'System32')
    environment['GHIDRA_HOME'] = 'Z:/nonexistent-test-sdk'
    environment['AEGIS_PYTHON_HOME'] = 'Z:/nonexistent-test-python'
    environment['JAVA_HOME'] = 'Z:/nonexistent-test-java'
    return environment


class Installation:
    def __init__(self, root, output):
        self.root, self.output = root, output
        self.exe = root / 'AegisAudit.exe'
        self.environment = clean_environment()
        self.launcher = None
        self.state = None

    def spawn(self, *arguments):
        return subprocess.Popen([str(self.exe), '--no-open', '--non-interactive', *map(str, arguments)],
                                cwd=self.output, env=self.environment, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW)

    def command(self, *arguments, expected=0, timeout=90):
        process = self.spawn(*arguments)
        try:
            code = process.wait(timeout=timeout)
        except BaseException:
            process.kill()
            process.wait(timeout=10)
            raise
        if code != expected:
            raise AssertionError(f'Packaged command {arguments} exited {code}, expected {expected}; inspect .data/logs/desktop.log')

    def start(self, *arguments):
        self.launcher = self.spawn(*arguments)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if self.launcher.poll() is not None:
                raise AssertionError('Packaged launcher exited during startup; inspect ' + str(self.root / '.data/logs/desktop.log'))
            state = self.root / '.data/launcher.json'
            try:
                value = json.loads(state.read_text(encoding='utf-8'))
                inspector = ProcessHandles()
                try:
                    owned = {entry['pid'] for entry in inspector.descendants(self.launcher.pid)}
                finally:
                    inspector.close()
                if not all(entry['pid'] in owned for entry in value['processes']):
                    time.sleep(0.2)
                    continue
                api = API(value['url'])
                executors = api.rpc('SystemService', 'GetCapabilities').get('executors', [])
                if executors and any(any(cap['name'] == 'semgrep' and cap.get('available')
                                        for cap in executor.get('capabilities', [])) for executor in executors):
                    self.state = value
                    return api
            except (OSError, ValueError):
                pass
            time.sleep(0.2)
        raise AssertionError('Packaged service/executor did not become ready')

    def stop(self):
        self.command('--stop')
        if self.launcher is not None:
            self.launcher.wait(timeout=70)
            assert self.launcher.returncode == 0
            self.launcher = None

    def cleanup(self):
        if self.launcher is not None and self.launcher.poll() is None:
            try:
                self.stop()
            except BaseException:
                self.launcher.kill()
                self.launcher.wait(timeout=10)
                self.launcher = None


def scan_packaged_tools(installation, output):
    source = output / 'native scan inputs'
    shutil.copytree(ROOT / 'tests/fixtures/audit/source', source)
    environment = dict(installation.environment)
    environment['SEMGREP_SETTINGS_FILE'] = str(output / 'semgrep-settings.yml')
    environment['SEMGREP_SEND_METRICS'] = 'off'
    environment['SEMGREP_ENABLE_VERSION_CHECK'] = '0'
    command = [str(installation.root / '.tools/windows-python/python.exe'), '-I', '-X', 'utf8',
               '-m', 'semgrep.console_scripts.entrypoint', 'scan', '--experimental', '--json',
               '--metrics=off', '--disable-version-check', '--no-git-ignore', '--no-rewrite-rule-ids',
               '--x-ignore-semgrepignore-files', '--project-root', '.', '--jobs', '2', '--timeout', '15',
               '--config', str(installation.root / 'tools/runtime/rules.yml'), '.']
    owner = ProcessOwner(Windows())
    try:
        process = owner.spawn(command, cwd=source, env=environment, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              creationflags=subprocess.CREATE_NO_WINDOW)
        stdout, stderr = process.communicate(timeout=120)
        (output / 'packaged-semgrep.json').write_bytes(stdout)
        (output / 'packaged-semgrep.log').write_bytes(stderr)
        assert process.returncode == 0, 'Relocated Semgrep failed; inspect packaged-semgrep.log'
        report = json.loads(stdout)
        assert report['version'] == '1.176.1'
        assert set(report['paths']['scanned']) == {'accounts.py', 'commands.py', 'documents.py', 'messages.c'}
        assert len(report['results']) == 2 and not report['errors']
    finally:
        owner.close()
    return {'name': 'real_relocated_semgrep_scan_without_developer_path', 'status': 'PASSED',
            'scanned_files': 4, 'rule_clues': 2, 'scan_errors': 0,
            'target_execution': False, 'raw_sha256': hashlib.sha256(stdout).hexdigest()}


def exercise(installation, output, checks, git=False):
    handles = ProcessHandles()
    try:
        doctor = output / 'doctor.json'
        installation.command('--diagnostics', doctor)
        capabilities = {entry['name']: entry for entry in json.loads(doctor.read_text(encoding='utf-8'))}
        for name in ('import', 'tree-sitter', 'git', 'ghidra', 'semgrep'):
            assert capabilities[name].get('available'), capabilities[name]
        checks.append({'name': 'relocated_diagnostics_without_developer_path', 'status': 'PASSED'})
        checks.append(scan_packaged_tools(installation, output))
        with socket.socket() as occupied:
            occupied.bind(('127.0.0.1', 0))
            occupied.listen()
            installation.command('--port', occupied.getsockname()[1], expected=1)
            assert occupied.getsockname()[1] != 0
        checks.append({'name': 'explicit_busy_port_rejected_without_stopping_its_owner', 'status': 'PASSED'})
        api = installation.start()
        original_pids = [entry['pid'] for entry in installation.state['processes']]
        installation.command()
        repeated = json.loads((installation.root / '.data/launcher.json').read_text(encoding='utf-8'))
        assert [entry['pid'] for entry in repeated['processes']] == original_pids
        checks.append({'name': 'duplicate_launch_reuses_owned_services', 'status': 'PASSED'})
        project = api.rpc('ProjectService', 'CreateProject', requestId=str(uuid.uuid4()),
                          name='Standalone persistence regression')['project']
        subprocess.run([sys.executable, str(ROOT / 'tests/smoke.py'), '--server', api.base,
                        '--binary', *(['--git'] if git else []), '--output', str(output / 'backend-smoke.json')], cwd=ROOT, check=True)
        records = json.loads((output / 'backend-smoke.json').read_text(encoding='utf-8'))
        preserved_report = records[0]['reports']['json']
        report_sha256 = hashlib.sha256(api.download(preserved_report)).hexdigest()
        checks.append({'name': 'real_source_pe32_pe64_elf_and_reports', 'status': 'PASSED'})
        if git:
            checks.append({'name': 'fixed_https_git_revision_and_factual_partial_coverage', 'status': 'PASSED'})
        tracked = handles.track(handles.descendants(installation.launcher.pid))
        installation.stop()
        handles.assert_reaped(tracked)
        checks.append({'name': 'graceful_stop_reaps_owned_processes', 'status': 'PASSED'})
        api = installation.start()
        assert any(entry['id'] == project['id'] for entry in api.rpc('ProjectService', 'ListProjects').get('projects', []))
        assert hashlib.sha256(api.download(preserved_report)).hexdigest() == report_sha256
        checks.append({'name': 'restart_preserves_projects_and_artifacts', 'status': 'PASSED'})
        artifact = api.upload('sample-pe64.exe', (ROOT / 'tests/fixtures/binary/sample-pe64.exe').read_bytes(), 'application/octet-stream')
        snapshot = api.rpc('ProjectService', 'CreateSnapshot', requestId=str(uuid.uuid4()), projectId=project['id'],
                           name='sample-pe64.exe', kind='TARGET_KIND_BINARY', artifactId=artifact)['snapshot']
        snapshot = api.wait('ProjectService', 'GetSnapshot', 'snapshot', {'READY'}, snapshotId=snapshot['id'])
        run = api.rpc('RunService', 'CreateRun', requestId=str(uuid.uuid4()), snapshotId=snapshot['id'])['run']
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            descendants = handles.descendants(installation.launcher.pid)
            if any(entry['name'].lower() == 'java.exe' for entry in descendants):
                break
            time.sleep(0.1)
        else:
            raise AssertionError('No real Ghidra descendant was observed before forced shutdown')
        tracked = handles.track(descendants)
        installation.launcher.kill()
        installation.launcher.wait(timeout=15)
        installation.launcher = None
        handles.assert_reaped(tracked)
        checks.append({'name': 'forced_launcher_exit_reaps_active_ghidra_tree', 'status': 'PASSED',
                       'descendants': descendants})
        api = installation.start()
        assert hashlib.sha256(api.download(preserved_report)).hexdigest() == report_sha256
        interrupted = api.rpc('RunService', 'GetRun', runId=run['id'])['run']
        assert interrupted['state'] not in ('RUN_STATE_COMPLETED', 'RUN_STATE_PARTIAL')
        from smoke import source_zip
        source = api.upload('after-restart.zip', source_zip(), 'application/zip')
        fresh = api.rpc('ProjectService', 'CreateSnapshot', requestId=str(uuid.uuid4()), projectId=project['id'],
                        name='after-restart.zip', kind='TARGET_KIND_SOURCE', artifactId=source)['snapshot']
        fresh = api.wait('ProjectService', 'GetSnapshot', 'snapshot', {'READY'}, timeout=60, snapshotId=fresh['id'])
        fresh_run = api.rpc('RunService', 'CreateRun', requestId=str(uuid.uuid4()), snapshotId=fresh['id'])['run']
        api.wait('RunService', 'GetRun', 'run', {'COMPLETED'}, timeout=60, runId=fresh_run['id'])
        checks.append({'name': 'restart_after_forced_exit_does_not_report_interrupted_work_as_success',
                       'status': 'PASSED', 'interrupted_run_state': interrupted['state']})
        installation.stop()
    finally:
        installation.cleanup()
        handles.close()


def main():
    require_windows()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--git', action='store_true', help='Also verify public HTTPS Git import using the configured Windows network')
    options = parser.parse_args()
    output = (options.output or ROOT / '.data/verification' / ('win-package-' + time.strftime('%Y%m%d-%H%M%S'))).resolve()
    output.mkdir(parents=True, exist_ok=False)
    installation = output / 'AegisAudit \u5ba1\u8ba1 package'
    result = {'observed_at': datetime.now(timezone.utc).isoformat(), 'platform': 'Windows x64',
              'scope': 'standalone lifecycle and static tooling, not isolation or formal vulnerability acceptance',
              'checks': [], 'status': 'RUNNING'}
    try:
        result.update(unpack_verified(options.package.resolve(), installation))
        result['checks'].append({'name': 'all_manifest_files_verified_and_runtime_data_excluded', 'status': 'PASSED'})
        exercise(Installation(installation, output), output, result['checks'], options.git)
        result['status'] = 'PASSED'
    except BaseException as error:
        result['status'] = 'FAILED'
        result['error'] = str(error)
        raise
    finally:
        (output / 'summary.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        print('Windows package evidence: ' + str(output), flush=True)


if __name__ == '__main__':
    main()
