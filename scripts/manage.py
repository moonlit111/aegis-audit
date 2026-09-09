#!/usr/bin/env python3
"""Build, start, inspect and stop this checkout's local application."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import urllib.request
import webbrowser
from aegis import ROOT, environment, require_windows, resolve_command

DATA = ROOT / '.data'
STATE = DATA / 'launcher.json'


def run(args):
    env = environment()
    return subprocess.run(resolve_command(args, env), cwd=ROOT, env=env, check=True)


def executable(name):
    suffix = '.exe'
    for folder in ['bin', 'target/release', 'target/debug']:
        candidate = ROOT / folder / (name + suffix)
        if candidate.is_file():
            return candidate
    raise RuntimeError('Application binaries are missing. Run: python scripts/manage.py build')


def process_identity(pid):
    if not isinstance(pid, int) or pid <= 0:
        return ''
    require_windows()
    powershell = Path(os.environ.get('SystemRoot', 'C:/Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    command = [str(powershell), '-NoProfile', '-NonInteractive', '-Command',
               f'$p = Get-CimInstance Win32_Process -Filter "ProcessId = {pid}"; if ($p) {{ $p | Select-Object CreationDate,CommandLine | ConvertTo-Json -Compress }}']
    flags = {'creationflags': subprocess.CREATE_NO_WINDOW}
    result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='replace', **flags)
    return result.stdout.strip() if result.returncode == 0 else ''


def owned(item):
    identity = process_identity(item.get('pid'))
    return bool(identity) and identity == item.get('identity')


def stop_item(item):
    if not owned(item):
        return
    pid = item['pid']
    os.kill(pid, signal.CTRL_BREAK_EVENT)
    for _ in range(300):
        if not owned(item):
            return
        time.sleep(0.1)
    raise RuntimeError(f'{item["name"]} has not stopped; inspect its log and active task before retrying.')


def health(base):
    try:
        request = urllib.request.Request(base + '/healthz')
        with urllib.request.urlopen(request, timeout=2) as response:
            value = json.load(response)
            return bool(value.get('ok'))
    except (OSError, ValueError):
        return False


def start(options, process_factory=None):
    require_windows()
    if STATE.exists():
        previous = json.loads(STATE.read_text(encoding='utf-8'))
        if any(owned(item) for item in previous['processes']):
            print('A managed application is already running: ' + previous['url'])
            return
    base = f'http://127.0.0.1:{options.port}'
    if health(base):
        raise RuntimeError(base + ' is already serving an application outside this launcher; use its existing window or a different --port.')
    (DATA / 'logs').mkdir(parents=True, exist_ok=True)
    if not (ROOT / 'frontend/dist/index.html').is_file():
        raise RuntimeError('Frontend build is missing. Run: python scripts/manage.py build')
    flags = {'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP}
    processes = []
    try:
        specs = [
            ('server', [executable('aegis-server'), '--bind', f'127.0.0.1:{options.port}']),
            ('executor', [executable('aegis-executor'), '--server', base, '--work-dir', DATA / ('executor' if options.port == 7331 else f'executor-{options.port}')]),
        ]
        for name, args in specs:
            with (DATA / 'logs' / (name + '.log')).open('ab') as log:
                spawn = process_factory or subprocess.Popen
                process = spawn([str(arg) for arg in args], cwd=ROOT, env=environment(), stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, **flags)
            time.sleep(0.15)
            if process.poll() is not None:
                raise RuntimeError(name + ' failed to start. See .data/logs/' + name + '.log')
            identity = process_identity(process.pid)
            if not identity:
                process.terminate()
                raise RuntimeError('Cannot record owned process identity')
            processes.append({'name': name, 'pid': process.pid, 'identity': identity})
            if name == 'server':
                for _ in range(100):
                    if health(base): break
                    if process.poll() is not None: raise RuntimeError('Control service exited during startup')
                    time.sleep(0.1)
                else: raise RuntimeError('Control service startup timed out')
        STATE.write_text(json.dumps({'url': base, 'processes': processes}, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        print('AegisAudit is running: ' + base)
        print('Logs: .data/logs/   Stop: python scripts/manage.py stop')
        if options.open: webbrowser.open(base)
    except BaseException:
        for item in reversed(processes): stop_item(item)
        raise


def main():
    require_windows()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['build', 'start', 'stop', 'status', 'doctor', 'check', 'codegen', 'runtime'])
    parser.add_argument('--port', type=int, default=7331)
    parser.add_argument('--open', action='store_true')
    parser.add_argument('--debug', action='store_true', help='Build debug binaries')
    options = parser.parse_args()
    pnpm = 'pnpm.cmd'
    if options.action == 'build':
        if not (ROOT / 'Cargo.toml').is_file(): raise RuntimeError('Build requires a source checkout')
        run(['cargo', 'build', '--workspace', '--locked', *([] if options.debug else ['--release'])])
        run([pnpm, '--dir', 'frontend', 'install', '--frozen-lockfile'])
        run([pnpm, '--dir', 'frontend', 'build'])
    elif options.action == 'start':
        start(options)
    elif options.action in ('stop', 'status'):
        if not STATE.exists():
            print('No application is managed by this launcher.')
            return
        state = json.loads(STATE.read_text(encoding='utf-8'))
        if options.action == 'status':
            print(state['url'] + (' — reachable' if health(state['url']) else ' — unavailable'))
            for item in state['processes']:
                print(item['name'] + (': running' if owned(item) else ': stopped'))
        else:
            for item in reversed(state['processes']): stop_item(item)
            STATE.unlink()
            print('Application stopped. Projects, artifacts and task history remain in .data/.')
    elif options.action == 'runtime':
        run([sys.executable, ROOT / 'tools/windows/install-upx.py'])
        run([sys.executable, ROOT / 'tools/windows/sandbox/install-zig.py'])
        run([sys.executable, ROOT / 'tools/windows/sandbox/install-llvm.py'])
        run([sys.executable, ROOT / 'tools/windows/sandbox/install-tinyinst.py'])
        sandbox = Path(os.environ.get('SystemRoot', 'C:/Windows')) / 'System32' / 'WindowsSandbox.exe'
        if not sandbox.is_file():
            raise RuntimeError('Windows Sandbox is not installed or enabled; enable it in Windows Features and restart.')
    elif options.action == 'doctor':
        run([executable('aegis-executor'), '--doctor'])
    elif options.action == 'codegen':
        run([sys.executable, ROOT / 'scripts/codegen.py'])
    elif options.action == 'check':
        run([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_*.py'])
        run(['cargo', 'fmt', '--all', '--', '--check'])
        run([sys.executable, ROOT / 'scripts/codegen.py', '--check'])
        run(['cargo', 'clippy', '--workspace', '--all-targets', '--locked', '--', '-D', 'warnings'])
        run(['cargo', 'test', '--workspace', '--locked'])
        run([pnpm, '--dir', 'frontend', 'check'])
        run([pnpm, '--dir', 'frontend', 'format:check'])
        run([pnpm, '--dir', 'frontend', 'build'])


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, subprocess.CalledProcessError, OSError) as error:
        raise SystemExit(str(error))
