#!/usr/bin/env python3
"""Run browser tests with real isolated control/executor processes."""
import argparse
from pathlib import Path
import os
import signal
import socket
import subprocess
import tempfile
import time
import urllib.request
from aegis import ROOT, environment, resolve_command


def stop(process):
    if process.poll() is not None:
        return
    process.send_signal(signal.CTRL_BREAK_EVENT if os.name == 'nt' else signal.SIGTERM)
    try:
        process.wait(timeout=25)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-build', action='store_true')
    parser.add_argument('--skip-ghidra', action='store_true')
    parser.add_argument('--runtime', action='store_true', help='Also test the Docker runtime browser workflow')
    options = parser.parse_args()
    env = environment()
    pnpm = 'pnpm.cmd' if os.name == 'nt' else 'pnpm'
    if not options.no_build:
        subprocess.run(resolve_command(['cargo', 'build', '--workspace', '--locked'], env), cwd=ROOT, env=env, check=True)
        subprocess.run(resolve_command([pnpm, '--dir', 'frontend', 'build'], env), cwd=ROOT, env=env, check=True)
    if options.skip_ghidra:
        env['AEGIS_SKIP_GHIDRA'] = '1'
    if options.runtime:
        env['AEGIS_TEST_RUNTIME'] = '1'
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    env['AEGIS_E2E_BASE_URL'] = f'http://127.0.0.1:{port}'
    output = ROOT / '.data/verification'
    output.mkdir(parents=True, exist_ok=True)
    suffix = '.exe' if os.name == 'nt' else ''
    flags = {'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == 'nt' else {}
    with tempfile.TemporaryDirectory(prefix='aegis-browser-') as temporary:
        data = Path(temporary)
        processes = []
        with (output / 'browser-server.log').open('w') as server_log, (output / 'browser-executor.log').open('w') as executor_log:
            try:
                server = subprocess.Popen([str(ROOT / 'target/debug' / ('aegis-server' + suffix)), '--bind', f'127.0.0.1:{port}', '--data-dir', str(data / 'server')], cwd=ROOT, env=env, stdout=server_log, stderr=subprocess.STDOUT, **flags)
                processes.append(server)
                for _ in range(100):
                    if server.poll() is not None:
                        raise RuntimeError('Test control service exited; inspect .data/verification/browser-server.log')
                    try:
                        with urllib.request.urlopen(env['AEGIS_E2E_BASE_URL'] + '/healthz', timeout=1):
                            break
                    except OSError:
                        time.sleep(0.1)
                else:
                    raise RuntimeError('Test control service did not start')
                executor = subprocess.Popen([str(ROOT / 'target/debug' / ('aegis-executor' + suffix)), '--server', env['AEGIS_E2E_BASE_URL'], '--work-dir', str(data / 'executor'), '--bootstrap-file', str(data / 'server/executor-bootstrap.token')], cwd=ROOT, env=env, stdout=executor_log, stderr=subprocess.STDOUT, **flags)
                processes.append(executor)
                result = subprocess.run(resolve_command([pnpm, '--dir', 'frontend', 'test:e2e'], env), cwd=ROOT, env=env)
                return result.returncode
            finally:
                for process in reversed(processes):
                    stop(process)


if __name__ == '__main__':
    raise SystemExit(main())
