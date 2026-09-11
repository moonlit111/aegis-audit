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
from e2e_model import FixtureProvider
import json


def stop(process):
    if process.poll() is not None:
        return
    process.send_signal(signal.CTRL_BREAK_EVENT if os.name == 'nt' else signal.SIGTERM)
    try:
        process.wait(timeout=25)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def wait_server(process, base):
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError('Test control service exited; inspect .data/verification/browser-server.log')
        try:
            with urllib.request.urlopen(base + '/healthz', timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError('Test control service did not start')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-build', action='store_true')
    parser.add_argument('--skip-ghidra', action='store_true')
    parser.add_argument('--runtime', action='store_true', help='Also test the Windows host runtime browser workflow')
    parser.add_argument('--grep', help='Run only browser tests matching this Playwright expression')
    options = parser.parse_args()
    env = environment()
    for name in ('DEEPSEEK_API_KEY', 'AEGIS_MODEL_API_KEY', 'AEGIS_MODEL_ENDPOINT', 'AEGIS_MODEL'):
        env.pop(name, None)
    env['NO_PROXY'] = 'localhost,127.0.0.1,::1'
    pnpm = 'pnpm.cmd' if os.name == 'nt' else 'pnpm'
    if not options.no_build:
        subprocess.run(resolve_command(['cargo', 'build', '--workspace', '--locked'], env), cwd=ROOT, env=env, check=True)
        subprocess.run(resolve_command([pnpm, '--dir', 'frontend', 'build'], env), cwd=ROOT, env=env, check=True)
    if options.skip_ghidra:
        env['AEGIS_SKIP_GHIDRA'] = '1'
    if options.runtime:
        env['AEGIS_TEST_RUNTIME'] = '1'
    port = free_port()
    env['AEGIS_E2E_BASE_URL'] = f'http://127.0.0.1:{port}'
    output = ROOT / '.data/verification'
    output.mkdir(parents=True, exist_ok=True)
    suffix = '.exe' if os.name == 'nt' else ''
    flags = {'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == 'nt' else {}
    with tempfile.TemporaryDirectory(prefix='aegis-browser-') as temporary, FixtureProvider() as provider:
        env['AEGIS_E2E_MODEL_ENDPOINT'] = provider.endpoint
        data = Path(temporary)
        processes = []
        with (output / 'browser-server.log').open('w') as server_log, (output / 'browser-executor.log').open('w') as executor_log:
            try:
                server = subprocess.Popen([str(ROOT / 'target/debug' / ('aegis-server' + suffix)), '--bind', f'127.0.0.1:{port}', '--data-dir', str(data / 'server')], cwd=ROOT, env=env, stdout=server_log, stderr=subprocess.STDOUT, **flags)
                processes.append(server)
                wait_server(server, env['AEGIS_E2E_BASE_URL'])
                environment_port = free_port()
                env['AEGIS_E2E_ENV_BASE_URL'] = f'http://127.0.0.1:{environment_port}'
                fallback_env = {**env, 'AEGIS_MODEL_ENDPOINT': provider.endpoint,
                                'AEGIS_MODEL': 'environment-fixture-model', 'AEGIS_MODEL_API_KEY': 'browser-fixture-key'}
                fallback_server = subprocess.Popen([str(ROOT / 'target/debug' / ('aegis-server' + suffix)), '--bind', f'127.0.0.1:{environment_port}', '--data-dir', str(data / 'environment-server')], cwd=ROOT, env=fallback_env, stdout=server_log, stderr=subprocess.STDOUT, **flags)
                processes.append(fallback_server)
                wait_server(fallback_server, env['AEGIS_E2E_ENV_BASE_URL'])
                executor = subprocess.Popen([str(ROOT / 'target/debug' / ('aegis-executor' + suffix)), '--server', env['AEGIS_E2E_BASE_URL'], '--work-dir', str(data / 'executor'), '--bootstrap-file', str(data / 'server/executor-bootstrap.token')], cwd=ROOT, env=env, stdout=executor_log, stderr=subprocess.STDOUT, **flags)
                processes.append(executor)
                arguments = [pnpm, '--dir', 'frontend', 'test:e2e']
                if options.grep:
                    arguments.extend(['--grep', options.grep])
                result = subprocess.run(resolve_command(arguments, env), cwd=ROOT, env=env)
                return result.returncode
            finally:
                for process in reversed(processes):
                    stop(process)
                (output / 'browser-model.json').write_text(json.dumps(provider.calls, ensure_ascii=False, indent=2), encoding='utf-8')


if __name__ == '__main__':
    raise SystemExit(main())
