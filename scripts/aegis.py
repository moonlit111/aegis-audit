#!/usr/bin/env python3
"""Run project commands with isolated, optional .tools installations."""
from pathlib import Path
import os
import json
import platform
import shutil
import subprocess
import sys
import urllib.request

ROOT = Path(sys.executable).resolve().parent if getattr(sys, 'frozen', False) else Path(__file__).resolve().parent.parent


def require_windows():
    if platform.system() != 'Windows' or platform.machine().lower() not in ('amd64', 'x86_64'):
        raise RuntimeError('AegisAudit supports Windows x64 only. macOS and Linux hosts are not supported.')


def environment():
    require_windows()
    env = os.environ.copy()
    # urllib uses the Windows user's manual proxy settings when no proxy env is set.
    for scheme, value in urllib.request.getproxies().items():
        if scheme in ('http', 'https', 'all', 'no') and value:
            env.setdefault(scheme.upper() + '_PROXY', value)
    tools = ROOT / '.tools'
    candidates = [tools / 'node', tools / 'pnpm', tools / 'bin', tools / 'cargo/bin', tools / 'git/cmd']
    env['PATH'] = os.pathsep.join(str(p) for p in candidates if p.is_dir()) + os.pathsep + env.get('PATH', '')
    if (tools / 'rustup').is_dir():
        env['RUSTUP_HOME'] = str(tools / 'rustup')
        env['CARGO_HOME'] = str(tools / 'cargo')
    python_home = tools / 'windows-python'
    if (python_home / 'python.exe').is_file():
        if getattr(sys, 'frozen', False):
            env['AEGIS_PYTHON_HOME'] = str(python_home)
        else:
            env.setdefault('AEGIS_PYTHON_HOME', str(python_home))
    java = tools / 'jdk'
    if (java / 'bin/java.exe').is_file():
        env['JAVA_HOME'] = str(java)
        env['PATH'] = str(java / 'bin') + os.pathsep + env['PATH']
    ghidra = tools / 'ghidra_12.1.3_PUBLIC'
    if (tools / 'paths.json').is_file():
        paths = json.loads((tools / 'paths.json').read_text(encoding='utf-8'))
        ghidra = Path(paths.get('ghidra', ghidra))
    if ghidra.is_dir():
        if getattr(sys, 'frozen', False):
            env['GHIDRA_HOME'] = str(ghidra.resolve())
        else:
            env.setdefault('GHIDRA_HOME', str(ghidra.resolve()))
    env.setdefault('CARGO_BUILD_JOBS', '4')
    return env


def resolve_command(args, env):
    command = [str(arg) for arg in args]
    if os.name == 'nt':
        if command[0] in ('pnpm', 'npm'):
            command[0] += '.cmd'
        # CreateProcess does not use the child's PATH to locate its executable.
        command[0] = shutil.which(command[0], path=env.get('PATH', '')) or command[0]
    return command


def main():
    args = sys.argv[1:]
    if not args:
        print('Usage: py -3 scripts/aegis.py <cargo|pnpm|buf|...> [arguments]')
        return 2
    env = environment()
    return subprocess.call(resolve_command(args, env), cwd=ROOT, env=env)


if __name__ == '__main__':
    raise SystemExit(main())
