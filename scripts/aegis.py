#!/usr/bin/env python3
"""Run project commands with isolated, optional .tools installations."""
from pathlib import Path
import os
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent


def environment():
    env = os.environ.copy()
    tools = ROOT / '.tools'
    candidates = [tools / 'node/bin', tools / 'node', tools / 'pnpm/bin', tools / 'pnpm', tools / 'bin', tools / 'cargo/bin']
    env['PATH'] = os.pathsep.join(str(p) for p in candidates if p.is_dir()) + os.pathsep + env.get('PATH', '')
    if (tools / 'rustup').is_dir():
        env['RUSTUP_HOME'] = str(tools / 'rustup')
        env['CARGO_HOME'] = str(tools / 'cargo')
    for java in [tools / 'jdk/Contents/Home', tools / 'jdk']:
        if (java / 'bin/java').exists() or (java / 'bin/java.exe').exists():
            env['JAVA_HOME'] = str(java)
            env['PATH'] = str(java / 'bin') + os.pathsep + env['PATH']
            break
    ghidra = tools / 'ghidra_12.1.3_PUBLIC'
    if (tools / 'paths.json').is_file():
        paths = json.loads((tools / 'paths.json').read_text(encoding='utf-8'))
        ghidra = Path(paths.get('ghidra', ghidra))
    if ghidra.is_dir():
        env.setdefault('GHIDRA_HOME', str(ghidra.resolve()))
    env.setdefault('CARGO_BUILD_JOBS', '4')
    return env


def main():
    args = sys.argv[1:]
    if not args:
        print('Usage: python3 scripts/aegis.py <cargo|pnpm|buf|...> [arguments]')
        return 2
    command = args
    if os.name == 'nt' and args[0] in ('pnpm', 'npm'):
        command = [args[0] + '.cmd', *args[1:]]
    return subprocess.call(command, cwd=ROOT, env=environment())


if __name__ == '__main__':
    raise SystemExit(main())
