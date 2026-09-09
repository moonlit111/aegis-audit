#!/usr/bin/env python3
"""Build tiny, benign PE32/PE64/ELF64 files from the checked-in C source."""
from pathlib import Path
import hashlib
import json
import subprocess
from aegis import ROOT, environment, resolve_command

env = environment()
sysroot = Path(subprocess.check_output(resolve_command(['rustc', '--print', 'sysroot'], env), env=env, text=True).strip())
version = subprocess.check_output(resolve_command(['rustc', '-vV'], env), env=env, text=True)
host = next(line[6:] for line in version.splitlines() if line.startswith('host: '))
linker = sysroot / 'lib/rustlib' / host / 'bin/rust-lld.exe'
source = ROOT / 'tests/fixtures/binary/sample.c'
temp = ROOT / '.data/fixture-build'
temp.mkdir(parents=True, exist_ok=True)
entries = []
for name, target, flavor, extra in [
    ('sample-pe64.exe', 'x86_64-pc-windows-msvc', 'link', ['/entry:entry','/subsystem:console','/nodefaultlib','/timestamp:0','/export:helper']),
    ('sample-pe32.exe', 'i686-pc-windows-msvc', 'link', ['/entry:entry','/subsystem:console','/nodefaultlib','/timestamp:0','/safeseh:no','/export:helper']),
    ('sample-elf64', 'x86_64-unknown-linux-gnu', 'gnu', ['-e','_start','--build-id=none']),
]:
    obj = temp / (name + '.o')
    output = source.parent / name
    compile_args = ['clang','--target=' + target,'-O0','-fno-stack-protector','-fno-ident','-fno-pic','-c',str(source),'-o',str(obj)]
    subprocess.run(resolve_command(compile_args, env), env=env, check=True)
    link_args = [str(linker),'-flavor',flavor,*extra,*(['/out:' + str(output), '/implib:' + str(temp / (name + '.lib'))] if flavor == 'link' else ['-o',str(output)]),str(obj)]
    subprocess.run(link_args, env=env, check=True)
    entries.append({'file':name,'target':target,'sha256':hashlib.sha256(output.read_bytes()).hexdigest(),'size':output.stat().st_size})
    print(name + ': ' + entries[-1]['sha256'])
(source.parent / 'manifest.json').write_text(json.dumps({'purpose':'Benign structure-analysis fixtures, not course acceptance cases','source':'sample.c','source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'compiler':subprocess.check_output(resolve_command(['clang','--version'],env),text=True,env=env).splitlines()[0],'fixtures':entries},indent=2)+'\n')
