#!/usr/bin/env python3
"""Build tiny, benign PE32/PE64/ELF64 files from the checked-in C source."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
from aegis import ROOT, environment

env = environment()
sysroot = Path(subprocess.check_output(['rustc', '--print', 'sysroot'], env=env, text=True).strip())
if sys.platform == 'darwin':
    env['DYLD_LIBRARY_PATH'] = str(sysroot / 'lib')
version = subprocess.check_output(['rustc', '-vV'], env=env, text=True)
host = next(line[6:] for line in version.splitlines() if line.startswith('host: '))
linker = sysroot / 'lib/rustlib' / host / 'bin/rust-lld'
if not linker.exists(): linker = linker.with_suffix('.exe')
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
    subprocess.run(compile_args, env=env, check=True)
    link_args = [str(linker),'-flavor',flavor,*extra,*(['/out:' + str(output), '/implib:' + str(temp / (name + '.lib'))] if flavor == 'link' else ['-o',str(output)]),str(obj)]
    subprocess.run(link_args, env=env, check=True)
    entries.append({'file':name,'target':target,'sha256':hashlib.sha256(output.read_bytes()).hexdigest(),'size':output.stat().st_size})
    print(name + ': ' + entries[-1]['sha256'])
(source.parent / 'manifest.json').write_text(json.dumps({'purpose':'Benign structure-analysis fixtures, not course acceptance cases','source':'sample.c','source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'compiler':subprocess.check_output(['clang','--version'],text=True,env=env).splitlines()[0],'fixtures':entries},indent=2)+'\n')
