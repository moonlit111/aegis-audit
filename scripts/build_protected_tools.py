#!/usr/bin/env python3
"""Build versioned Windows acceptance targets and a binary-only distribution."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sys
import time
import zipfile

from aegis import ROOT, require_windows
from check_c_ares_cve import build_environment, digest, run, write_json


CATALOG = ROOT / 'evaluation/targets/protected-tools.json'
SOURCE = ROOT / 'evaluation/programs'


def resource(name: str, version: str) -> str:
    number = version.replace('.', ',') + ',0'
    return f'''#include <windows.h>
1 VERSIONINFO
 FILEVERSION {number}
 PRODUCTVERSION {number}
 FILEFLAGSMASK 0x3fL
 FILEFLAGS 0
 FILEOS VOS_NT_WINDOWS32
 FILETYPE VFT_APP
BEGIN
 BLOCK "StringFileInfo"
 BEGIN
  BLOCK "040904b0"
  BEGIN
   VALUE "FileDescription", "{name}\\0"
   VALUE "FileVersion", "{version}\\0"
   VALUE "InternalName", "{name}\\0"
   VALUE "OriginalFilename", "{name}.exe\\0"
   VALUE "ProductName", "{name}\\0"
   VALUE "ProductVersion", "{version}\\0"
  END
 END
 BLOCK "VarFileInfo"
 BEGIN
  VALUE "Translation", 0x409, 1200
 END
END
'''


def build(output: Path, llvm: Path, upx: Path) -> dict:
    require_windows()
    if output.exists():
        raise ValueError('Build output already exists; choose a new batch.')
    env = build_environment(llvm)
    rc = Path('C:/Program Files (x86)/Windows Kits/10/bin/10.0.26100.0/x64/rc.exe')
    clang = llvm / 'bin/clang.exe'
    if not rc.is_file() or not upx.is_file():
        raise FileNotFoundError('Windows SDK resource compiler or pinned UPX is missing.')
    catalog = json.loads(CATALOG.read_text(encoding='utf-8'))
    output.mkdir(parents=True)
    summary = {
        'schema_version': 1,
        'created_at': datetime.now(timezone.utc).isoformat(),
        'scope': 'CONTROLLED_BINARY_ACCEPTANCE',
        'target_platform': 'windows/x64',
        'qualification_basis': 'User reported instructor approval for this target category.',
        'formal_acceptance': False,
        'end_to_end_audit': 'NOT_RUN',
        'compiler': run([str(clang), '--version'], ROOT, env)['stdout'].strip(),
        'upx': run([str(upx), '--version'], ROOT, env)['stdout'].splitlines()[0],
        'sources': {p.name: digest(p) for p in [SOURCE / 'native_tool.h',
                    *[SOURCE / item['source'] for item in catalog]]},
        'targets': [],
        'commands': [],
    }

    def execute(command: list[str], work: Path) -> dict:
        record = run(command, work, env)
        summary['commands'].append(record)
        write_json(output / 'build.json', summary)
        if record['exit_code'] != 0:
            raise RuntimeError(record['stderr'] or record['stdout'])
        return record

    for item in catalog:
        for variant, version in (('baseline', '1.0.0'), ('corrected', '1.0.1')):
            folder = output / 'reference' / item['id'] / version
            folder.mkdir(parents=True)
            destination = output / 'targets' / item['id'] / version / (item['name'] + '.exe')
            destination.parent.mkdir(parents=True)
            rc_path = folder / 'version.rc'
            rc_path.write_text(resource(item['name'], version), encoding='ascii')
            res_path = folder / 'version.res'
            execute([str(rc), '/nologo', '/fo', str(res_path), str(rc_path)], folder)
            binaries = {}
            for mode in ('reference', 'protected'):
                protected = mode == 'protected' and item['protection'] != 'UPX'
                binary = folder / (mode + '.exe')
                command = [str(clang), '-target', 'x86_64-pc-windows-msvc', '-std=c11',
                           '-O0' if protected else '-O1', '-ffreestanding', '-fno-builtin',
                           '-fno-stack-protector', '-ffunction-sections', '-fdata-sections',
                           '-Wno-deprecated-declarations', f'-DTOOL_FIXED={int(variant == "corrected")}',
                           f'-DTOOL_PROTECTED={int(protected)}', str(SOURCE / item['source']),
                           str(res_path), '-o', str(binary), '-nostdlib',
                           '-Wl,/entry:entry,/subsystem:console,/nodefaultlib,/opt:ref,/opt:icf',
                           '-lkernel32', '-lshell32']
                if mode == 'protected' and item['protection'] == 'UPX':
                    shutil.copyfile(folder / 'reference.exe', binary)
                    execute([str(upx), '-q', '--best', str(binary)], folder)
                    execute([str(upx), '-t', str(binary)], folder)
                    unpacked = folder / 'unpacked.exe'
                    execute([str(upx), '-q', '-d', '-o', str(unpacked), str(binary)], folder)
                    binaries['unpacked'] = {
                        'path': unpacked.relative_to(output).as_posix(),
                        'sha256': digest(unpacked), 'bytes': unpacked.stat().st_size,
                    }
                else:
                    execute(command, folder)
                binaries[mode] = {'path': binary.relative_to(output).as_posix(),
                                  'sha256': digest(binary), 'bytes': binary.stat().st_size}
            shutil.copyfile(folder / 'protected.exe', destination)
            summary['targets'].append({
                'id': item['id'], 'name': item['name'], 'version': version, 'variant': variant,
                'protection': item['protection'], 'interface': item['interface'],
                'path': destination.relative_to(output).as_posix(),
                'sha256': digest(destination), 'bytes': destination.stat().st_size,
                'binaries': binaries, 'formal_acceptance': False,
            })
            write_json(output / 'build.json', summary)

    public = [{key: item[key] for key in ('id', 'name', 'version', 'protection', 'interface',
                                        'path', 'sha256', 'bytes')} for item in summary['targets']]
    write_json(output / 'catalog.json', public)
    readme = ['# Protected Tools', '', 'Platform: Windows x64.', '',
              'Run targets in a dedicated test directory. No installation is required.', '',
              '1.0.0 and 1.0.1 are separately versioned builds; test results are recorded separately.', '']
    for item in catalog:
        readme += [f'## {item["name"]}', '', f'`{item["interface"]}`', '', item['purpose'], '']
    (output / 'README.md').write_text('\n'.join(readme), encoding='ascii')
    package = output / 'protected-tools-windows-x64.zip'
    with zipfile.ZipFile(package, 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in [output / 'README.md', output / 'catalog.json',
                     *[output / item['path'] for item in summary['targets']]]:
            archive.write(path, path.relative_to(output))
    summary['package'] = {'path': package.name, 'sha256': digest(package),
                          'bytes': package.stat().st_size}
    summary['build_status'] = 'COMPLETED'
    write_json(output / 'build.json', summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--batch', default=time.strftime('protected-tools-%Y%m%d-%H%M%S'))
    parser.add_argument('--llvm', type=Path, default=ROOT / '.tools/llvm-min')
    parser.add_argument('--upx', type=Path,
                        default=ROOT / '.tools/reverse/upx/upx-5.2.1-win64/upx.exe')
    options = parser.parse_args()
    if Path(options.batch).name != options.batch or options.batch in ('.', '..'):
        parser.error('--batch must be a single directory name')
    output = ROOT / '.data/verification/protected-tools' / options.batch
    summary = build(output.resolve(), options.llvm.resolve(), options.upx.resolve())
    print(json.dumps({'build': str(output), 'targets': len(summary['targets']),
                      'package': summary['package'], 'formal_acceptance': False}, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
