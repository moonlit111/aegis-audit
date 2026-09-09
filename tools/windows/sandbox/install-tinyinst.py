#!/usr/bin/env python3
"""Build and install the pinned TinyInst litecov runtime for A05 experiments."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[3]
VERSIONS = ROOT / 'tools/windows/versions.json'
TOOLS = ROOT / '.tools'


def command(args: list[str], cwd: Path, env: dict[str, str] | None = None) -> None:
    subprocess.run(args, cwd=cwd, env=env, check=True)


def find_visual_studio_root(clang_or_cl: Path) -> Path:
    for parent in clang_or_cl.parents:
        if parent.name in {'Community', 'Professional', 'Enterprise'}:
            return parent
    raise RuntimeError('cannot locate the Visual Studio installation root')


def build_environment() -> dict[str, str]:
    cl = shutil.which('cl')
    cmake = shutil.which('cmake')
    if not cl or not cmake:
        raise RuntimeError(
            'load the MSVC environment first: . .data/windows/msvc-env.ps1'
        )
    cl_path = Path(cl)
    msvc_root = cl_path.parent.parent.parent.parent
    environment = os.environ.copy()
    environment['VisualStudioVersion'] = '17.0'
    environment['VCToolsInstallDir'] = str(msvc_root) + '\\'
    environment['CL'] = '/utf-8'
    return environment


def patch_mbuild_for_visual_studio_18(source: Path, visual_studio: Path) -> None:
    path = source / 'third_party/mbuild/mbuild/msvs.py'
    text = path.read_text(encoding='utf-8')
    old = "prefix = 'C:/Program Files/Microsoft Visual Studio/2022'"
    new = f"prefix = '{visual_studio.as_posix()}'"
    if old not in text:
        raise RuntimeError('the pinned mbuild source no longer contains the expected prefix')
    path.write_text(text.replace(old, new), encoding='utf-8')


def install(source: Path, destination: Path, commit: str) -> None:
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    if source.exists():
        command(['git', 'fetch', 'origin'], source)
    else:
        command(['git', 'clone', 'https://github.com/googleprojectzero/tinyinst.git', str(source)], ROOT)
    command(['git', 'checkout', commit], source)
    command(['git', 'submodule', 'update', '--init', '--recursive'], source)

    environment = build_environment()
    cl = Path(shutil.which('cl'))
    visual_studio = find_visual_studio_root(cl)
    patch_mbuild_for_visual_studio_18(source, visual_studio)
    build = source / 'build'
    command([
        'cmake',
        '-S',
        str(source),
        '-B',
        str(build),
        '-G',
        'NMake Makefiles',
        '-DCMAKE_BUILD_TYPE=Release',
    ], source, environment)
    command(['cmake', '--build', str(build), '--config', 'Release'], source, environment)

    runtime = TOOLS / 'tinyinst'
    if runtime.exists():
        shutil.rmtree(runtime)
    runtime.mkdir(parents=True)
    shutil.copy2(build / 'litecov.exe', runtime / 'litecov.exe')
    for name in ('msvcp140.dll', 'vcruntime140.dll', 'vcruntime140_1.dll'):
        system_dll = Path(os.environ['SystemRoot']) / 'System32' / name
        if not system_dll.is_file():
            raise RuntimeError(f'Microsoft runtime DLL is missing: {name}')
        shutil.copy2(system_dll, runtime / name)
    (runtime / 'VERSION.json').write_text(
        json.dumps({
            'engine': 'TinyInst litecov',
            'commit': commit,
            'submodules': {
                'mbuild': subprocess.check_output(
                    ['git', 'rev-parse', 'HEAD'],
                    cwd=source / 'third_party/mbuild',
                    text=True,
                ).strip(),
                'xed': subprocess.check_output(
                    ['git', 'rev-parse', 'HEAD'],
                    cwd=source / 'third_party/xed',
                    text=True,
                ).strip(),
            },
        }, indent=2) + '\n',
        encoding='utf-8',
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--force', action='store_true', help='replace an existing installation')
    args = parser.parse_args()

    specs = json.loads(VERSIONS.read_text(encoding='utf-8'))
    spec = specs['tinyinst']
    runtime = TOOLS / 'tinyinst'
    version_file = runtime / 'VERSION.json'
    if runtime.is_dir() and version_file.is_file():
        current = json.loads(version_file.read_text(encoding='utf-8'))
        if current.get('commit') == spec['version'] and not args.force:
            print(f'Using {runtime / "litecov.exe"}')
            return 0

    source = TOOLS / 'tinyinst-source'
    install(source, runtime, spec['version'])
    print(f'Installed {runtime / "litecov.exe"} ({spec["version"]})')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
