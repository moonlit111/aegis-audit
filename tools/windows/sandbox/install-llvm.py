#!/usr/bin/env python3
"""Install the pinned minimal LLVM/libFuzzer runtime for A05 experiments."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import urllib.request


ROOT = Path(__file__).resolve().parents[3]
VERSIONS = ROOT / 'tools/windows/versions.json'
TOOLS = ROOT / '.tools'


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def download(url: str, checksum: str, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_suffix(destination.suffix + '.partial')
    request = urllib.request.Request(url, headers={'User-Agent': 'AegisAudit-runtime-tools/0.1'})
    with urllib.request.urlopen(request, timeout=180) as source, partial.open('wb') as target:
        shutil.copyfileobj(source, target, 1024 * 1024)
    actual = sha256(partial)
    if actual != checksum:
        partial.unlink()
        raise RuntimeError(f'SHA-256 mismatch for {url}: expected {checksum}, got {actual}')
    partial.replace(destination)
    return destination


def installed_version(clang: Path) -> str | None:
    if not clang.is_file():
        return None
    result = subprocess.run(
        [str(clang), '--version'],
        capture_output=True,
        text=True,
        encoding='utf-8',
        errors='replace',
        check=False,
    )
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        if line.startswith('clang version '):
            return line.split()[2]
    return None


def copy_minimal_runtime(source_root: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    (destination / 'bin').mkdir(exist_ok=True)
    for name in ('clang.exe', 'clang++.exe', 'lld-link.exe'):
        source = source_root / 'bin' / name
        if not source.is_file():
            raise RuntimeError(f'LLVM archive is missing {name}')
        shutil.copy2(source, destination / 'bin' / name)
    resource = source_root / 'lib/clang'
    versions = [item for item in resource.iterdir() if item.is_dir()] if resource.is_dir() else []
    if len(versions) != 1:
        raise RuntimeError('the LLVM archive has an unexpected resource layout')
    for name in ('include', Path('lib') / 'windows'):
        source = versions[0] / name
        if not source.is_dir():
            raise RuntimeError(f'LLVM archive is missing {name}')
        target = destination / 'lib/clang' / versions[0].name / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source, target)


def extract_minimal_runtime(archive: Path, destination: Path) -> None:
    with tempfile.TemporaryDirectory(prefix='llvm-', dir=TOOLS) as temporary:
        root = Path(temporary)
        subprocess.run(['tar', '-xf', str(archive), '-C', str(root)], check=True)
        clangs = list(root.rglob('bin/clang.exe'))
        if len(clangs) != 1:
            raise RuntimeError('the LLVM archive must contain exactly one clang.exe')
        source_root = clangs[0].parent.parent
        copy_minimal_runtime(source_root, destination)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--force', action='store_true', help='replace an existing installation')
    args = parser.parse_args()

    specs = json.loads(VERSIONS.read_text(encoding='utf-8'))
    spec = specs['llvm']
    destination = TOOLS / 'llvm-min'
    clang = destination / 'bin/clang.exe'
    current = installed_version(clang)
    if current == spec['version'] and not args.force:
        print(f'Using {clang}')
        return 0
    if destination.exists() and args.force:
        shutil.rmtree(destination)

    archive = TOOLS / 'downloads' / f'clang-llvm-{spec["version"]}-x86_64-windows.tar.zst'
    if not archive.is_file() or sha256(archive) != spec['sha256']:
        archive = download(spec['url'], spec['sha256'], archive)
    extract_minimal_runtime(archive, destination)
    actual = installed_version(clang)
    if actual != spec['version']:
        raise RuntimeError(f'installed LLVM version is {actual}, expected {spec["version"]}')
    print(f'Installed {clang} ({actual})')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
