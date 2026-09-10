#!/usr/bin/env python3
"""Install the pinned portable Zig compiler used by native-source attempts."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import urllib.request
import zipfile


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
    with urllib.request.urlopen(request, timeout=120) as source, partial.open('wb') as target:
        shutil.copyfileobj(source, target, 1024 * 1024)
    actual = sha256(partial)
    if actual != checksum:
        partial.unlink()
        raise RuntimeError(f'SHA-256 mismatch for {url}: expected {checksum}, got {actual}')
    partial.replace(destination)
    return destination


def extract_zip(archive: Path, destination: Path) -> None:
    with tempfile.TemporaryDirectory(prefix='zig-', dir=TOOLS) as temporary:
        root = Path(temporary)
        with zipfile.ZipFile(archive) as package:
            for item in package.infolist():
                target = (root / item.filename).resolve()
                if root.resolve() not in target.parents:
                    raise RuntimeError(f'archive path escapes extraction directory: {item.filename}')
            package.extractall(root)
        children = list(root.iterdir())
        source = children[0] if len(children) == 1 and children[0].is_dir() else root
        if not (source / 'zig.exe').is_file():
            raise RuntimeError('Zig archive does not contain zig.exe')
        if destination.exists():
            shutil.rmtree(destination)
        shutil.move(str(source), destination)


def installed_version(zig: Path) -> str | None:
    if not zig.is_file():
        return None
    import subprocess
    result = subprocess.run(
        [str(zig), 'version'],
        capture_output=True,
        text=True,
        encoding='utf-8',
        errors='replace',
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--force', action='store_true', help='replace an existing installation')
    args = parser.parse_args()

    specs = json.loads(VERSIONS.read_text(encoding='utf-8'))
    spec = specs['zig']
    destination = TOOLS / 'zig'
    zig = destination / 'zig.exe'
    current = installed_version(zig)
    if current == spec['version'] and not args.force:
        print(f'Using {zig}')
        return 0

    archive = TOOLS / 'downloads' / f'zig-{spec["version"]}-x86_64-windows.zip'
    if not archive.is_file() or sha256(archive) != spec['sha256']:
        archive = download(spec['url'], spec['sha256'], archive)
    extract_zip(archive, destination)
    actual = installed_version(zig)
    if actual != spec['version']:
        raise RuntimeError(f'installed Zig version is {actual}, expected {spec["version"]}')
    print(f'Installed {zig} ({actual})')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
