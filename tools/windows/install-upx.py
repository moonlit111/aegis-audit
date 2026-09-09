#!/usr/bin/env python3
"""Install the pinned portable UPX executable used by protection processing."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import urllib.request
import zipfile


ROOT = Path(__file__).resolve().parents[2]
VERSIONS = ROOT / 'tools/windows/versions.json'
TOOLS = ROOT / '.tools'


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def download(url: str, checksum: str, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_suffix(destination.suffix + '.partial')
    request = urllib.request.Request(url, headers={'User-Agent': 'AegisAudit-bootstrap/0.1'})
    with urllib.request.urlopen(request, timeout=120) as source, partial.open('wb') as target:
        shutil.copyfileobj(source, target, 1024 * 1024)
    actual = sha256(partial)
    if actual != checksum:
        partial.unlink()
        raise RuntimeError(f'SHA-256 mismatch for {url}: expected {checksum}, got {actual}')
    partial.replace(destination)
    return destination


def installed_version(upx: Path) -> str | None:
    if not upx.is_file():
        return None
    result = subprocess.run(
        [str(upx), '--version'],
        capture_output=True,
        text=True,
        encoding='utf-8',
        errors='replace',
        check=False,
    )
    if result.returncode != 0:
        return None
    for line in (result.stdout + result.stderr).splitlines():
        if line.startswith('upx '):
            return line.split()[1]
    return None


def extract(archive: Path, destination: Path) -> None:
    with tempfile.TemporaryDirectory(prefix='upx-', dir=TOOLS) as temporary:
        root = Path(temporary)
        with zipfile.ZipFile(archive) as package:
            for item in package.infolist():
                target = (root / item.filename).resolve()
                if root.resolve() not in target.parents:
                    raise RuntimeError(f'archive path escapes extraction directory: {item.filename}')
            package.extractall(root)
        candidates = list(root.rglob('upx.exe'))
        if len(candidates) != 1:
            raise RuntimeError('the UPX archive must contain exactly one upx.exe')
        if destination.exists():
            shutil.rmtree(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(candidates[0].parent, destination)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--force', action='store_true', help='replace an existing installation')
    args = parser.parse_args()

    specs = json.loads(VERSIONS.read_text(encoding='utf-8'))
    spec = specs['upx']
    destination = TOOLS / 'upx'
    upx = destination / 'upx.exe'
    current = installed_version(upx)
    if current == spec['version'] and not args.force:
        print(f'Using {upx}')
        return 0

    archive = TOOLS / 'downloads' / f'upx-{spec["version"]}-win64.zip'
    if not archive.is_file() or sha256(archive) != spec['sha256']:
        archive = download(spec['url'], spec['sha256'], archive)
    extract(archive, destination)
    actual = installed_version(upx)
    if actual != spec['version']:
        raise RuntimeError(f'installed UPX version is {actual}, expected {spec["version"]}')
    print(f'Installed {upx} ({actual})')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
