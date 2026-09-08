#!/usr/bin/env python3
"""Export the working tree for Windows, or verify an extracted source handoff."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import time
import zipfile
from aegis import ROOT


def verify_source(directory):
    root = directory.resolve()
    manifest = json.loads((root / 'SOURCE-MANIFEST.json').read_text(encoding='utf-8'))
    files = manifest.get('files')
    if manifest.get('schema_version') != 1 or not isinstance(files, list) or not files:
        raise ValueError('Unsupported or empty source manifest')
    seen = set()
    failures = []
    for entry in files:
        name = entry.get('path', '')
        path = PurePosixPath(name)
        if (not name or '\\' in name or ':' in name or path.is_absolute()
                or any(part in ('', '.', '..') for part in name.split('/'))
                or name in seen):
            raise ValueError('Invalid or duplicate manifest path: ' + name)
        seen.add(name)
        target = root.joinpath(*path.parts)
        if not target.resolve().is_relative_to(root) or any(
                parent.is_symlink() for parent in (target, *target.parents) if parent != root):
            raise ValueError('Source path must not be a link: ' + name)
        if not target.is_file():
            failures.append(name + ': missing')
            continue
        data = target.read_bytes()
        if len(data) != entry.get('size') or hashlib.sha256(data).hexdigest() != entry.get('sha256'):
            failures.append(name + ': size or SHA-256 mismatch')
    if failures:
        raise ValueError('Source verification failed:\n' + '\n'.join(failures))
    print(f'{len(files)} source files verified; version {manifest.get("version", "unknown")}; Git HEAD {manifest["git_head"]}')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify', nargs='?', const=ROOT, type=Path,
                        help='Verify extracted files against SOURCE-MANIFEST.json; no Git or installed toolchain required')
    options = parser.parse_args()
    if options.verify is not None:
        verify_source(options.verify)
        return
    names = subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'], cwd=ROOT).decode().split('\0')
    paths = sorted({Path(name) for name in names if name})
    paths = [path for path in paths if (ROOT / path).is_file() and not (ROOT / path).is_symlink()
             and not any(part in {'.git', '.data', '.tools', '.cache', '.codex', '.agents', '.pnpm-store', 'node_modules', 'target', '__pycache__'} for part in path.parts)
             and path.name != '.env' and not path.name.startswith('.env.')]
    output = ROOT / '.data/handoff'
    output.mkdir(parents=True, exist_ok=True)
    name = 'aegis-audit-windows-source-' + time.strftime('%Y%m%d-%H%M%S')
    archive = output / (name + '.zip')
    files = []
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED, strict_timestamps=False) as bundle:
        for path in paths:
            data = (ROOT / path).read_bytes()
            files.append({'path': path.as_posix(), 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
            bundle.writestr(name + '/' + path.as_posix(), data)
        manifest = {'schema_version': 1, 'purpose': 'Windows source handoff, including current uncommitted files',
                    'created_at': datetime.now(timezone.utc).isoformat(),
                    'version': re.search(r'\[workspace.package\]\s*version = "([^"]+)"', (ROOT / 'Cargo.toml').read_text(encoding='utf-8')).group(1),
                    'git_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                    'git_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True).strip()),
                    'files': files}
        bundle.writestr(name + '/SOURCE-MANIFEST.json', json.dumps(manifest, ensure_ascii=False, indent=2))
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix('.zip.sha256').write_text(checksum + '  ' + archive.name + '\n', encoding='utf-8')
    with zipfile.ZipFile(archive) as bundle:
        if bundle.testzip() is not None:
            raise ValueError('Source archive CRC check failed')
        for file in files:
            data = bundle.read(name + '/' + file['path'])
            if len(data) != file['size'] or hashlib.sha256(data).hexdigest() != file['sha256']:
                raise ValueError('Source archive verification failed: ' + file['path'])
    print(archive)
    print(f'{len(files)} source files verified; SHA-256 {checksum}')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error))
