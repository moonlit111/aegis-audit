#!/usr/bin/env python3
"""Package native release binaries, browser assets and setup files, excluding all runtime data."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import zipfile
from aegis import ROOT, environment
from notices import collect


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-build', action='store_true')
    parser.add_argument('--output', type=Path, default=ROOT / '.data/dist')
    options = parser.parse_args()
    if not options.no_build:
        subprocess.run([__import__('sys').executable, 'scripts/manage.py', 'build'], cwd=ROOT, env=environment(), check=True)
    version = re.search(r'\[workspace.package\]\s*version = "([^"]+)"', (ROOT / 'Cargo.toml').read_text()).group(1)
    name = f'aegis-audit-{version}-{platform.system().lower()}-{platform.machine().lower()}'
    options.output.mkdir(parents=True, exist_ok=True)
    suffix = '.exe' if os.name == 'nt' else ''
    with tempfile.TemporaryDirectory(prefix='aegis-package-') as temporary:
        stage = Path(temporary) / name
        for binary in ['aegis-server', 'aegis-executor']:
            target = stage / 'bin' / (binary + suffix)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / 'target/release' / (binary + suffix), target)
        shutil.copytree(ROOT / 'frontend/dist', stage / 'frontend/dist')
        shutil.copytree(ROOT / 'Docs', stage / 'Docs')
        for source in ['README.md', 'tools/versions.json', 'tools/ghidra/ExportProgram.java', 'scripts/aegis.py', 'scripts/bootstrap.py', 'scripts/manage.py', 'scripts/configure_model.py']:
            target = stage / source
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / source, target)
        collect(stage / 'THIRD-PARTY-NOTICES')
        files = [{'path': file.relative_to(stage).as_posix(), 'sha256': hashlib.sha256(file.read_bytes()).hexdigest(), 'size': file.stat().st_size}
                 for file in sorted(stage.rglob('*')) if file.is_file()]
        (stage / 'PACKAGE-MANIFEST.json').write_text(json.dumps({'version': version, 'platform': platform.platform(), 'scope': 'STRUCTURE_ANALYSIS', 'files': files}, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        archive = options.output / (name + '.zip')
        with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as output:
            for file in sorted(stage.rglob('*')):
                if file.is_file(): output.write(file, file.relative_to(stage.parent))
        checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
        archive.with_suffix('.zip.sha256').write_text(checksum + '  ' + archive.name + '\n')
        print(str(archive))
        print('SHA-256: ' + checksum)


if __name__ == '__main__':
    main()
