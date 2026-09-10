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
from aegis import ROOT, environment, require_windows
from notices import collect


def main():
    require_windows()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-build', action='store_true')
    parser.add_argument('--standalone-windows', action='store_true', help='Bundle the Windows EXE launcher, Python, Git, Java and Ghidra')
    parser.add_argument('--output', type=Path, default=ROOT / '.data/dist')
    options = parser.parse_args()
    if not options.no_build:
        subprocess.run([__import__('sys').executable, 'scripts/manage.py', 'build'], cwd=ROOT, env=environment(), check=True)
    version = re.search(r'\[workspace.package\]\s*version = "([^"]+)"', (ROOT / 'Cargo.toml').read_text()).group(1)
    name = f'aegis-audit-{version}-windows-amd64'
    if options.standalone_windows:
        name += '-standalone'
    options.output.mkdir(parents=True, exist_ok=True)
    suffix = '.exe'
    with tempfile.TemporaryDirectory(prefix='aegis-package-') as temporary:
        stage = Path(temporary) / name
        for binary in ['aegis-server', 'aegis-executor']:
            target = stage / 'bin' / (binary + suffix)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / 'target/release' / (binary + suffix), target)
        shutil.copytree(ROOT / 'frontend/dist', stage / 'frontend/dist')
        shutil.copytree(ROOT / 'Docs', stage / 'Docs')
        shutil.copytree(ROOT / 'tools/runtime', stage / 'tools/runtime', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        for source in ['README.md', 'tools/versions.json', 'tools/windows/versions.json', 'tools/windows/semgrep-requirements.txt', 'tools/ghidra/ExportProgram.java', 'tools/ida/d810_export.py', 'tools/reverse/versions.json', 'tools/reverse/requirements.txt', 'scripts/aegis.py', 'scripts/bootstrap.py', 'scripts/manage.py', 'scripts/configure_model.py', 'scripts/windows_secrets.py', 'scripts/install_reverse_tools.py', 'scripts/configure_d810.py']:
            target = stage / source
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / source, target)
        collect(stage / 'THIRD-PARTY-NOTICES')
        if options.standalone_windows:
            from windows_package import bundle
            bundle(stage, version)
        files = [{'path': file.relative_to(stage).as_posix(), 'sha256': hashlib.sha256(file.read_bytes()).hexdigest(), 'size': file.stat().st_size}
                 for file in sorted(stage.rglob('*')) if file.is_file()]
        source_state = {
            'git_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
            'git_dirty': bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True).strip()),
        }
        (stage / 'PACKAGE-MANIFEST.json').write_text(json.dumps({
            'version': version, 'platform': platform.platform(),
            'scopes': ['STRUCTURE_ANALYSIS', 'SECURITY_AUDIT', 'RUNTIME_VERIFICATION', 'DYNAMIC_TESTING'],
            'pending_windows_native_scopes': ['RUNTIME_VERIFICATION', 'DYNAMIC_TESTING'],
            'source_at_packaging': source_state, 'files': files,
        }, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        archive = options.output / (name + '.zip')
        with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED, strict_timestamps=False) as output:
            for file in sorted(stage.rglob('*')):
                if file.is_file(): output.write(file, file.relative_to(stage.parent))
        checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
        archive.with_suffix('.zip.sha256').write_text(checksum + '  ' + archive.name + '\n')
        print(str(archive))
        print('SHA-256: ' + checksum)


if __name__ == '__main__':
    main()
