#!/usr/bin/env python3
"""Collect installed dependency licenses for an application distribution."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
from aegis import ROOT, environment, resolve_command


def collect(destination):
    destination.mkdir(parents=True, exist_ok=True)
    env = environment()
    metadata = json.loads(subprocess.check_output(resolve_command(['cargo', 'metadata', '--locked', '--format-version', '1'], env), cwd=ROOT, env=env))
    pnpm = 'pnpm.cmd' if __import__('os').name == 'nt' else 'pnpm'
    frontend = json.loads(subprocess.check_output(resolve_command([pnpm, '--dir', 'frontend', 'licenses', 'list', '--prod', '--json'], env), cwd=ROOT, env=env))
    packages = []
    for package in metadata['packages']:
        if package['source']:
            packages.append(('rust', package['name'], package['version'], package.get('license'), package.get('repository'), Path(package['manifest_path']).parent))
    for entries in frontend.values():
        for package in entries:
            for version, location in zip(package['versions'], package['paths']):
                packages.append(('javascript', package['name'], version, package.get('license'), package.get('homepage'), Path(location)))
    notices = []
    for ecosystem, name, version, license_id, repository, source in packages:
        key = re.sub(r'[^A-Za-z0-9_.-]', '_', name) + '-' + version
        files = []
        for file in sorted(source.rglob('*')):
            if file.is_file() and file.name.upper().startswith(('LICENSE', 'LICENCE', 'COPYING', 'NOTICE', 'COPYRIGHT', 'THIRDPARTYNOTICE')):
                relative = Path(ecosystem) / key / file.relative_to(source)
                target = destination / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(file, target)
                files.append(relative.as_posix())
        notices.append({'ecosystem': ecosystem, 'name': name, 'version': version, 'license': license_id, 'repository': repository, 'notice_files': files})
    (destination / 'index.json').write_text(json.dumps(notices, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (destination / 'README.txt').write_text('Dependency license metadata and upstream notice files.\nThe Rust list includes optional/build dependencies as a conservative superset.\nJava, Ghidra and Git are installed separately with their upstream licenses.\nThe optional Linux runtime image is built locally from tools/runtime/Dockerfile, retains its package licenses, and is not included in this ZIP.\nSee Docs/开源参考与依赖.md for external tools and code references.\n', encoding='utf-8')
    return notices


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / '.data/third-party-notices')
    options = parser.parse_args()
    print(f'Collected notices for {len(collect(options.output))} dependency packages.')
