#!/usr/bin/env python3
"""Install pinned native reverse-engineering tools into this workspace."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import urllib.parse
import urllib.request
import zipfile

from aegis import ROOT, require_windows


def archive_members(package):
    for item in package.infolist():
        name = item.filename.replace('\\', '/')
        path = PurePosixPath(name)
        if path.is_absolute() or '..' in path.parts or ':' in name or (item.external_attr >> 16) & 0o170000 == 0o120000:
            raise RuntimeError('Unsafe path in tool archive: ' + name)
        yield item, path


def install():
    require_windows()
    specs = json.loads((ROOT / 'tools/reverse/versions.json').read_text(encoding='utf-8'))
    downloads = ROOT / '.tools/downloads'
    downloads.mkdir(parents=True, exist_ok=True)
    installed = {}
    for name, spec in specs.items():
        archive = downloads / spec.get('archive_name', Path(urllib.parse.urlparse(spec['url']).path).name)
        if not archive.is_file():
            temporary = archive.with_suffix(archive.suffix + '.part')
            request = urllib.request.Request(spec['url'], headers={'User-Agent': 'AegisAudit-tool-installer'})
            with urllib.request.urlopen(request, timeout=120) as response, temporary.open('wb') as output:
                shutil.copyfileobj(response, output)
            if hashlib.sha256(temporary.read_bytes()).hexdigest() != spec['sha256']:
                raise RuntimeError('Tool archive checksum mismatch: ' + name)
            os.replace(temporary, archive)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != spec['sha256']:
            raise RuntimeError('Cached tool archive checksum mismatch: ' + str(archive))
        destination = ROOT / '.tools/reverse' / name
        destination.mkdir(parents=True, exist_ok=True)
        if 'license_file' in spec:
            license_spec = spec['license_file']
            license_cache = downloads / (name + '-LICENSE.txt')
            if not license_cache.is_file():
                with urllib.request.urlopen(license_spec['url'], timeout=30) as response:
                    license_cache.write_bytes(response.read())
            data = license_cache.read_bytes()
            if hashlib.sha256(data).hexdigest() != license_spec['sha256']:
                raise RuntimeError('Tool license checksum mismatch: ' + name)
            (destination / 'LICENSE.txt').write_bytes(data)
        with zipfile.ZipFile(archive) as package:
            members = list(archive_members(package))
            if sum(item.file_size for item, _ in members) > 256 * 1024 * 1024:
                raise RuntimeError('Tool archive exceeds extraction limit')
            # Retain upstream license files and complete runtime resources.
            for item, relative in members:
                target = destination.joinpath(*relative.parts)
                if item.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with package.open(item) as source, target.open('wb') as output:
                        shutil.copyfileobj(source, output)
        if 'source_marker' in spec:
            markers = [p for p in destination.rglob('manager.py') if p.parent.name == 'd810']
            if len(markers) != 1:
                raise RuntimeError('Expected D-810 source package')
            installed[name] = {'path': markers[0].parent.parent.relative_to(ROOT).as_posix(),
                               'version': spec['version'], 'archive_sha256': spec['sha256']}
            print(name + ' source prepared; IDA/Hex-Rays probe is still required', flush=True)
            continue
        executables = list(destination.rglob(spec['executable']))
        if len(executables) != 1:
            raise RuntimeError('Expected exactly one tool executable: ' + name)
        executable = executables[0]
        probe = subprocess.run([str(executable), '--version'], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30,
                               creationflags=subprocess.CREATE_NO_WINDOW, check=True)
        version = (probe.stdout + probe.stderr).strip()
        if spec['version'] not in version:
            raise RuntimeError('Installed tool version mismatch: ' + name)
        installed[name] = {'path': executable.relative_to(ROOT).as_posix(), 'version': spec['version'],
                           'archive_sha256': spec['sha256'], 'executable_sha256': hashlib.sha256(executable.read_bytes()).hexdigest()}
        print(name + ' ' + spec['version'] + ': ' + str(executable), flush=True)
    manifest = ROOT / '.tools/reverse/installed.json'
    manifest.write_text(json.dumps(installed, indent=2) + '\n', encoding='utf-8')
    return installed


if __name__ == '__main__':
    argparse.ArgumentParser(description=__doc__).parse_args()
    install()
