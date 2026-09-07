#!/usr/bin/env python3
"""Install pinned tools locally; requires Python, Git and a native C/C++ toolchain."""
import argparse
import hashlib
import inspect
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile
import urllib.parse
import urllib.request
import zipfile
from aegis import ROOT, environment

TOOLS = ROOT / '.tools'
VERSIONS = json.loads((ROOT / 'tools/versions.json').read_text(encoding='utf-8'))


def host_key():
    system = platform.system().lower()
    arch = {'aarch64': 'arm64', 'arm64': 'arm64', 'amd64': 'x64', 'x86_64': 'x64'}.get(platform.machine().lower(), platform.machine().lower())
    key = system + '-' + arch
    if key not in VERSIONS['platforms']:
        raise RuntimeError('Bootstrap currently supports macOS ARM64, Windows x64 and Linux x64. Configure other toolchains manually.')
    return key


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def download(url, checksum):
    cache = TOOLS / 'downloads'
    cache.mkdir(parents=True, exist_ok=True)
    path = cache / urllib.parse.unquote(url.rsplit('/', 1)[-1])
    if path.is_file() and digest(path) == checksum:
        return path
    print('Downloading ' + path.name, flush=True)
    partial = path.with_name(path.name + '.partial')
    with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'AegisAudit-bootstrap/0.1'}), timeout=120) as source, partial.open('wb') as target:
        shutil.copyfileobj(source, target, 1024 * 1024)
    if digest(partial) != checksum:
        partial.unlink()
        raise RuntimeError('SHA-256 mismatch: ' + path.name)
    partial.replace(path)
    return path


def unpack(archive, destination):
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='extract-', dir=TOOLS) as temporary:
        root = Path(temporary)
        if zipfile.is_zipfile(archive):
            with zipfile.ZipFile(archive) as package:
                for item in package.infolist():
                    target = (root / item.filename).resolve()
                    if root.resolve() not in target.parents:
                        raise RuntimeError('Archive path escapes extraction directory')
                package.extractall(root)
                if os.name != 'nt':
                    for item in package.infolist():
                        permissions = item.external_attr >> 16 & 0o777
                        if permissions:
                            (root / item.filename).chmod(permissions)
        else:
            with tarfile.open(archive) as package:
                for item in package.getmembers():
                    target = (root / item.name).resolve()
                    if target != root.resolve() and root.resolve() not in target.parents:
                        raise RuntimeError('Archive path escapes extraction directory')
                options = {'filter': 'data'} if 'filter' in inspect.signature(package.extractall).parameters else {}
                package.extractall(root, **options)
        children = list(root.iterdir())
        source = children[0] if len(children) == 1 and children[0].is_dir() else root
        for item in source.iterdir():
            shutil.move(str(item), destination / item.name)


def install_archive(spec, destination):
    if destination.is_dir() and any(destination.iterdir()):
        print('Using ' + str(destination), flush=True)
        return
    unpack(download(spec['url'], spec['sha256']), destination)


def command(args, env=None, cwd=ROOT):
    subprocess.run([str(arg) for arg in args], cwd=cwd, env=env or environment(), check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--core-only', action='store_true', help='Skip Java and Ghidra; source analysis only')
    group.add_argument('--runtime-only', action='store_true', help='Only Java/Ghidra for a prebuilt application package')
    parser.add_argument('--sdk-dir', type=Path, help='ASCII directory for Ghidra')
    options = parser.parse_args()
    host = VERSIONS['platforms'][host_key()]
    TOOLS.mkdir(parents=True, exist_ok=True)
    if not shutil.which('git'):
        raise RuntimeError('Install Git first (Git for Windows / Xcode Command Line Tools / system package manager).')
    if not options.runtime_only:
        install_archive(host['node'], TOOLS / 'node')
        env = environment()
        env['RUSTUP_HOME'] = str(TOOLS / 'rustup')
        env['CARGO_HOME'] = str(TOOLS / 'cargo')
        suffix = '.exe' if os.name == 'nt' else ''
        rustup = TOOLS / 'cargo/bin' / ('rustup' + suffix)
        if not rustup.is_file():
            url = f'https://static.rust-lang.org/rustup/dist/{host["rust_host"]}/rustup-init{suffix}'
            with urllib.request.urlopen(url + '.sha256', timeout=30) as response:
                checksum = response.read().decode().split()[0]
            installer = download(url, checksum)
            installer.chmod(0o755)
            command([installer, '-y', '--no-modify-path', '--profile', 'minimal', '--default-toolchain', VERSIONS['rust']], env)
        command([rustup, 'toolchain', 'install', VERSIONS['rust'], '--profile', 'minimal'], env)
        command([rustup, 'component', 'add', '--toolchain', VERSIONS['rust'], 'rustfmt', 'clippy'], env)
        env = environment()
        npm = 'npm.cmd' if os.name == 'nt' else 'npm'
        pnpm = 'pnpm.cmd' if os.name == 'nt' else 'pnpm'
        local_pnpm = TOOLS / ('pnpm/pnpm.cmd' if os.name == 'nt' else 'pnpm/bin/pnpm')
        if not local_pnpm.exists():
            command([npm, 'install', '--global', '--prefix', TOOLS / 'pnpm', 'pnpm@' + VERSIONS['pnpm'], '--no-audit', '--no-fund'], env)
        env = environment()
        command([pnpm, '--dir', 'frontend', 'install', '--frozen-lockfile'], env)
        binary = TOOLS / 'bin' / ('buf' + suffix)
        binary.parent.mkdir(exist_ok=True)
        if not binary.exists() or digest(binary) != host['buf']['sha256']:
            shutil.copy2(download(host['buf']['url'], host['buf']['sha256']), binary)
            binary.chmod(0o755)
        installed = subprocess.check_output(['cargo', 'install', '--list'], env=env, text=True)
        for package, version in [('connectrpc-codegen', VERSIONS['connect_codegen']), ('protoc-gen-buffa', VERSIONS['buffa_codegen']), ('protoc-gen-buffa-packaging', VERSIONS['buffa_codegen'])]:
            if f'{package} v{version}:' not in installed:
                command(['cargo', 'install', package, '--version', version, '--locked'], env)
    if not options.core_only:
        install_archive(host['jdk'], TOOLS / 'jdk')
        sdk_root = options.sdk_dir or Path.home() / '.cache/aegis-audit'
        if not str(sdk_root).isascii():
            sdk_root = Path(os.environ.get('PUBLIC', 'C:/Users/Public')) / 'AegisAudit/tools' if os.name == 'nt' else Path('/Users/Shared/AegisAudit/tools')
        if not str(sdk_root).isascii():
            raise RuntimeError('Ghidra requires an ASCII SDK path; pass --sdk-dir.')
        ghidra = sdk_root / ('ghidra_' + VERSIONS['ghidra']['version'] + '_PUBLIC')
        install_archive(VERSIONS['ghidra'], ghidra)
        (TOOLS / 'paths.json').write_text(json.dumps({'ghidra': str(ghidra.resolve())}, indent=2) + '\n', encoding='utf-8')
        native = 'decompile.exe' if os.name == 'nt' else 'decompile'
        if not any((ghidra / ('Ghidra/Features/Decompiler/' + directory) / host['ghidra_native'] / native).is_file() for directory in ['os', 'build/os']):
            env = environment()
            env['GRADLE_USER_HOME'] = str(TOOLS / 'gradle-cache')
            gradle = ghidra / 'support/gradle' / ('gradlew.bat' if os.name == 'nt' else 'gradlew')
            if os.name != 'nt': gradle.chmod(gradle.stat().st_mode | 0o111)
            command([gradle, 'buildNatives', '--no-daemon', '--max-workers=4', '--console=plain'], env, ghidra / 'support/gradle')
    next_action = 'start --open' if options.runtime_only else 'build'
    print('Tool setup complete. Run: python scripts/manage.py ' + next_action, flush=True)


if __name__ == '__main__':
    main()
