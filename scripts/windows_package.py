#!/usr/bin/env python3
"""Build and bundle the Windows launcher and its private runtime dependencies."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

from aegis import ROOT, environment
from bootstrap import install_archive, install_python_tools

SPECS = json.loads((ROOT / 'tools/windows/versions.json').read_text(encoding='utf-8'))
TOOLS = ROOT / '.tools'
BUILD = ROOT / '.data/windows/standalone-build'


def prepare():
    if os.name != 'nt':
        raise RuntimeError('Build the standalone Windows package on Windows x64.')
    python = install_python_tools()
    if not python.is_file():
        raise RuntimeError('The pinned standalone Python installation is incomplete.')
    venv = TOOLS / 'windows-launcher-build'
    interpreter = venv / 'Scripts/python.exe'
    if not interpreter.is_file():
        subprocess.run([str(python), '-m', 'venv', str(venv)], check=True)
    subprocess.run([str(interpreter), '-m', 'pip', 'install', '--disable-pip-version-check',
                    '-r', str(ROOT / 'tools/windows/requirements.txt')], check=True)
    install_archive(SPECS['git'], TOOLS / 'git')
    subprocess.run([str(python), '-c', 'import tkinter; print("Bundled Python and Tk:", tkinter.TkVersion)'], check=True)
    return interpreter


def build_launcher():
    python = prepare()
    BUILD.mkdir(parents=True, exist_ok=True)
    subprocess.run([
        str(python), '-m', 'PyInstaller', '--noconfirm', '--clean', '--onedir', '--windowed',
        '--name', 'AegisAudit', '--icon', str(ROOT / 'tools/windows/aegis.ico'),
        '--paths', str(ROOT / 'scripts'), '--hidden-import', 'pystray._win32',
        '--exclude-module', 'pystray._darwin', '--exclude-module', 'pystray._xorg',
        '--exclude-module', 'pystray._appindicator', '--exclude-module', 'pystray._gtk',
        '--distpath', str(BUILD / 'dist'), '--workpath', str(BUILD / 'work'),
        '--specpath', str(BUILD), str(ROOT / 'scripts/windows_launcher.py'),
    ], cwd=ROOT, check=True)
    return BUILD / 'dist/AegisAudit', python


def collect_python_notices(python, destination):
    destination.mkdir(parents=True, exist_ok=True)
    script = '''
import importlib.metadata as metadata
import json
from pathlib import Path
import shutil
import sys
root = Path(sys.argv[1])
records = []
for package in metadata.distributions():
    name = package.metadata['Name']
    if name.lower() == 'pip':
        continue
    notices = []
    for file in package.files or []:
        if Path(file).name.upper().startswith(('LICENSE', 'LICENCE', 'COPYING', 'COPYRIGHT', 'NOTICE')):
            source = Path(package.locate_file(file))
            if source.is_file():
                target = root / name / Path(file).name
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists():
                    target = target.with_name(str(len(notices)) + '-' + target.name)
                shutil.copy2(source, target)
                notices.append(target.relative_to(root).as_posix())
    records.append({'name': name, 'version': package.version,
                    'license': package.metadata.get('License-Expression') or package.metadata.get('License'),
                    'notice_files': notices})
(root / 'index.json').write_text(json.dumps(records, ensure_ascii=False, indent=2) + '\\n', encoding='utf-8')
'''
    subprocess.run([str(python), '-c', script, str(destination)], check=True)
    for file in (TOOLS / 'windows-python').glob('*'):
        if file.is_file() and file.name.upper().startswith(('LICENSE', 'COPYING', 'COPYRIGHT')):
            shutil.copy2(file, destination / file.name)
    tcl = TOOLS / 'windows-python/tcl'
    if tcl.is_dir():
        for file in tcl.rglob('*'):
            if file.is_file() and file.name.lower() in ('license', 'license.terms'):
                target = destination / 'tcl-tk' / file.relative_to(tcl)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(file, target)


def bundle(stage, version):
    from install_reverse_tools import install as install_reverse_tools
    install_reverse_tools()
    launcher, python = build_launcher()
    shutil.copytree(launcher, stage, dirs_exist_ok=True)
    ghidra = Path(environment().get('GHIDRA_HOME', ''))
    jdk = TOOLS / 'jdk'
    if not (ghidra / 'support/analyzeHeadless.bat').is_file() or not (jdk / 'bin/java.exe').is_file():
        raise RuntimeError('Install the pinned Java/Ghidra runtime with scripts/bootstrap.py first.')
    for source, target in [(jdk, stage / '.tools/jdk'),
                           (ghidra, stage / '.tools/ghidra_12.1.3_PUBLIC'),
                           (TOOLS / 'git', stage / '.tools/git')]:
        shutil.copytree(source, target)
    shutil.copytree(TOOLS / 'windows-python', stage / '.tools/windows-python',
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc', 'Scripts'))
    shutil.copytree(TOOLS / 'reverse', stage / '.tools/reverse', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    icon = stage / 'tools/windows/aegis.ico'
    icon.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / 'tools/windows/aegis.ico', icon)
    shutil.copy2(ROOT / 'tools/windows/versions.json', icon.parent / 'versions.json')
    # The upstream JDK includes the redistributable required by the native Rust tools.
    runtime = jdk / 'bin/vcruntime140.dll'
    if not runtime.is_file():
        raise RuntimeError('The bundled JDK is missing its Visual C++ runtime.')
    shutil.copy2(runtime, stage / 'bin/vcruntime140.dll')
    collect_python_notices(python, stage / 'THIRD-PARTY-NOTICES/windows-launcher')
    collect_python_notices(TOOLS / 'windows-python/python.exe', stage / 'THIRD-PARTY-NOTICES/windows-analysis-tools')
    (stage / 'WINDOWS-STANDALONE.json').write_text(json.dumps({
        'schema_version': 1, 'version': version, 'entrypoint': 'AegisAudit.exe',
        'data_directory': '.data', 'requires_system_python': False,
        'requires_rust_or_node': False, 'bundled_python': SPECS['python']['version'],
        'bundled_git': SPECS['git']['version'], 'bundled_java': '21.0.12.1+1',
        'bundled_ghidra': '12.1.3', 'bundled_semgrep': '1.176.1', 'api_credentials_included': False,
        'dynamic_runtime': 'NOT_YET_WINDOWS_NATIVE',
    }, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare-only', action='store_true')
    options = parser.parse_args()
    print(prepare() if options.prepare_only else build_launcher()[0])
