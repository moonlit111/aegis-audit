#!/usr/bin/env python3
"""Verify a local IDA Pro/Hex-Rays installation before enabling the optional D-810 adapter."""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from aegis import ROOT, require_windows


def product_version(path):
    version = ctypes.WinDLL('version', use_last_error=True)
    version.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
    version.GetFileVersionInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID]
    version.VerQueryValueW.argtypes = [wintypes.LPCVOID, wintypes.LPCWSTR, ctypes.POINTER(wintypes.LPVOID), ctypes.POINTER(wintypes.UINT)]
    ignored = wintypes.DWORD()
    size = version.GetFileVersionInfoSizeW(str(path), ctypes.byref(ignored))
    if not size:
        raise RuntimeError('IDA version metadata is unavailable: ' + str(path))
    buffer = ctypes.create_string_buffer(size)
    if not version.GetFileVersionInfoW(str(path), 0, size, buffer):
        raise ctypes.WinError(ctypes.get_last_error())
    pointer, length = wintypes.LPVOID(), wintypes.UINT()
    if not version.VerQueryValueW(buffer, '\\', ctypes.byref(pointer), ctypes.byref(length)):
        raise ctypes.WinError(ctypes.get_last_error())
    fields = ctypes.cast(pointer, ctypes.POINTER(wintypes.DWORD * 13)).contents
    high, low = fields[4], fields[5]
    return high >> 16, high & 0xffff, low >> 16, low & 0xffff


def check_version(version):
    if tuple(version[:2]) < (7, 5):
        raise RuntimeError('IDA ' + '.'.join(map(str, version)) + ' is incompatible: D-810 requires IDA >= 7.5 and IDAPython >= 3.7. IDA 7.0/Python 2.7 cannot load this adapter.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ida-dir', type=Path, required=True)
    parser.add_argument('--d810-root', type=Path)
    parser.add_argument('--check-only', action='store_true')
    options = parser.parse_args()
    require_windows()
    ida_dir = options.ida_dir.resolve()
    gui = next((p for p in [ida_dir / 'ida64.exe', ida_dir / 'ida.exe'] if p.is_file()), None)
    if gui is None:
        raise RuntimeError('IDA executable not found in ' + str(ida_dir))
    version = product_version(gui)
    print('Detected IDA ' + '.'.join(map(str, version)), flush=True)
    check_version(version)
    executable = next((p for p in [ida_dir / 'idat64.exe', ida_dir / 'idat.exe'] if p.is_file()), None)
    python_plugins = list((ida_dir / 'plugins').glob('*python*.dll'))
    if executable is None or not python_plugins:
        raise RuntimeError('Required IDA Pro console / IDAPython components are missing. IDA Freeware does not provide the local Python microcode interface needed by D-810.')
    if options.check_only:
        print('Version minimum satisfied; Hex-Rays/Python/D-810 still require a real probe.')
        return
    if options.d810_root:
        plugin_root = options.d810_root.resolve()
    else:
        installed = json.loads((ROOT / '.tools/reverse/installed.json').read_text(encoding='utf-8'))
        plugin_root = (ROOT / installed['d810_ng' if version[0] >= 9 else 'd810']['path']).resolve()
    manager = plugin_root / 'd810/manager.py'
    if not manager.is_file():
        raise RuntimeError('The pinned D-810 package is required; run scripts/install_reverse_tools.py')
    dependencies = ROOT / '.tools/reverse/d810-deps'
    if not (dependencies / 'z3').is_dir():
        raise RuntimeError('Install the private dependencies from tools/reverse/requirements.txt first')
    bridge = ROOT / 'tools/ida/d810_export.py'
    parent = ROOT / '.data/verification/ida-d810'
    parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='probe-', dir=parent))
    shutil.copy2(bridge, work / 'd810_export.py')
    shutil.copy2(ROOT / 'tests/fixtures/binary/sample-pe64.exe', work / 'target.bin')
    (work / 'd810-request.json').write_text(json.dumps({'plugin_root': str(plugin_root), 'dependencies': str(dependencies), 'profile': 'instructions',
                                                       'snapshot_path': 'probe.exe', 'max_functions': 1}), encoding='utf-8')
    with (work / 'console.log').open('wb') as log:
        completed = subprocess.run([str(executable), '-A', '-Lida.log', '-Sd810_export.py', '-oanalysis.i64', 'target.bin'],
                                   cwd=work, stdout=log, stderr=subprocess.STDOUT, timeout=240,
                                   creationflags=subprocess.CREATE_NO_WINDOW)
    result_file = work / 'd810-result.json'
    if completed.returncode or not result_file.is_file():
        raise RuntimeError('IDA/Hex-Rays/D-810 probe failed. Check Python 3, z3-solver, architecture license and logs: ' + str(work))
    result = json.loads(result_file.read_text(encoding='utf-8'))
    metadata = result.get('metadata', {})
    if not metadata.get('hexrays_initialized') or not metadata.get('d810_hooks_installed') or not any(u.get('code') for u in result.get('units', [])):
        raise RuntimeError('Probe did not produce real pseudocode: ' + str(work))
    settings = {'executable': str(executable), 'plugin_root': str(plugin_root), 'dependencies': str(dependencies), 'variant': metadata['d810_variant'], 'verified': True,
                'ida_version': metadata['ida_version'], 'hexrays_version': metadata['hexrays_version'],
                'executable_sha256': hashlib.sha256(executable.read_bytes()).hexdigest(),
                'manager_sha256': hashlib.sha256(manager.read_bytes()).hexdigest(),
                'bridge_sha256': hashlib.sha256(bridge.read_bytes()).hexdigest()}
    target = ROOT / '.tools/ida-d810.json'
    target.write_text(json.dumps(settings, indent=2) + '\n', encoding='utf-8')
    print('Verified local D-810 adapter; restart the executor. Evidence: ' + str(work))


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, KeyError, subprocess.TimeoutExpired) as error:
        raise SystemExit(str(error))
