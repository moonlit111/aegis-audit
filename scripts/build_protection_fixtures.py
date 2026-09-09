#!/usr/bin/env python3
"""Build the benign UPX mechanism fixture (plain + packed) and its manifest.

The fixture only proves that the B05 processing chain runs a real tool, keeps the
original untouched and records before/after evidence. It is not a course
acceptance object and cannot substitute for a real closed-source packed sample.

Usage: py -3 scripts/build_protection_fixtures.py
UPX is located via AEGIS_UPX or PATH; without it only the plain fixture is built.
"""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
from aegis import ROOT, environment, resolve_command

env = environment()
source = ROOT / 'tests/fixtures/protection/packable.rs'
output_dir = ROOT / 'tests/fixtures/protection'
# Rust embeds absolute paths; build in an ASCII path so the fixture is stable.
build_dir = ROOT / '.data/fixture-build/protection'
build_dir.mkdir(parents=True, exist_ok=True)

plain = build_dir / 'packable-plain.exe'
rustc_version = subprocess.check_output(
    resolve_command(['rustc', '-vV'], env), env=env, text=True).splitlines()[0]
subprocess.run(
    resolve_command([
        'rustc', '-O', '-C', 'strip=symbols',
        '-o', str(plain), str(source),
    ], env),
    env=env, check=True)

entries = {
    'plain': {
        'file': 'packable-plain.exe',
        'sha256': hashlib.sha256(plain.read_bytes()).hexdigest(),
        'size': plain.stat().st_size,
    },
}
shutil.copyfile(plain, output_dir / 'packable-plain.exe')
print('packable-plain.exe: ' + entries['plain']['sha256'])

upx = os.environ.get('AEGIS_UPX') or shutil.which('upx', path=env.get('PATH', ''))
if not upx:
    print('UPX not found (set AEGIS_UPX or add upx to PATH); packed fixture not rebuilt')
else:
    upx_version = subprocess.check_output([upx, '--version'], text=True).splitlines()[0].strip()
    packed = build_dir / 'packable-upx.exe'
    packed.unlink(missing_ok=True)
    shutil.copyfile(plain, packed)
    subprocess.run([upx, str(packed)], check=True, capture_output=True)
    entries['upx'] = {
        'file': 'packable-upx.exe',
        'sha256': hashlib.sha256(packed.read_bytes()).hexdigest(),
        'size': packed.stat().st_size,
        'tool': upx_version,
        'compression_ratio': round(packed.stat().st_size / plain.stat().st_size, 4),
    }
    shutil.copyfile(packed, output_dir / 'packable-upx.exe')
    print('packable-upx.exe: ' + entries['upx']['sha256'] + ' (' + upx_version + ')')

manifest = {
    'purpose': 'Benign UPX mechanism fixture for the B05 processing chain',
    'explicitly_not': 'a course acceptance case or a real closed-source packed object',
    'source': 'packable.rs',
    'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
    'toolchain': {'rustc': rustc_version},
    'reproducibility': 'rustc embeds build paths; the committed artifacts and hashes are authoritative',
    'fixtures': entries,
}
(output_dir / 'manifest.json').write_text(
    json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
print('manifest.json written')
