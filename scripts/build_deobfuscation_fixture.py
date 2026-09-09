#!/usr/bin/env python3
"""Build the benign B06 deobfuscation mechanism fixture and its manifest.

The fixture only proves that the static recovery chain finds and decodes a
single-byte XOR string table and a base64 text table. It is not a course
acceptance object and cannot substitute for a real obfuscated sample.

Usage: py -3 scripts/build_deobfuscation_fixture.py
"""
from pathlib import Path
import hashlib
import json
import shutil
import subprocess
from aegis import ROOT, environment, resolve_command

env = environment()
source = ROOT / 'tests/fixtures/deobfuscation/obfuscated.rs'
output_dir = ROOT / 'tests/fixtures/deobfuscation'
# Rust embeds absolute paths; build in an ASCII path so the fixture is stable.
build_dir = ROOT / '.data/fixture-build/deobfuscation'
build_dir.mkdir(parents=True, exist_ok=True)
output = build_dir / 'obfuscated.exe'

rustc_version = subprocess.check_output(
    resolve_command(['rustc', '-vV'], env), env=env, text=True).splitlines()[0]
subprocess.run(
    resolve_command([
        'rustc', '-O', '-C', 'no-vectorize-loops', '-C', 'no-vectorize-slp',
        '-C', 'strip=symbols', '-o', str(output), str(source),
    ], env),
    env=env, check=True)
(data, size) = (output.read_bytes(), output.stat().st_size)
manifest = {
    'purpose': 'Benign B06 deobfuscation mechanism fixture (single-byte XOR + base64 text table)',
    'explicitly_not': 'a course acceptance case or a real obfuscated sample',
    'source': 'obfuscated.rs',
    'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
    'toolchain': {'rustc': rustc_version},
    'expected': {
        'xor_key': '0x5a',
        'xor_plaintext_contains': 'AegisAudit deobfuscation fixture',
        'repeating_xor_key': '37139b42',
        'repeating_plaintext_contains': 'AegisAudit repeating key fixture',
        'base64_plaintext_contains': 'AegisAudit base64 fixture',
    },
    'reproducibility': 'rustc embeds build paths; the committed artifact and hash are authoritative',
    'fixtures': [{
        'file': 'obfuscated.exe',
        'sha256': hashlib.sha256(data).hexdigest(),
        'size': size,
    }],
}
(output_dir / 'manifest.json').write_text(
    json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
shutil.copyfile(output, output_dir / 'obfuscated.exe')
print('obfuscated.exe: ' + manifest['fixtures'][0]['sha256'])
print('manifest.json written')
