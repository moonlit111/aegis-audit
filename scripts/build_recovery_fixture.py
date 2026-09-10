#!/usr/bin/env python3
"""Build (without executing) the benign string/MBA recovery fixture and its UPX variant."""
import hashlib
import json
from pathlib import Path
import subprocess
import shutil
import tempfile
from aegis import ROOT, environment, resolve_command


def main():
    env = environment()
    folder = ROOT / 'tests/fixtures/recovery'
    build_root = ROOT / '.data/fixture-build/recovery'
    build_root.mkdir(parents=True, exist_ok=True)
    build = Path(tempfile.mkdtemp(prefix='build-', dir=build_root))
    plain, packed = build / 'sample.exe', build / 'sample-upx.exe'
    command = ['rustc', '--edition', '2024', '-C', 'opt-level=0', '-C', 'panic=abort', '-C', 'debug-assertions=no',
               '-C', 'overflow-checks=no', '-C', 'link-arg=/ENTRY:mainCRTStartup', '-C', 'link-arg=/SUBSYSTEM:CONSOLE',
               '-C', 'link-arg=/NODEFAULTLIB', '-C', 'link-arg=/EXPORT:decode_table', '-C', 'link-arg=/EXPORT:mba_add', '-C', 'link-arg=/EXPORT:mba_add64',
               '-o', str(plain), str(folder / 'sample.rs')]
    subprocess.run(resolve_command(command, env), env=env, check=True)
    subprocess.run([env['AEGIS_UPX'], '-o', str(packed), str(plain)], env=env, check=True)
    expected = 'AegisAudit recovered test string'
    if expected.encode() in plain.read_bytes():
        raise RuntimeError('The fixture leaked the decoded test string into static bytes')
    for artifact in (plain, packed):
        shutil.copy2(artifact, folder / artifact.name)
    record = {'purpose': 'Benign tool integration fixture; not a course acceptance target', 'target_executed': False,
              'source_sha256': hashlib.sha256((folder / 'sample.rs').read_bytes()).hexdigest(),
              'expected_recovered_string': expected, 'mba_equivalence': '(a XOR b) + 2 * (a AND b) == a + b modulo 2^32',
              'files': [{ 'name': p.name, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest(), 'size': p.stat().st_size } for p in (plain, packed)]}
    (folder / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
