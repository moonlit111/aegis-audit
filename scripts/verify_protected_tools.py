#!/usr/bin/env python3
"""Verify the paired protected Windows acceptance binaries (two packed, two obfuscated).

Every check is executed against the frozen build described by ``catalog.json``:
artifact integrity, the real protection applied to each pair, and a normal /
defect / corrected behaviour matrix. Static review alone never satisfies this
check; each verdict below comes from running the shipped binary.

Usage: py -3 scripts/verify_protected_tools.py --batch protected-tools-20260911-r3
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

from aegis import ROOT


DEFAULT_BATCH = 'protected-tools-20260911-r3'
UPX = ROOT / '.tools/reverse/upx/upx-5.2.1-win64/upx.exe'

# Operative constants that the obfuscated pairs encode in the shipped image and
# keep in plaintext in the unprotected reference build.
OBFUSCATION_MARKERS = {
    'O1': [b'admin'],
    'O2': [b'cmd.exe /d /c type ', b'relay.txt'],
}


def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def execute(command: list[str], cwd: Path, timeout: int = 60) -> dict:
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True,
                            encoding='utf-8', errors='replace', timeout=timeout, check=False)
    return {'command': [str(item) for item in command], 'exit_code': result.returncode,
            'stdout': result.stdout[-4096:], 'stderr': result.stderr[-4096:]}


def run_target(target: Path, arguments: list[str], directory: Path) -> dict:
    return execute([str(target)] + arguments, directory)


def upx_test(upx: Path, binary: Path, directory: Path) -> dict:
    record = execute([str(upx), '-t', str(binary)], directory)
    combined = record['stdout'] + record['stderr']
    record['packed'] = '[OK]' in combined and 'NotPackedException' not in combined
    record['not_packed'] = 'NotPackedException' in combined
    return record


def scan_plaintext(binary: Path, needles: list[bytes]) -> dict:
    data = binary.read_bytes()
    return {needle.decode('ascii', 'replace'): needle in data for needle in needles}


SPECS = [
    {
        'id': 'P1', 'name': 'ParcelDrop', 'protection': 'UPX',
        'fix_expectation': 'the corrected build imports the entry under the inbox',
        'normal': {'arguments': ['inbox', 'payload.txt', 'payload.txt'],
                   'expect_exit': 0, 'expect_present': ['inbox/payload.txt'], 'expect_absent': ['escaped.txt']},
        'probe': {'arguments': ['inbox', '..\\escaped.txt', 'payload.txt'],
                  'expect_exit': 0, 'expect_present': ['escaped.txt'],
                  'expect_absent': [], 'defect': 'the entry escapes the inbox'},
        'probe_fixed': {'expect_exit': 0, 'expect_present': ['inbox/escaped.txt'],
                        'expect_absent': ['escaped.txt']},
        'fixtures': {'payload.txt': 'parcel'},
    },
    {
        'id': 'P2', 'name': 'RowVault', 'protection': 'UPX',
        'fix_expectation': 'the corrected build truncates labels beyond the supported width',
        'normal': {'arguments': ['record.rv'], 'expect_exit': 0,
                   'expect_present': [], 'expect_absent': []},
        'probe': {'arguments': ['long.rv'], 'expect_exit': None,
                  'expect_present': [], 'expect_absent': [], 'defect': 'the label write leaves the record page'},
        'probe_fixed': {'expect_exit': 0, 'expect_present': [], 'expect_absent': []},
        'fixtures': {'record.rv': 'RV1' + ' ' + 'A' * 32, 'long.rv': 'RV1' + '`' + 'B' * 96},
    },
    {
        'id': 'O1', 'name': 'PermitLedger', 'protection': 'XOR_STRINGS_AND_OPAQUE_PREDICATE',
        'fix_expectation': 'the corrected build authorizes with the stored role and exports nothing',
        'normal': {'arguments': ['account.txt', 'alice', 'secret', 'guest', 'status',
                                 'record.txt', 'exported.txt'],
                   'expect_exit': 0, 'expect_present': [], 'expect_absent': ['exported.txt']},
        'probe': {'arguments': ['account.txt', 'alice', 'secret', 'admin', 'export',
                                'record.txt', 'exported.txt'],
                  'expect_exit': 0, 'expect_present': ['exported.txt'],
                  'expect_absent': [], 'defect': 'a requested role authorizes the export'},
        'probe_fixed': {'expect_exit': 0, 'expect_present': [], 'expect_absent': ['exported.txt']},
        'fixtures': {'account.txt': 'alice|secret|guest', 'record.txt': 'ledger-entry'},
    },
    {
        'id': 'O2', 'name': 'TextRelay', 'protection': 'XOR_STRINGS_AND_OPAQUE_PREDICATE',
        'fix_expectation': 'the corrected build copies the named file instead of interpreting it',
        'normal': {'arguments': ['doc.txt'], 'expect_exit': 0,
                   'expect_present': ['relay.txt'], 'expect_absent': ['injected.txt']},
        'probe': {'arguments': ['doc.txt & copy doc.txt injected.txt'],
                  'expect_exit': 0, 'expect_present': ['injected.txt'],
                  'expect_absent': [], 'defect': 'the document name reaches the command interpreter'},
        'probe_fixed': {'expect_exit': 0, 'expect_present': ['relay.txt'],
                        'expect_absent': ['injected.txt']},
        'fixtures': {'doc.txt': 'report-body',
                     'doc.txt & copy doc.txt injected.txt': 'report-body'},
    },
]


def case_result(binary: Path, root: Path, label: str, case: dict, fixtures: dict) -> dict:
    directory = root / label
    if directory.exists():
        shutil.rmtree(directory)
    directory.mkdir(parents=True)
    for name, content in fixtures.items():
        (directory / name).write_text(content, encoding='utf-8', newline='')
    started = time.monotonic()
    record = run_target(binary, list(case['arguments']), directory)
    record['seconds'] = round(time.monotonic() - started, 3)
    record['label'] = label
    record['arguments'] = list(case['arguments'])
    record['files_after'] = sorted(item.relative_to(directory).as_posix()
                                   for item in directory.rglob('*') if item.is_file())
    record['defect'] = case.get('defect', '')
    expected = case.get('expect_exit')
    checks = {'exit_code': (expected is None and record['exit_code'] != 0)
              or (expected is not None and record['exit_code'] == expected)}
    present = record['files_after']
    for name in case.get('expect_present', []):
        checks['present:' + name] = name in present
    for name in case.get('expect_absent', []):
        checks['absent:' + name] = name not in present
    record['checks'] = checks
    record['passed'] = all(checks.values())
    return record


def verify_batch(batch: Path, upx: Path) -> dict:
    catalog = json.loads((batch / 'catalog.json').read_text(encoding='utf-8'))
    build = json.loads((batch / 'build.json').read_text(encoding='utf-8'))
    by_id: dict[str, list[dict]] = {}
    for entry in catalog:
        by_id.setdefault(entry['id'], []).append(entry)
    scratch = batch / 'verification'
    scratch.mkdir(exist_ok=True)
    upx_version = execute([str(upx), '--version'], scratch)['stdout'].splitlines()[0].strip()
    results = []
    for spec in SPECS:
        entries = by_id[spec['id']]
        versions = {entry['version']: entry for entry in entries}
        target = batch / versions['1.0.0']['path']
        corrected = batch / versions['1.0.1']['path']
        reference = batch / 'reference' / spec['id'] / '1.0.0' / 'reference.exe'
        integrity = {
            'baseline': sha256(target) == versions['1.0.0']['sha256'],
            'corrected': sha256(corrected) == versions['1.0.1']['sha256'],
        }
        package = {entry['path']: sha256(batch / entry['path']) for entry in entries}
        protection = {'baseline': upx_test(upx, target, scratch),
                      'corrected': upx_test(upx, corrected, scratch)}
        protected_file = batch / 'reference' / spec['id'] / '1.0.0' / 'protected.exe'
        obfuscation = None
        if spec['protection'] == 'UPX':
            unpacked = batch / 'reference' / spec['id'] / '1.0.0' / 'unpacked.exe'
            protection['unpacked'] = upx_test(upx, unpacked, scratch)
            protection['checks'] = {
                'baseline_packed': protection['baseline']['packed'],
                'corrected_packed': protection['corrected']['packed'],
                'unpacked_is_not_packed': protection['unpacked']['not_packed'],
                'unpacked_restores_the_reference_body':
                    unpacked.stat().st_size == reference.stat().st_size,
            }
        else:
            hidden = scan_plaintext(protected_file, OBFUSCATION_MARKERS[spec['id']])
            visible = scan_plaintext(reference, OBFUSCATION_MARKERS[spec['id']])
            obfuscation = {
                'markers': OBFUSCATION_MARKERS[spec['id']][0].decode('ascii', 'replace'),
                'protected': hidden, 'reference': visible,
                'checks': {
                    'protected_hides_every_marker': not any(hidden.values()),
                    'reference_keeps_the_plaintext': all(visible.values()),
                    'shipped_images_are_not_packed': (protection['baseline']['not_packed']
                                                      and protection['corrected']['not_packed']),
                },
            }
        root = scratch / spec['id']
        normal = case_result(target, root, 'normal', spec['normal'], spec['fixtures'])
        probe = case_result(target, root, 'probe', spec['probe'], spec['fixtures'])
        fixed_case = {**spec['probe'], **spec['probe_fixed']}
        fixed_case['defect'] = ''
        fixed = case_result(corrected, root, 'probe-corrected', fixed_case, spec['fixtures'])
        fixed_normal = case_result(corrected, root, 'normal-corrected',
                                   dict(spec['normal']), spec['fixtures'])
        checks = {'artifact_integrity': all(integrity.values()),
                  'normal_input_accepted': normal['passed'],
                  'defect_reproduced_on_baseline': probe['passed'],
                  'defect_absent_after_correction': fixed['passed'],
                  'normal_input_accepted_after_correction': fixed_normal['passed'],
                  'package_hashes_match': all(
                      package[entry['path']] == entry['sha256'] for entry in entries)}
        checks.update(protection.get('checks', {}))
        if obfuscation:
            checks.update(obfuscation['checks'])
        results.append({
            'id': spec['id'], 'name': spec['name'], 'protection': spec['protection'],
            'fix_expectation': spec['fix_expectation'],
            'targets': {'baseline': versions['1.0.0']['path'], 'corrected': versions['1.0.1']['path']},
            'sha256': {'baseline': sha256(target), 'corrected': sha256(corrected)},
            'integrity': integrity, 'protection_evidence': protection,
            'obfuscation_evidence': obfuscation,
            'cases': {'normal': normal, 'probe': probe, 'probe_corrected': fixed,
                      'normal_corrected': fixed_normal},
            'checks': checks, 'passed': all(checks.values()),
        })
        print(spec['id'] + ': ' + json.dumps({'passed': all(checks.values()),
                                              'failed': [k for k, v in checks.items() if not v]}),
              flush=True)
    document = {
        'schema_version': 1,
        'batch': batch.name,
        'created_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'platform': 'windows/x64',
        'scope': 'CONTROLLED_BINARY_ACCEPTANCE',
        'purpose': 'Runtime verification of the two packed and two obfuscated closed-source targets',
        'upx': upx_version,
        'build_hash': sha256(batch / 'build.json'),
        'package': build.get('package', {}),
        'targets': results,
        'passed': all(item['passed'] for item in results),
        'formal_acceptance': False,
        'limitations': [
            'Every verdict comes from running the shipped binary; no result is inferred from source.',
            'The defect and corrected builds are verified as a pair, not as one independent sample.',
        ],
    }
    return document


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--batch', default=DEFAULT_BATCH)
    parser.add_argument('--upx', type=Path, default=UPX)
    parser.add_argument('--output', type=Path)
    options = parser.parse_args()
    if Path(options.batch).name != options.batch:
        parser.error('--batch must be a single directory name')
    batch = ROOT / '.data/verification/protected-tools' / options.batch
    if not batch.is_dir():
        parser.error('batch directory not found: ' + str(batch))
    if not options.upx.is_file():
        parser.error('UPX not found: ' + str(options.upx))
    document = verify_batch(batch, options.upx)
    output = options.output or (batch / 'verification.json')
    output.write_text(json.dumps(document, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'passed': document['passed'], 'evidence': str(output),
                      'targets': [{'id': item['id'], 'passed': item['passed']}
                                  for item in document['targets']]}, ensure_ascii=False, indent=2))
    return 0 if document['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
