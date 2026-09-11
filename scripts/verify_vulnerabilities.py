#!/usr/bin/env python3
"""Independently verify that each shipped 1.0.0 binary really carries the reported defect.

This harness does not reuse the archived PoC recipe: it drives the documented
command line itself, with a negative control, the exploit input and (where the
defect has one) a boundary probe. Static corroboration only reads the import
table of the frozen binary.

Usage: py -3 scripts/verify_vulnerabilities.py --batch protected-tools-20260911-r3
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

from aegis import ROOT


STATUS_CRASH = {0xC0000005, 0xC000001D, 0xC00000FD, 0xC0000374, 0xC0000409}


def import_probe(binary: Path, symbols: list[str]) -> dict:
    data = binary.read_bytes()
    return {symbol: symbol.encode() in data for symbol in symbols}


def run(target: Path, arguments: list[str], work: Path, fixtures: dict[str, str]) -> dict:
    work.mkdir(parents=True, exist_ok=True)
    for name, content in fixtures.items():
        (work / name).write_text(content, encoding="utf-8", newline="")
    completed = subprocess.run([str(target), *arguments], cwd=work, capture_output=True,
                               text=True, encoding="utf-8", errors="replace", timeout=30,
                               check=False)
    files = sorted(item.relative_to(work).as_posix() for item in work.rglob("*") if item.is_file())
    return {
        'arguments': arguments,
        'exit_code': completed.returncode,
        'status': format(completed.returncode & 0xFFFFFFFF, '08X'),
        'crashed': (completed.returncode & 0xFFFFFFFF) in STATUS_CRASH,
        'stdout': completed.stdout.strip()[:400],
        'stderr': completed.stderr.strip()[:400],
        'files': files,
        'work': str(work.relative_to(ROOT)),
    }


def check(name: str, record: dict, expect: dict) -> dict:
    results = {}
    for key, value in expect.items():
        if key == 'exit':
            results['exit_code'] = record['exit_code'] == value
        elif key == 'crash':
            results['crashed'] = record['crashed'] is value
        elif key == 'present':
            results['present:' + value] = value in record['files']
        elif key == 'absent':
            results['absent:' + value] = value not in record['files']
        elif key == 'stdout_has':
            results['stdout:' + value] = value in record['stdout']
        elif key == 'not_exit':
            results['not_exit_' + str(value)] = record['exit_code'] != value
    return {'name': name, 'expectation': expect, 'checks': results,
            'passed': all(results.values()), 'observation': record}


def verify(batch: Path) -> dict:
    targets = {item['id']: batch / f"targets/{item['id']}/1.0.0/{item['name']}.exe"
               for item in json.loads((batch / 'catalog.json').read_text(encoding='utf-8'))}
    scratch = batch / 'vulnerability-verification'
    # Every case starts from an empty tree: the targets refuse to overwrite an
    # existing file, so a leftover artifact from an earlier run would read as a
    # failed import instead of a clean control.
    for target_id in targets:
        shutil.rmtree(scratch / target_id, ignore_errors=True)
    cases: list[dict] = []

    def add(target_id: str, name: str, arguments: list[str], fixtures: dict[str, str],
            expect: dict, subdir: str = '') -> None:
        binary = targets[target_id]
        work = scratch / target_id / (subdir or name)
        record = run(binary, arguments, work, dict(fixtures))
        result = check(name, record, expect)
        result['id'] = target_id
        result['target_sha256'] = __import__('hashlib').sha256(binary.read_bytes()).hexdigest()
        cases.append(result)
        print(f"{target_id} {name:<24s} exit={record['exit_code']:<12d} passed={result['passed']}",
              flush=True)

    # P1: the inbox is meant to be flat; the defect joins ENTRY_NAME verbatim.
    payload = {'payload.txt': 'parcel'}
    add('P1', 'control', ['inbox', 'payload.txt', 'payload.txt'], payload,
        {'exit': 0, 'present': 'inbox/payload.txt', 'absent': 'escaped.txt'})
    add('P1', 'exploit', ['inbox', '..\\escaped.txt', 'payload.txt'], payload,
        {'exit': 0, 'present': 'escaped.txt'})
    deep = scratch / 'P1' / 'deep' / 'work'
    record = run(targets['P1'], ['inbox', '..\\..\\deep-escape.txt', 'payload.txt'],
                 deep, dict(payload))
    # cwd = <scratch>/P1/deep/work, so inbox/../../ lands in <scratch>/P1/deep.
    escaped = scratch / 'P1' / 'deep' / 'deep-escape.txt'
    cases.append({'id': 'P1', 'name': 'exploit-two-levels',
                  'passed': record['exit_code'] == 0 and escaped.is_file(),
                  'observation': record | {'escaped_outside_work': str(escaped.relative_to(ROOT))},
                  'expectation': {'exit': 0, 'outside_work_file': 'deep/deep-escape.txt'}})
    print('P1 exploit-two-levels       passed=' +
          str(cases[-1]['passed']) + ' escaped=' + str(escaped.is_file()), flush=True)

    # P2: the record label is written from a length byte into a 32-byte window.
    windows = {'record.rv': 'RV1' + ' ' + 'A' * 32, 'long.rv': 'RV1' + '`' + 'B' * 96,
               'edge.rv': 'RV1' + '!' + 'C' * 33}
    add('P2', 'control-32-bytes', ['record.rv'], windows, {'exit': 0, 'stdout_has': 'AAAA'})
    add('P2', 'exploit-96-bytes', ['long.rv'], windows, {'crash': True})
    add('P2', 'boundary-33-bytes', ['edge.rv'], windows, {'crash': True})

    # O1: the export decides with the caller-supplied role, not the stored one.
    account = {'account.txt': 'alice|secret|guest', 'record.txt': 'ledger-entry'}
    add('O1', 'control-status', ['account.txt', 'alice', 'secret', 'guest', 'status',
                                 'record.txt', 'exported.txt'], account,
        {'exit': 0, 'absent': 'exported.txt'})
    add('O1', 'control-stored-role-denied', ['account.txt', 'alice', 'secret', 'guest', 'export',
                                             'record.txt', 'exported.txt'], account,
        {'absent': 'exported.txt'})
    add('O1', 'control-wrong-password', ['account.txt', 'alice', 'wrong', 'admin', 'export',
                                         'record.txt', 'exported.txt'], account,
        {'absent': 'exported.txt'})
    add('O1', 'exploit-forged-role', ['account.txt', 'alice', 'secret', 'admin', 'export',
                                      'record.txt', 'exported.txt'], account,
        {'exit': 0, 'present': 'exported.txt', 'stdout_has': 'Record exported'})

    # O2: the document name reaches cmd.exe unfiltered.
    documents = {'doc.txt': 'report-body',
                 'doc.txt & copy doc.txt injected.txt': 'report-body'}
    add('O2', 'control', ['doc.txt'], documents,
        {'exit': 0, 'present': 'relay.txt', 'absent': 'injected.txt'})
    add('O2', 'exploit-injected-copy', ['doc.txt & copy doc.txt injected.txt'], documents,
        {'exit': 0, 'present': 'injected.txt'})
    add('O2', 'exploit-arbitrary-command', ['doc.txt & copy /y doc.txt arbitrary.txt'], documents,
        {'exit': 0, 'present': 'arbitrary.txt'})

    # A UPX-packed image hides most of its import table, so the static check uses
    # the same recovered image the audit analysed (the UPX-unpacked copy for the
    # packed pair). The obfuscated pair only encodes strings, so its import table
    # is still readable in the shipped file.
    imports = {
        'P1': {'image': 'reference/P1/1.0.0/unpacked.exe',
               'symbols': import_probe(batch / 'reference/P1/1.0.0/unpacked.exe',
                                       ['CopyFileW', 'CreateDirectoryW', 'GetFileAttributesW'])},
        'P2': {'image': 'reference/P2/1.0.0/unpacked.exe',
               'symbols': import_probe(batch / 'reference/P2/1.0.0/unpacked.exe',
                                       ['VirtualAlloc', 'VirtualFree', 'GetSystemInfo'])},
        'O1': {'image': 'targets/O1/1.0.0/PermitLedger.exe',
               'symbols': import_probe(targets['O1'],
                                       ['lstrcmpA', 'CopyFileW', 'GetCurrentProcessId'])},
        'O2': {'image': 'targets/O2/1.0.0/TextRelay.exe',
               'symbols': import_probe(targets['O2'],
                                       ['CreateProcessW', 'GetSystemDirectoryW', 'GetCommandLineW'])},
    }
    decoded = {
        'O1': {'image': 'reference/O1/1.0.0/reference.exe',
               'symbols': import_probe(batch / 'reference/O1/1.0.0/reference.exe', ['admin'])},
        'O2': {'image': 'reference/O2/1.0.0/reference.exe',
               'symbols': import_probe(batch / 'reference/O2/1.0.0/reference.exe',
                                       ['cmd.exe /d /c type '])},
    }
    for target_id, extra in decoded.items():
        imports[target_id]['decoded_reference'] = extra
    document = {
        'schema_version': 1,
        'batch': batch.name,
        'verified_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'platform': 'windows/x64',
        'scope': 'VULNERABILITY_PRESENCE',
        'method': 'Negative control, exploit input and boundary probe executed against the frozen binary; import table read statically.',
        'targets': {key: str(value.relative_to(ROOT)) for key, value in targets.items()},
        'cases': cases,
        'imports': imports,
        'imports_note': 'Symbols are read from the image the audit analysed: the UPX-unpacked copy for the packed pair, the shipped file for the obfuscated pair. decoded_reference shows that the same literal is plaintext before obfuscation.',
        'passed': all(item['passed'] for item in cases),
    }
    return document


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--batch', default='protected-tools-20260911-r3')
    parser.add_argument('--output', type=Path)
    options = parser.parse_args()
    if Path(options.batch).name != options.batch:
        parser.error('--batch must be a single directory name')
    batch = ROOT / '.data/verification/protected-tools' / options.batch
    if not batch.is_dir():
        parser.error('batch not found: ' + str(batch))
    document = verify(batch)
    output = options.output or (batch / 'vulnerability-verification.json')
    output.write_text(json.dumps(document, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    failed = [item['id'] + '/' + item['name'] for item in document['cases'] if not item['passed']]
    print(json.dumps({'passed': document['passed'], 'failed': failed, 'evidence': str(output)},
                     ensure_ascii=False))
    return 0 if document['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
