#!/usr/bin/env python3
"""Build the self-authored RecordView CLI and prebuilt libFuzzer demonstration pair."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import time
import zipfile

from aegis import ROOT, require_windows
from check_c_ares_cve import build_environment, digest, run, write_json


SOURCE = ROOT / 'tests/fixtures/runtime/fuzz-demo'


def cli_cases(fixed: bool) -> list[tuple[str, bytes, int]]:
    cases = [
        ('empty', b'', 3),
        ('short-header', b'AEG1|00', 3),
        ('wrong-magic', b'NOPE|00|', 3),
        ('non-decimal', b'AEG1|x5|hello', 3),
        ('wrong-separator', b'AEG1|05:hello', 3),
        ('zero-length', b'AEG1|00|', 0),
        ('maximum-payload', b'AEG1|63|' + b'x' * 63, 0),
        ('destination-limit', b'AEG1|64|' + b'x' * 64, 3),
        ('file-limit', b'x' * 4097, 2),
    ]
    if fixed:
        # Only the fixed CLI is asked to reject truncated payloads here.
        # The product FUZZ run must discover the buggy input from valid seeds.
        cases.extend([('missing-payload', b'AEG1|05|', 3),
                      ('short-payload', b'AEG1|05|hell', 3)])
    return cases


def check_cli(output: Path) -> list[dict]:
    inputs = output / 'checks/inputs'
    inputs.mkdir(parents=True)
    receipts = []
    for fixed, version in ((False, '1.0.0'), (True, '1.0.1')):
        target = output / f'RecordView-{version}.exe'
        for label, data, expected in cli_cases(fixed):
            path = inputs / f'{label}.bin'
            path.write_bytes(data)
            receipt = run([str(target), str(path)], output, os.environ.copy(), timeout=20)
            receipts.append({'target': target.name, 'case': label,
                             'expected_exit_code': expected, **receipt})
            write_json(output / 'checks/cli.json', receipts)
            if receipt['exit_code'] != expected or 'AddressSanitizer:' in receipt['stderr']:
                raise RuntimeError(f'{target.name}: CLI boundary check failed: {label}')
            if expected == 0 and not receipt['stdout'].startswith('Accepted:'):
                raise RuntimeError(f'{target.name}: accepted record did not produce output: {label}')
    return receipts


def configuration(name: str) -> dict:
    return {
        'mode': 'FUZZ', 'adapter': 'WINDOWS_LIBFUZZER_PREBUILT', 'path': name,
        'function': '', 'globals': {}, 'fixtures': [],
        'baseline': {'args': [], 'kwargs': {}, 'stdin': ''},
        'probe': {'args': [], 'kwargs': {}, 'stdin': ''},
        'observer': 'SANITIZER', 'marker_path': '', 'repeats': 2, 'timeout_seconds': 3,
        'fuzz': {'engine': 'LLVM_LIBFUZZER', 'input_mode': 'FILE',
                 'seeds': ['AEG1|05|hello', 'AEG1|04|demo'],
                 'max_cases': 2000, 'budget_seconds': 15, 'random_seed': 71413},
    }


def build(output: Path, llvm: Path) -> dict:
    require_windows()
    if output.exists():
        raise ValueError('Output already exists; choose a new --batch to preserve previous evidence.')
    env = build_environment(llvm)
    clang = llvm / 'bin/clang.exe'
    runtime = llvm / 'lib/clang/23/lib/windows/clang_rt.asan_dynamic-x86_64.dll'
    if not runtime.is_file():
        raise FileNotFoundError(f'Missing LLVM AddressSanitizer runtime: {runtime}')
    output.mkdir(parents=True)
    shutil.copytree(SOURCE, output / 'source')
    (output / 'corpus').mkdir()
    for name in ('hello.txt', 'demo.txt'):
        # UI seeds are literal UTF-8 bytes, without the text-file line ending.
        (output / 'corpus' / name).write_bytes((SOURCE / name).read_bytes().rstrip(b'\r\n'))
    shutil.copy2(runtime, output / runtime.name)
    summary = {
        'schema_version': 1, 'created_at': datetime.now(timezone.utc).isoformat(),
        'name': 'RecordView', 'purpose': 'SELF_AUTHORED_FUZZ_DEMONSTRATION',
        'formal_acceptance': False, 'target_platform': 'windows/x86_64',
        'format': 'AEG1|NN|TEXT (two decimal length digits; up to 63 payload bytes)',
        'defect': 'CWE-125: declared payload length is not checked against available input bytes',
        'effects': 'ASan-detected out-of-bounds read in a local in-memory parser; no network, shell, or persistence',
        'compiler': run([str(clang), '--version'], ROOT, env)['stdout'].strip(),
        'sources': {path.name: digest(path) for path in SOURCE.iterdir() if path.is_file()},
        'runtime': {'path': runtime.name, 'sha256': digest(runtime),
                    'license': 'Apache-2.0 WITH LLVM-exception', 'source': 'https://llvm.org/'},
        'targets': [], 'commands': [], 'product_verification': 'NOT_RUN',
    }
    for fixed, version in ((False, '1.0.0'), (True, '1.0.1')):
        for fuzz in (False, True):
            name = f'RecordView-{version}{"-fuzz" if fuzz else ""}.exe'
            command = [str(clang), '-target', 'x86_64-pc-windows-msvc', '-std=c11', '-O1', '-g',
                       '-fno-omit-frame-pointer', '-Wall', '-Wextra', '-Werror',
                       '-D_CRT_SECURE_NO_WARNINGS', f'-DAEGIS_RECORD_FIXED={int(fixed)}',
                       '-fsanitize=fuzzer,address' if fuzz else '-fsanitize=address',
                       str(SOURCE / 'record_parser.c'),
                       str(SOURCE / ('record_fuzz.c' if fuzz else 'record_cli.c')),
                       '-o', str(output / name)]
            built = run(command, output, env)
            summary['commands'].append(built)
            write_json(output / 'build.json', summary)
            if built['exit_code'] != 0:
                raise RuntimeError(built['stdout'] + built['stderr'])
            baselines = []
            for seed in sorted((output / 'corpus').iterdir()):
                baseline = run([str(output / name), str(seed)], output, os.environ.copy(), timeout=20)
                if baseline['exit_code'] != 0:
                    raise RuntimeError('Valid baseline failed: ' + baseline['stdout'] + baseline['stderr'])
                baselines.append({'seed': seed.name, **baseline})
            entry = {'path': name, 'version': version, 'fixed': fixed, 'libfuzzer': fuzz,
                     'sha256': digest(output / name), 'bytes': (output / name).stat().st_size,
                     'valid_seed_checks': baselines}
            if fuzz:
                config_path = output / f'{name}.runtime.json'
                write_json(config_path, configuration(name))
                entry['runtime_config'] = config_path.name
            summary['targets'].append(entry)
            write_json(output / 'build.json', summary)
    summary['cli_checks'] = {'status': 'PASSED', 'cases': len(check_cli(output)),
                             'receipt': 'checks/cli.json'}
    readme = [
        '# RecordView: Self-Authored Fuzz Demonstration', '',
        'This is a controlled teaching fixture, not third-party vulnerability research or course acceptance evidence.',
        'The two versions use the same parser. Version 1.0.0 misses a source-length check; 1.0.1 adds it.', '',
        '## Files', '',
        '- RecordView-1.0.0.exe / RecordView-1.0.1.exe: regular file-inspector CLI, also ASan-instrumented.',
        '- RecordView-1.0.0-fuzz.exe / RecordView-1.0.1-fuzz.exe: prebuilt LLVM libFuzzer + ASan targets.',
        '- source/: complete self-authored C source. corpus/: valid starting inputs only.',
        '- *.runtime.json: product configurations. build.json: commands, hashes and baseline receipts.',
        '- checks/: CLI boundary regression inputs and receipts; NOT an initial fuzz corpus.',
        '- clang_rt.asan_dynamic-x86_64.dll: LLVM ASan runtime (Apache-2.0 WITH LLVM-exception).', '',
        '## AegisAudit', '',
        'Import each *-fuzz.exe as a separate binary snapshot, then select the Dynamic Fuzz Testing action.',
        'Use seeds AEG1|05|hello and AEG1|04|demo, 2000 maximum cases, 15 seconds, seed 71413.',
        'The buggy version should produce a reproducible ASan read error; the fixed version rejects truncated records.',
        'Alternatively, open an existing result and choose Configure Fuzz Testing to restore its saved settings.',
        'The product saves deduplicated/minimized inputs and replay receipts; do not substitute a configured budget for measured executions.',
        'Ordinary CLI executables are not libFuzzer targets. Do not UPX-pack the instrumented fuzz targets.', '',
        '## Verify Through the Product', '',
        'From the repository root, while AegisAudit is running:', '',
        '```powershell',
        'py -3 scripts/check_fuzz_demo.py --demo-dir PATH_TO_THIS_DIRECTORY',
        '```', '',
        'This creates a dedicated project and verifies both versions through the real local runtime.',
        'It archives the minimized input, repeated replay receipts, reports and direct configuration/result URLs',
        'under .data/verification/fuzz-demo/. Product evidence is separate from this build-only archive.', '',
        '## Command Line', '',
        'Run from this directory so that the bundled ASan runtime can be found:', '',
        '```powershell',
        '.\\RecordView-1.0.0.exe .\\corpus\\hello.txt',
        'Copy-Item .\\corpus .\\corpus-buggy -Recurse',
        'Copy-Item .\\corpus .\\corpus-fixed -Recurse',
        '.\\RecordView-1.0.0-fuzz.exe -runs=2000 -seed=71413 -max_total_time=15 .\\corpus-buggy',
        '.\\RecordView-1.0.1-fuzz.exe -runs=2000 -seed=71413 -max_total_time=15 .\\corpus-fixed',
        '```', '',
        'The parser only reads a provided local input. It has no network access, command execution or persistence logic.',
        'Windows host execution is not sandbox isolation. A crash demonstrates this fixture defect, not arbitrary code execution.', '',
    ]
    (output / 'README.md').write_text('\n'.join(readme), encoding='ascii')
    summary['build_status'] = 'COMPLETED'
    write_json(output / 'build.json', summary)
    package = output / 'RecordView-fuzz-demo-windows-x64.zip'
    with zipfile.ZipFile(package, 'w', zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(output.rglob('*')):
            if path.is_file() and path != package:
                bundle.write(path, path.relative_to(output))
    summary['package'] = {'path': package.name, 'sha256': digest(package), 'bytes': package.stat().st_size}
    write_json(output / 'build.json', summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--batch', default=time.strftime('recordview-%Y%m%d-%H%M%S'))
    parser.add_argument('--llvm', type=Path, default=ROOT / '.tools/llvm-min')
    args = parser.parse_args()
    if Path(args.batch).name != args.batch or args.batch in ('.', '..'):
        parser.error('--batch must be a single directory name')
    output = (ROOT / '.data/demos' / args.batch).resolve()
    summary = build(output, args.llvm.resolve())
    print(json.dumps({'output': str(output), 'targets': summary['targets'],
                      'package': summary['package'], 'formal_acceptance': False}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
