#!/usr/bin/env python3
"""A05: record native Windows fuzzing-engine compatibility without claiming success."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=True, indent=2), encoding='utf-8')
    os.replace(temporary, path)


def run(command: list[str], cwd: Path, timeout: int = 60) -> dict:
    result = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding='utf-8',
        errors='replace',
        timeout=timeout,
        check=False,
    )
    return {
        'command': command,
        'exit_code': result.returncode,
        'stdout': result.stdout,
        'stderr': result.stderr,
    }


def compiler_probe(work: Path, sanitizer: str) -> dict:
    source = work / 'probe.c'
    source.write_text(
        'extern int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size);\n'
        'int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {\n'
        '    (void)data;\n'
        '    (void)size;\n'
        '    return 0;\n'
        '}\n',
        encoding='ascii',
    )
    output = work / f'{sanitizer}-probe.exe'
    result = run([
        'cl',
        '/nologo',
        '/EHsc',
        f'/fsanitize={sanitizer}',
        source.name,
        f'/Fe:{output.name}',
    ], work)
    return {
        'sanitizer': sanitizer,
        'compile': result,
        'artifact_exists': output.is_file(),
        'supported': result['exit_code'] == 0 and output.is_file(),
    }


def llvm_probe(work: Path, sanitizer: str, clang: Path, runtime: Path) -> dict:
    source = work / 'probe.c'
    source.write_text(
        'extern int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size);\n'
        'int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {\n'
        '    (void)data;\n'
        '    (void)size;\n'
        '    return 0;\n'
        '}\n',
        encoding='ascii',
    )
    output = work / f'{sanitizer}-probe.exe'
    compile_result = run([
        str(clang),
        '-O1',
        f'-fsanitize={sanitizer}',
        source.name,
        '-o',
        output.name,
    ], work)
    if compile_result['exit_code'] != 0 or not output.is_file():
        return {
            'sanitizer': sanitizer,
            'compile': compile_result,
            'run': None,
            'supported': False,
        }
    environment = os.environ.copy()
    environment['PATH'] = str(runtime) + os.pathsep + environment.get('PATH', '')
    execution = subprocess.run(
        [str(output), '-runs=1'],
        cwd=work,
        capture_output=True,
        text=True,
        encoding='utf-8',
        errors='replace',
        timeout=60,
        check=False,
        env=environment,
    )
    run_result = {
        'command': [str(output), '-runs=1'],
        'exit_code': execution.returncode,
        'stdout': execution.stdout,
        'stderr': execution.stderr,
    }
    combined = execution.stdout + execution.stderr
    return {
        'sanitizer': sanitizer,
        'compile': compile_result,
        'run': run_result,
        'supported': execution.returncode == 0 and 'cov:' in combined and 'Done' in combined,
    }


def tinyinst_probe(work: Path, engine: Path, target: Path) -> dict:
    target_copy = work / target.name
    shutil.copy2(target, target_copy)
    coverage = work / 'coverage.txt'
    result = run([
        str(engine),
        '-instrument_module',
        target.name,
        '-coverage_file',
        coverage.name,
        '--',
        f'.\\{target.name}',
    ], work)
    return {
        'engine': 'TinyInst litecov',
        'target': target.name,
        'run': result,
        'coverage_exists': coverage.is_file(),
        'supported': result['exit_code'] == 0 and coverage.is_file(),
    }


def engine_inventory() -> dict:
    engines = {}
    tinyinst = ROOT / '.tools/tinyinst/litecov.exe'
    for name, path in [
        ('WinAFL', shutil.which('WinAFL')),
        ('afl-fuzz', shutil.which('afl-fuzz')),
        ('TinyInst', str(tinyinst) if tinyinst.is_file() else None),
        ('Jackalope', shutil.which('Jackalope')),
    ]:
        engines[name] = {
            'available': path is not None,
            'path': path,
        }
    return engines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path,
                        default=ROOT / '.data/verification/windows-fuzz')
    parser.add_argument('--batch', default=time.strftime('a05-%Y%m%d-%H%M%S'))
    parser.add_argument('--llvm', type=Path, default=ROOT / '.tools/llvm-min')
    args = parser.parse_args()

    if platform.system() != 'Windows' or platform.machine().lower() not in ('amd64', 'x86_64'):
        print('A05 compatibility check supports Windows x64 only.', file=sys.stderr)
        return 2

    batch = (args.output / args.batch).resolve()
    if batch.exists() and any(batch.iterdir()):
        print(f'Batch directory is not empty: {batch}', file=sys.stderr)
        return 2
    batch.mkdir(parents=True, exist_ok=True)

    cl = shutil.which('cl')
    compiler = {
        'name': 'MSVC cl.exe',
        'path': cl,
        'version': run(['cl'], batch)['stdout'] if cl else '',
    }
    probes = {}
    if cl:
        for sanitizer in ('address', 'fuzzer'):
            probe_work = batch / f'probe-{sanitizer}'
            probe_work.mkdir()
            probes[sanitizer] = compiler_probe(probe_work, sanitizer)
    llvm = args.llvm.resolve() / 'bin/clang.exe'
    llvm_runtime = args.llvm.resolve() / 'lib/clang/23/lib/windows'
    llvm_probes = {}
    if llvm.is_file():
        for sanitizer in ('fuzzer', 'fuzzer,address'):
            probe_work = batch / f'llvm-{sanitizer.replace(",", "-")}'
            probe_work.mkdir()
            llvm_probes[sanitizer] = llvm_probe(probe_work, sanitizer, llvm, llvm_runtime)
    engines = engine_inventory()
    tinyinst = ROOT / '.tools/tinyinst/litecov.exe'
    tinyinst_result = None
    if tinyinst.is_file():
        tinyinst_work = batch / 'tinyinst'
        tinyinst_work.mkdir()
        tinyinst_result = tinyinst_probe(
            tinyinst_work,
            tinyinst,
            ROOT / 'tests/fixtures/binary/sample-pe64.exe',
        )

    source_ready = all(
        llvm_probes.get(name, {}).get('supported')
        for name in ('fuzzer', 'fuzzer,address')
    )
    pe_engine_ready = tinyinst_result is not None and tinyinst_result['supported']
    summary = {
        'schema_version': 1,
        'observed_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'platform': 'windows/x86_64',
        'compiler': compiler,
        'source_probes': probes,
        'llvm': {
            'path': str(llvm),
            'version': run([str(llvm), '--version'], batch)['stdout'] if llvm.is_file() else '',
            'probes': llvm_probes,
            'compile_location': 'host',
            'execution_location': 'host',
        },
        'engines': engines,
        'tinyinst': tinyinst_result,
        'source_coverage_guided_ready': source_ready,
        'source_engine': 'LLVM libFuzzer' if source_ready else None,
        'source_status': 'READY' if source_ready else 'NOT_READY',
        'closed_source_pe_engine_ready': pe_engine_ready,
        'closed_source_engine': 'TinyInst litecov' if pe_engine_ready else None,
        'closed_source_status': 'READY' if pe_engine_ready else 'NOT_READY',
        'status': 'ENGINE_EXPERIMENT_READY' if source_ready and pe_engine_ready else 'NOT_READY',
        'product_integration': False,
        'conclusion': (
            'Source and closed-source PE engine experiments are ready. Product integration, '
            'in-guest compilation, crash-input preservation, and formal-target execution remain pending.'
        ),
    }
    write_json(batch / 'summary.json', summary)
    print(f"A05 status: {summary['status']}")
    print(f"Evidence: {batch / 'summary.json'}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
