#!/usr/bin/env python3
"""Reproduce CVE-2016-5180 in c-ares with LLVM libFuzzer and ASan."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SOURCE = ROOT / '.data/references/dynamic-reuse-20260910/c-ares-CVE-2016-5180'
DEFAULT_PATCH = ROOT / '.data/references/dynamic-reuse-20260910/CVE-2016-5180.patch'
DEFAULT_LLVM = ROOT / '.tools/llvm-min'
DEFAULT_OUTPUT = ROOT / '.data/verification/windows-fuzz'
SEED = b'a\\.'


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    os.replace(temporary, path)


def run(command: list[str], cwd: Path, env: dict[str, str], timeout: int = 120) -> dict:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
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


def c_sources(makefile: Path) -> list[str]:
    text = makefile.read_text(encoding='utf-8')
    match = re.search(r'^CSOURCES\s*=\s*(.*?)^HHEADERS', text, re.MULTILINE | re.DOTALL)
    if match is None:
        raise RuntimeError('cannot parse CSOURCES from Makefile.inc')
    sources = re.findall(r'([A-Za-z0-9_./-]+\.c)', match.group(1))
    if not sources or 'ares_create_query.c' not in sources:
        raise RuntimeError('parsed source list is missing ares_create_query.c')
    return sources


def build_environment(llvm: Path) -> dict[str, str]:
    msvc = ROOT / '.tools/msvc/VC/Tools/MSVC/14.51.36231'
    sdk = Path('C:/Program Files (x86)/Windows Kits/10')
    required = [
        msvc / 'include',
        sdk / 'Include/10.0.26100.0/ucrt',
        sdk / 'Include/10.0.26100.0/um',
        sdk / 'Include/10.0.26100.0/shared',
        msvc / 'lib/x64',
        sdk / 'Lib/10.0.26100.0/ucrt/x64',
        sdk / 'Lib/10.0.26100.0/um/x64',
        llvm / 'bin/clang.exe',
        llvm / 'lib/clang/23/lib/windows',
    ]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise RuntimeError('missing build inputs: ' + ', '.join(missing))
    env = os.environ.copy()
    env['INCLUDE'] = ';'.join(str(path) for path in required[:4])
    env['LIB'] = ';'.join(str(path) for path in required[4:7])
    env['PATH'] = str(required[8]) + os.pathsep + env.get('PATH', '')
    return env


def compile_objects(
    source: Path,
    work: Path,
    clang: Path,
    env: dict[str, str],
    sources: list[str],
) -> tuple[list[Path], list[dict]]:
    objects = []
    records = []
    object_dir = work / 'obj'
    object_dir.mkdir(parents=True, exist_ok=True)
    flags = [
        str(clang),
        '-target',
        'x86_64-pc-windows-msvc',
        '-O1',
        '-g',
        '-fsanitize=fuzzer,address',
        '-DWIN32',
        '-DCARES_BUILDING_LIBRARY',
        '-DCARES_STATICLIB',
        '-Wno-deprecated-declarations',
        f'-I{source}',
    ]
    for name in sources:
        obj = object_dir / f'{name}.obj'
        result = run([*flags, '-c', str(source / name), '-o', str(obj)], work, env)
        records.append({'source': name, **result})
        if result['exit_code'] != 0 or not obj.is_file():
            raise RuntimeError(f'compile failed for {name}: {result["stderr"]}')
        objects.append(obj)
    return objects, records


def compile_harness(source: Path, work: Path, clang: Path, env: dict[str, str]) -> Path:
    harness_source = work / 'fuzz_target.c'
    harness_source.write_text(
        '#include <stdint.h>\n'
        '#include <stdlib.h>\n'
        '#include <string.h>\n'
        '#include "ares.h"\n'
        '#include "nameser.h"\n'
        '\n'
        'int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n'
        '  char *name = (char *)malloc(size + 1);\n'
        '  if (!name) return 0;\n'
        '  memcpy(name, data, size);\n'
        '  name[size] = \'\\0\';\n'
        '  unsigned char *buf = NULL;\n'
        '  int buflen = 0;\n'
        '  ares_create_query(name, ns_c_in, ns_t_a, 0x1234, 0, &buf, &buflen, 0);\n'
        '  free(buf);\n'
        '  free(name);\n'
        '  return 0;\n'
        '}\n',
        encoding='ascii',
    )
    harness = work / 'fuzz_target.obj'
    flags = [
        str(clang),
        '-target',
        'x86_64-pc-windows-msvc',
        '-O1',
        '-g',
        '-fsanitize=fuzzer,address',
        '-DWIN32',
        '-DCARES_BUILDING_LIBRARY',
        '-DCARES_STATICLIB',
        f'-I{source}',
        '-c',
        str(harness_source),
        '-o',
        str(harness),
    ]
    result = run(flags, work, env)
    if result['exit_code'] != 0 or not harness.is_file():
        raise RuntimeError(f'harness compile failed: {result["stderr"]}')
    return harness


def link_target(
    work: Path,
    clang: Path,
    env: dict[str, str],
    objects: list[Path],
    harness: Path,
    output: Path,
) -> dict:
    command = [
        str(clang),
        '-target',
        'x86_64-pc-windows-msvc',
        '-fsanitize=fuzzer,address',
        *[str(path) for path in objects],
        str(harness),
        '-o',
        str(output),
        '-lws2_32',
        '-ladvapi32',
    ]
    result = run(command, work, env)
    if result['exit_code'] != 0 or not output.is_file():
        raise RuntimeError(f'link failed: {result["stderr"]}')
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=DEFAULT_SOURCE)
    parser.add_argument('--patch', type=Path, default=DEFAULT_PATCH)
    parser.add_argument('--llvm', type=Path, default=DEFAULT_LLVM)
    parser.add_argument('--output', type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument('--batch', default=time.strftime('c-ares-cve-2016-5180-%Y%m%d-%H%M%S'))
    parser.add_argument('--runs', type=int, default=1000)
    options = parser.parse_args()

    if platform.system() != 'Windows' or platform.machine().lower() not in ('amd64', 'x86_64'):
        print('CVE-2016-5180 reproduction supports Windows x64 only.', file=sys.stderr)
        return 2
    if options.runs < 1:
        print('--runs must be positive.', file=sys.stderr)
        return 2

    source = options.source.resolve()
    patch = options.patch.resolve()
    llvm = options.llvm.resolve()
    clang = llvm / 'bin/clang.exe'
    if not source.is_dir() or not patch.is_file() or not clang.is_file():
        print('c-ares source, CVE patch, or LLVM clang is missing.', file=sys.stderr)
        return 2

    output = (options.output / options.batch).resolve()
    if output.exists() and any(output.iterdir()):
        print(f'Batch directory is not empty: {output}', file=sys.stderr)
        return 2
    output.mkdir(parents=True, exist_ok=True)

    env = build_environment(llvm)
    with tempfile.TemporaryDirectory(prefix='aegis-cares-cve-') as temporary:
        work = Path(temporary)
        source_copy = work / 'c-ares'
        shutil.copytree(source, source_copy)
        build_header = source_copy / 'ares_build.h'
        if not build_header.exists():
            shutil.copy2(source_copy / 'ares_build.h.dist', build_header)

        sources = c_sources(source_copy / 'Makefile.inc')
        objects, compile_records = compile_objects(source_copy, work, clang, env, sources)
        harness = compile_harness(source_copy, work, clang, env)
        vulnerable = work / 'cares-vulnerable.exe'
        vulnerable_link = link_target(work, clang, env, objects, harness, vulnerable)

        patch_result = run(['git', '-C', str(source_copy), 'apply', str(patch)], work, env)
        if patch_result['exit_code'] != 0:
            raise RuntimeError(f'patch failed: {patch_result["stderr"]}')
        patched_object_dir = work / 'patched-obj'
        patched_object_dir.mkdir(parents=True, exist_ok=True)
        patched_object = patched_object_dir / 'ares_create_query.obj'
        patched_compile = run([
            str(clang),
            '-target',
            'x86_64-pc-windows-msvc',
            '-O1',
            '-g',
            '-fsanitize=fuzzer,address',
            '-DWIN32',
            '-DCARES_BUILDING_LIBRARY',
            '-DCARES_STATICLIB',
            '-Wno-deprecated-declarations',
            f'-I{source_copy}',
            '-c',
            str(source_copy / 'ares_create_query.c'),
            '-o',
            str(patched_object),
        ], work, env)
        if patched_compile['exit_code'] != 0 or not patched_object.is_file():
            raise RuntimeError(f'patched compile failed: {patched_compile["stderr"]}')
        patched_objects = [
            patched_object if path.name == 'ares_create_query.c.obj' else path
            for path in objects
        ]
        patched = work / 'cares-patched.exe'
        patched_link = link_target(work, clang, env, patched_objects, harness, patched)

        corpus = work / 'corpus'
        corpus.mkdir()
        seed_path = corpus / 'seed'
        seed_path.write_bytes(SEED)
        fuzz_flags = [
            f'-runs={options.runs}',
            '-max_len=64',
            '-timeout=2',
            '-seed=71413',
            f'-artifact_prefix={work}/',
        ]
        vulnerable_run = run([str(vulnerable), *fuzz_flags, str(corpus)], work, env)
        crash_files = sorted(work.glob('crash-*'))
        if vulnerable_run['exit_code'] == 0 or not crash_files:
            raise RuntimeError('vulnerable build did not produce a libFuzzer crash artifact')
        crash_input = crash_files[0]
        shutil.copy2(crash_input, output / 'crash-input.bin')

        patched_run = run([str(patched), *fuzz_flags, str(corpus)], work, env)
        patched_crash_input_run = run([str(patched), str(crash_input)], work, env)
        if patched_run['exit_code'] != 0 or patched_crash_input_run['exit_code'] != 0:
            raise RuntimeError('patched build still crashed')

        minimized_input = work / 'minimized-input.bin'
        vulnerable_minimize = run([
            str(vulnerable),
            '-minimize_crash=1',
            f'-exact_artifact_path={minimized_input}',
            '-timeout=2',
            '-max_total_time=60',
            str(crash_input),
        ], work, env)
        minimized = minimized_input if minimized_input.is_file() else crash_input
        if minimized == minimized_input:
            shutil.copy2(minimized_input, output / 'minimized-input.bin')
        vulnerable_minimized_replays = [
            run([str(vulnerable), str(minimized)], work, env),
            run([str(vulnerable), str(minimized)], work, env),
        ]
        patched_minimized_run = run([str(patched), str(minimized)], work, env)
        if any(item['exit_code'] == 0 for item in vulnerable_minimized_replays):
            raise RuntimeError('minimized vulnerable input did not reproduce twice')
        if patched_minimized_run['exit_code'] != 0:
            raise RuntimeError('patched build crashed on the minimized input')

        vulnerable_output = vulnerable_run['stdout'] + vulnerable_run['stderr']
        crash_signature = 'heap-buffer-overflow' if 'heap-buffer-overflow' in vulnerable_output else 'unknown'
        summary = {
            'schema_version': 1,
            'task': 'CVE-2016-5180 reproduction',
            'cve': 'CVE-2016-5180',
            'observed_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'platform': 'windows/x64',
            'source': {
                'path': str(source),
                'commit': run(['git', '-C', str(source), 'rev-parse', 'HEAD'], source, env)['stdout'].strip(),
                'patch': str(patch),
                'patch_sha256': digest(patch),
            },
            'build': {
                'clang': run([str(clang), '--version'], work, env)['stdout'].strip(),
                'source_count': len(sources),
                'compile_failures': sum(record['exit_code'] != 0 for record in compile_records),
                'vulnerable_link_exit_code': vulnerable_link['exit_code'],
                'patched_link_exit_code': patched_link['exit_code'],
                'vulnerable_sha256': digest(vulnerable),
                'patched_sha256': digest(patched),
            },
            'fuzz': {
                'engine': 'LLVM libFuzzer',
                'sanitizer': 'AddressSanitizer',
                'seed': SEED.decode('ascii'),
                'seed_sha256': hashlib.sha256(SEED).hexdigest(),
                'runs': options.runs,
                'vulnerable_exit_code': vulnerable_run['exit_code'],
                'patched_exit_code': patched_run['exit_code'],
                'patched_crash_input_exit_code': patched_crash_input_run['exit_code'],
                'crash_signature': crash_signature,
                'crash_input_sha256': digest(crash_input),
                'minimize_exit_code': vulnerable_minimize['exit_code'],
                'minimized': minimized == minimized_input,
                'minimized_sha256': digest(minimized),
                'minimized_replay_exit_codes': [
                    item['exit_code'] for item in vulnerable_minimized_replays
                ],
                'patched_minimized_exit_code': patched_minimized_run['exit_code'],
            },
            'result': 'REPRODUCED' if crash_signature == 'heap-buffer-overflow' else 'UNEXPECTED_CRASH',
            'limits': [
                'This is a pinned local reproduction of a public historical CVE.',
                'The seed directly reaches the vulnerable escaped-dot path; it is not a blind discovery benchmark.',
                'The patched control uses the upstream CVE patch and the same harness.',
            ],
        }
        write_json(output / 'summary.json', summary)
        write_json(output / 'build.json', {
            'compile': compile_records,
            'vulnerable_link': vulnerable_link,
            'patched_compile': patched_compile,
            'patched_link': patched_link,
        })
        (output / 'vulnerable-stdout.log').write_text(vulnerable_run['stdout'], encoding='utf-8')
        (output / 'vulnerable-stderr.log').write_text(vulnerable_run['stderr'], encoding='utf-8')
        (output / 'patched-stdout.log').write_text(patched_run['stdout'], encoding='utf-8')
        (output / 'patched-stderr.log').write_text(patched_run['stderr'], encoding='utf-8')
        (output / 'minimize-stdout.log').write_text(vulnerable_minimize['stdout'], encoding='utf-8')
        (output / 'minimize-stderr.log').write_text(vulnerable_minimize['stderr'], encoding='utf-8')
        print(f"CVE-2016-5180 status: {summary['result']}")
        print(f"Evidence: {output / 'summary.json'}")
        return 0 if summary['result'] == 'REPRODUCED' else 1


if __name__ == '__main__':
    raise SystemExit(main())
