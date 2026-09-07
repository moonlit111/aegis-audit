#!/usr/bin/env python3
"""Verify Ghidra's own analysis deadline with a generated benign PE fixture."""
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
from aegis import ROOT, environment


def main():
    env = environment()
    sdk = Path(env['GHIDRA_HOME'])
    sysroot = Path(subprocess.check_output(['rustc', '--print', 'sysroot'], env=env, text=True).strip())
    version = subprocess.check_output(['rustc', '-vV'], env=env, text=True)
    host = next(line[6:] for line in version.splitlines() if line.startswith('host: '))
    linker = sysroot / 'lib/rustlib' / host / 'bin' / ('rust-lld.exe' if os.name == 'nt' else 'rust-lld')
    if __import__('sys').platform == 'darwin': env['DYLD_LIBRARY_PATH'] = str(sysroot / 'lib')
    output = ROOT / '.data/verification'
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='aegis-timeout-check-') as temporary:
        work = Path(temporary)
        source = work / 'many.c'
        source.write_text('\n'.join('int f%d(int x) { if(x > %d) return x + %d; return x - 1; }' % (i, i, i) for i in range(3000)) + '\nvoid entry(void) { volatile int x=f0(2)+f2999(3); for (;;) x++; }\n')
        subprocess.run(['clang', '--target=x86_64-pc-windows-msvc', '-O0', '-fno-stack-protector', '-c', str(source), '-o', str(work / 'many.obj')], env=env, check=True)
        subprocess.run([str(linker), '-flavor', 'link', '/entry:entry', '/subsystem:console', '/nodefaultlib', '/out:' + str(work / 'many.exe'), str(work / 'many.obj')], env=env, check=True)
        project = work / 'projects'
        project.mkdir()
        result = work / 'result.json'
        command = [str(sdk / 'support' / ('analyzeHeadless.bat' if os.name == 'nt' else 'analyzeHeadless')), str(project), 'timeout-check', '-import', str(work / 'many.exe'), '-analysisTimeoutPerFile', '1', '-max-cpu', '2', '-scriptPath', str(ROOT / 'tools/ghidra'), '-postScript', 'ExportProgram.java', str(result), 'many.exe', '-deleteProject']
        env['MAXMEM'] = '2G'
        flags = {'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == 'nt' else {'start_new_session': True}
        with (output / 'ghidra-timeout.log').open('w') as log:
            process = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT, **flags)
            try:
                code = process.wait(timeout=180)
            except subprocess.TimeoutExpired:
                if os.name == 'nt': subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'], check=True)
                else: os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                raise
        assert code == 0 and result.is_file(), 'Headless export failed; inspect ghidra-timeout.log'
        record = json.loads(result.read_text(encoding='utf-8'))
        assert record['metadata']['analysis_timed_out'] is True, 'Fixture did not trigger the internal deadline'
        assert record['files'][0]['status'] != 'PARSED'
        evidence = {'timed_out': True, 'status': record['files'][0]['status'], 'functions': len(record['units']), 'warnings': record['warnings'], 'purpose': 'benign tool-lifecycle fixture, not a course vulnerability case'}
        (output / 'ghidra-timeout-evidence.json').write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(evidence, ensure_ascii=False))


if __name__ == '__main__':
    main()
