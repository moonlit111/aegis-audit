#!/usr/bin/env python3
"""B06 evidence: recover constant-XOR strings from a fixture with real Ghidra P-code.

Requires the pinned Ghidra (py -3 scripts/bootstrap.py --runtime-only). The
fixture is a self-made mechanism case, explicitly not a course acceptance object.

Usage: py -3 scripts/check_deobfuscation.py [--batch first-round-20260909]
"""
from pathlib import Path
import argparse
import json
import subprocess
import tempfile
from aegis import ROOT, environment

parser = argparse.ArgumentParser()
parser.add_argument('--batch', default='first-round-20260909')
options = parser.parse_args()

env = environment()
sdk = Path(env['GHIDRA_HOME'])
fixture = ROOT / 'tests/fixtures/deobfuscation/obfuscated.exe'
manifest = json.loads((fixture.parent / 'manifest.json').read_text(encoding='utf-8'))

with tempfile.TemporaryDirectory(prefix='aegis-deobf-') as temporary:
    work = Path(temporary)
    project = work / 'project'
    project.mkdir()
    result = work / 'result.json'
    command = [
        str(sdk / 'support/analyzeHeadless.bat'), str(project), 'deobfuscation',
        '-import', str(fixture),
        '-scriptPath', str(ROOT / 'tools/ghidra'),
        '-postScript', 'ExportProgram.java', str(result), 'obfuscated.exe',
        '-deleteProject', '-analysisTimeoutPerFile', '120', '-max-cpu', '2',
    ]
    env['MAXMEM'] = '2G'
    flags = {'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP}
    log_path = ROOT / '.data/verification/windows-deobfuscation' / options.batch
    log_path.mkdir(parents=True, exist_ok=True)
    with (log_path / 'ghidra-export.log').open('w') as log:
        process = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT, **flags)
        code = process.wait(timeout=900)
    if code != 0 or not result.is_file():
        raise SystemExit('Ghidra export failed; inspect ghidra-export.log')

    record = json.loads(result.read_text(encoding='utf-8'))
    recovered = record.get('deobfuscation', [])
    expected = manifest['expected']
    match = next(
        (item for item in recovered
         if item.get('key') == expected['xor_key']
         and expected['xor_plaintext_contains'] in item.get('text', '')),
        None,
    )
    if match is None:
        raise SystemExit('Ghidra did not recover the expected constant-XOR string; raw result retained')

    evidence = {
        'task': 'B06',
        'batch': options.batch,
        'purpose': '真实 Ghidra P-code 识别常量 XOR 解码模式并恢复字符串；自制机制夹具，不是正式对象',
        'environment': {
            'ghidra': record['metadata']['ghidra_version'],
            'platform': 'Windows x64 原生；未执行目标',
        },
        'fixture': manifest['fixtures'][0],
        'recovered': match,
        'recovered_count': len(recovered),
        'target_executed': False,
        'limits': [
            '只恢复指令/P-code 中可见的常量 XOR 解码；运行期密钥与代码级混淆未处理',
            '窗口/长度上限内取证，不重建可执行映像',
            '自制夹具只证明机制，不能代替正式混淆对象',
        ],
    }
    (log_path / 'deobfuscation-evidence.json').write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'ghidra': evidence['environment']['ghidra'],
                      'recovered': len(recovered),
                      'key': match['key'], 'address': match['data_address'],
                      'text': match['text'][:80]}, ensure_ascii=False))
