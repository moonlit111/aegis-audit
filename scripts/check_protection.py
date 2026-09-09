#!/usr/bin/env python3
"""B05 evidence: run the real UPX processing chain and archive its records.

Requires a real UPX (AEGIS_UPX or PATH). The fixture is a self-made mechanism
case, explicitly not a course acceptance object.

Usage: py -3 scripts/check_protection.py [--batch first-round-20260909]
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
from aegis import ROOT, environment, resolve_command

parser = argparse.ArgumentParser()
parser.add_argument('--batch', default='first-round-20260909')
options = parser.parse_args()

env = environment()
upx = os.environ.get('AEGIS_UPX') or shutil.which('upx', path=env.get('PATH', ''))
if not upx:
    raise SystemExit('UPX not found: set AEGIS_UPX or add upx to PATH; no records written')
upx_version = subprocess.check_output([upx, '--version'], text=True).splitlines()[0].strip()
rustc_version = subprocess.check_output(
    resolve_command(['rustc', '-vV'], env), env=env, text=True).splitlines()[0]

fixture_dir = ROOT / 'tests/fixtures/protection'
manifest = json.loads((fixture_dir / 'manifest.json').read_text(encoding='utf-8'))
command = ['cargo', 'test', '-p', 'aegis-application', '--lib', '--locked',
           'native_upx', '--', '--ignored', '--test-threads=1', '--nocapture']
env['AEGIS_UPX'] = upx
result = subprocess.run(resolve_command(command, env), cwd=ROOT, env=env,
                        capture_output=True, encoding='utf-8', errors='replace')
output = result.stdout + result.stderr
records = [json.loads(line.split('PROTECTION_EVIDENCE ', 1)[1])
           for line in output.splitlines() if 'PROTECTION_EVIDENCE ' in line]

out_dir = ROOT / '.data/verification/windows-protection' / options.batch
out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / 'processing-records.json').write_text(
    json.dumps(records, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
summary = {
    'task': 'B05',
    'batch': options.batch,
    'purpose': '真实 UPX 处理链的去壳、原件保护、前后映射与失败记录',
    'fixture_status': '自制机制夹具；不能代替正式闭源加壳对象',
    'environment': {
        'upx': upx_version,
        'rustc': rustc_version,
        'platform': 'Windows x64 原生；未使用 Docker/WSL',
    },
    'command': ' '.join(command),
    'exit_code': result.returncode,
    'records': len(records),
    'states': {state: sum(1 for record in records if record.get('state') == state)
               for state in sorted({record.get('state') for record in records})},
    'fixture_manifest': manifest,
    'target_executed': any(record.get('target_executed') for record in records),
    'limits': [
        '只处理允许清单内的工具与固定参数；不执行目标本身',
        'UPX 恢复映像与加壳前字节流不保证逐字节相同，映射为节区/入口级',
        '未覆盖运行时装壳自解压、反调试与动态解混淆',
    ],
}
(out_dir / 'summary.json').write_text(
    json.dumps(summary, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
print(json.dumps({'exit_code': result.returncode, 'records': len(records),
                  'states': summary['states'], 'evidence': str(out_dir)}, ensure_ascii=False))
raise SystemExit(result.returncode)
