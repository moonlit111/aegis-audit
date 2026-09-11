#!/usr/bin/env python3
"""跑四个 Go 组件级复现（p06/p07/p08/p09），输出收集到各自 evidence/ 目录。

Go 工具链：D:/kechngsheji/tools/go/bin/go.exe（离线运行：不拉取任何外部模块）。
"""
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
GO = Path(r'D:/kechngsheji/tools/go/bin/go.exe')

ENV = {
    **os.environ,
    'GOTOOLCHAIN': 'local',          # 禁止自动下载工具链
    'GOPROXY': 'off',                # 离线：只用 stdlib + 本地 replace
    'GOFLAGS': '-mod=mod',
    'GOCACHE': str(HERE / '.gocache'),
    'GOPATH': str(HERE / '.gopath'),
}

TASKS = [
    ('p06-parts-panic', 'vuln', ['test', './server/', '-run', 'TestPrepareMissingContentLength', '-v']),
    ('p06-parts-panic', 'fixed', ['test', './server/', '-run', 'TestPrepareMissingContentLength', '-v']),
    ('p07-realpath', 'vuln', ['run', '.']),
    ('p07-realpath', 'fixed', ['run', '.']),
    ('p08-newnonce', 'only', ['run', '.']),
    ('p09-race', 'vuln', ['test', '-race', '.', '-run', 'TestImageEmbedRace', '-v']),
    ('p09-race', 'fixed', ['test', '-race', '.', '-run', 'TestImageEmbedRace', '-v']),
]


def main():
    if not GO.is_file():
        raise SystemExit(f'Go 工具链不存在：{GO}')
    summary = []
    for poc, variant, args in TASKS:
        root = HERE / poc if variant == 'only' else HERE / poc / variant
        evidence = HERE / poc / 'evidence'
        evidence.mkdir(parents=True, exist_ok=True)
        label = f'{poc}/{variant}'
        print(f'== {label}: go {" ".join(args)}', flush=True)
        result = subprocess.run([str(GO), *args], cwd=root, env=ENV,
                                capture_output=True, text=True, encoding='utf-8', errors='replace',
                                timeout=600)
        output = (result.stdout or '') + (result.stderr or '')
        (evidence / f'{variant}-output.txt').write_text(output, encoding='utf-8')
        highlights = [line for line in output.splitlines()
                      if 'POC_RESULT' in line or 'DATA RACE' in line or 'panic' in line.lower()
                      or '判定' in line or '读取成功' in line or '[极端]' in line or '[正常]' in line]
        for line in highlights[:8]:
            print(f'   {line.strip()[:150]}')
        summary.append(f'{label} (exit={result.returncode})\n' + '\n'.join(highlights[:8]))
    (HERE / '结论.txt').write_text('\n\n'.join(summary) + '\n', encoding='utf-8')
    print(f'\n汇总：{HERE / "结论.txt"}')


if __name__ == '__main__':
    main()
