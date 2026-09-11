#!/usr/bin/env python3
"""一键复现：依次运行 p01 / p03 / Go 四目标的组件级 PoC，并汇总结果。

用法（任选其一）：
    .venv/Scripts/python.exe -X utf8 run_all.py          # 直接跑
    run_all.cmd                                          # 双击/命令行（ASCII 包装）
"""
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PY = HERE / '.venv' / 'Scripts' / 'python.exe'

STEPS = [
    ('p01  Jinja2 模板注入 -> 任意代码执行（CVE-2024-34359 修复点）',
     HERE / 'poc1-jinja模板注入' / 'run_poc.py'),
    ('p03  消息 HTML 注入 -> 跨用户 XSS（含 Chrome 无头浏览器执行证明）',
     HERE / 'poc2-xss消息注入' / 'run_poc.py'),
    ('Go 四目标 p06/p07/p08/p09（越界 panic / 路径逃逸 / 缺校验 / 数据竞争）',
     HERE / 'poc3-go复现' / 'run_all.py'),
]


def main():
    if not PY.is_file():
        raise SystemExit(f'缺少 Python 环境：{PY}\n见 复现操作说明.md 第 0 节。')
    env = {**os.environ, 'PYTHONUTF8': '1'}
    failed = []
    for title, script in STEPS:
        print('=' * 64)
        print(f'== {title}')
        print('=' * 64, flush=True)
        result = subprocess.run([str(PY), '-X', 'utf8', str(script)],
                                cwd=script.parent, env=env)
        if result.returncode != 0:
            failed.append(title.split()[0])
        print()
    print('=' * 64)
    if failed:
        print('完成（以下步骤返回非零，见其 evidence 输出）：' + '、'.join(failed))
    else:
        print('全部步骤完成。原始证据在各 PoC 目录的 evidence/ 下。')
    print('=' * 64)
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
