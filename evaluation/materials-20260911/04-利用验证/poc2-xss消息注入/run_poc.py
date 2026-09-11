#!/usr/bin/env python3
"""PoC：FastChat gradio_patch 的聊天消息 HTML 注入 → XSS（对照池 p03）。

组件级验证（component-level）：
- 执行的是源码**原样**的 Chatbot.postprocess / _process_chat_messages
  （01-源码对照/p03-fastchat-xss/vulnerable-gradio_patch.py 与 fixed-...py）；
- gradio 的组件基类用桩替身（只提供 postprocess 用到的属性与父类方法），
  markdown2 与 nh3 是真实依赖；
- 浏览器执行证明：把 postprocess 的输出放进页面，用 Chrome 无头模式真实渲染，
  看注入的 onerror 是否执行（读 document.title）。

覆盖三个用例：
  A. 用户消息注入（漏洞版裸拼 <pre>，修复版 nh3.clean）
  B. 助手消息注入（修复是否完整——修复只动了用户侧）
  C. 非字符串消息（修复引入的分支行为）

用法：.venv/Scripts/python.exe poc2-xss消息注入/run_poc.py
"""
import importlib.util
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
MATERIALS = HERE.parent.parent
PAIR = MATERIALS / '01-源码对照' / 'p03-fastchat-xss'
BUILD = HERE / 'build'
EVIDENCE = HERE / 'evidence'

VARIANTS = {
    'vuln': PAIR / 'vulnerable-gradio_patch.py',
    'fixed': PAIR / 'fixed-gradio_patch.py',
}

USER_PAYLOAD = '<img src=x onerror="document.title=\'XSS-USER\'">'
ASSISTANT_PAYLOAD = '<img src=x onerror="document.title=\'XSS-ASSISTANT\'">'

CHROME = r'C:\Program Files\Google\Chrome\Application\chrome.exe'

GRADIO_STUB = '''"""gradio 组件基类桩：只满足本文件用到的名字，不参与被验证的逻辑。"""
import warnings
from enum import Enum
from typing import Any, Callable, Dict, List, Literal, Optional, Tuple, Union  # noqa: F401


def document(*args, **kwargs):
    def wrapper(cls):
        return cls
    return wrapper


class Component:
    def __init__(self, **kwargs):
        self._style = {}

    def style(self, **kwargs):
        return self


class IOComponent(Component):
    def __init__(self, **kwargs):
        self.value = kwargs.pop('value', None)
        super().__init__(**kwargs)

    def get_config(self):
        return {}


class Changeable:
    pass


class Selectable:
    pass


class JSONSerializable:
    pass


class EventListenerMethod:
    pass


class _ProcessingUtils:
    @staticmethod
    def get_mimetype(path):
        return 'application/octet-stream'


processing_utils = _ProcessingUtils()
'''


def build_shim():
    root = BUILD / 'gradio_shim'
    package = root / 'gradio'
    shutil.rmtree(root, ignore_errors=True)
    package.mkdir(parents=True)
    (package / '__init__.py').write_text('', encoding='utf-8')
    (package / 'components.py').write_text(GRADIO_STUB, encoding='utf-8')
    return root


def load_module(variant, shim_root):
    sys.path.insert(0, str(shim_root))
    spec = importlib.util.spec_from_file_location(f'gradio_patch_{variant}', VARIANTS[variant])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def browser_title(page):
    profile = tempfile.mkdtemp(prefix='poc2_chrome_')
    try:
        result = subprocess.run(
            [CHROME, '--headless=new', '--disable-gpu', '--no-first-run',
             f'--user-data-dir={profile}', '--virtual-time-budget=3000',
             '--dump-dom', page.as_uri()],
            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=60)
        match = re.search(r'<title>(.*?)</title>', result.stdout or '', re.S)
        return match.group(1).strip() if match else '(未取到 title)'
    except Exception as error:
        return f'(浏览器执行失败: {type(error).__name__})'
    finally:
        shutil.rmtree(profile, ignore_errors=True)


def page_for(cell_html, path):
    path.write_text(
        '<!doctype html><html><head><meta charset="utf-8"><title>BEFORE</title></head>'
        f'<body><div id="chat">{cell_html}</div></body></html>',
        encoding='utf-8')


def main():
    EVIDENCE.mkdir(exist_ok=True)
    shim_root = build_shim()
    lines = []
    for variant in ('vuln', 'fixed'):
        module = load_module(variant, shim_root)
        bot = module.Chatbot()
        user_cell, assistant_cell = bot.postprocess([(USER_PAYLOAD, ASSISTANT_PAYLOAD)])[0]

        lines.append(f'== {variant} 版本')
        lines.append(f'  A 用户消息输出: {user_cell}')
        lines.append(f'  B 助手消息输出: {assistant_cell}')

        if variant == 'vuln':
            shutil.copy2(VARIANTS[variant], EVIDENCE / 'gradio_patch.py')
        # 浏览器执行证明：每个用例单独一页
        cases = {'user': user_cell, 'assistant': assistant_cell}
        for name, cell in cases.items():
            page = EVIDENCE / f'{variant}_{name}.html'
            page_for(cell, page)
            title = browser_title(page)
            fired = title in ('XSS-USER', 'XSS-ASSISTANT')
            lines.append(f'  {name} 页面浏览器标题: {title!r} -> {"脚本已执行(注入成功)" if fired else "未执行(被拦截/无注入)"}')

        try:
            bot.postprocess([({'role': 'user', 'content': 'x'}, 'ok')])
            lines.append('  C 非字符串消息: 未抛异常')
        except Exception as error:
            lines.append(f'  C 非字符串消息: 抛 {type(error).__name__}: {str(error)[:90]}')

    (EVIDENCE / '结论.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print('\n'.join(lines))
    print(f'\n证据已写入 {EVIDENCE}')


if __name__ == '__main__':
    main()
