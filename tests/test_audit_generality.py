"""B09：产品代码不得含项目名/CVE 专用检测分支，也不得读取评测答案。"""
import re
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'scripts'))
from aegis import ROOT

# 产品侧代码。evaluation/、Docs/、tests/ 属于评测与材料侧，允许出现候选软件名。
PRODUCT_ROOTS = ['crates', 'tools/ghidra', 'tools/runtime', 'proto']
SUFFIXES = {'.rs', '.java', '.py', '.proto', '.ts', '.svelte', '.txt'}
SKIP_DIRS = {'generated', 'gen', 'target', 'node_modules', '__pycache__', '.git'}

CVE = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
# 正式/候选对象名称一旦出现在产品判定逻辑里，就是按项目名作弊的迹象。
PROJECT_NAMES = ['winrar', 'foxit', 'teamviewer', 'zoom.us', 'chatglm', 'deepseek-coder']
PROJECT = re.compile('|'.join(re.escape(name) for name in PROJECT_NAMES), re.IGNORECASE)
ANSWER_PATH = re.compile(r'evaluation/(reference|targets|answers)', re.IGNORECASE)


def product_files():
    for root in PRODUCT_ROOTS:
        base = ROOT / root
        if not base.is_dir():
            continue
        for path in sorted(base.rglob('*')):
            if not path.is_file() or path.suffix not in SUFFIXES:
                continue
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            yield path


def scanned_text(path):
    text = path.read_text(encoding='utf-8', errors='replace')
    if path.suffix == '.rs':
        # 本仓库约定 #[cfg(test)] 模块位于文件末尾；测试夹具里的负例字符串不算产品分支。
        marker = text.find('#[cfg(test)]')
        if marker != -1:
            text = text[:marker]
    return text


class GeneralityTests(unittest.TestCase):
    def scan(self, pattern):
        hits = []
        for path in product_files():
            for number, line in enumerate(scanned_text(path).splitlines(), 1):
                if pattern.search(line):
                    hits.append(f'{path.relative_to(ROOT)}:{number}: {line.strip()}')
        return hits

    def test_no_cve_specific_detection(self):
        hits = self.scan(CVE)
        self.assertEqual(hits, [], '产品代码出现 CVE 专用判定：\n' + '\n'.join(hits))

    def test_no_project_name_specific_detection(self):
        hits = self.scan(PROJECT)
        self.assertEqual(hits, [], '产品代码出现项目名专用判定：\n' + '\n'.join(hits))

    def test_product_code_cannot_read_evaluation_answers(self):
        hits = self.scan(ANSWER_PATH)
        self.assertEqual(hits, [], '产品代码引用评测答案路径：\n' + '\n'.join(hits))

    def test_scan_actually_covers_the_audit_engine(self):
        covered = {path.relative_to(ROOT).as_posix() for path in product_files()}
        for expected in ['crates/application/src/audit.rs', 'crates/application/src/sast.rs',
                         'crates/server/src/agents.rs', 'crates/executor/src/jobs.rs',
                         'crates/application/src/prompts/protocol.txt',
                         'crates/application/src/prompts/auditor.txt',
                         'crates/application/src/prompts/reviewer.txt']:
            self.assertIn(expected, covered, '通用性扫描遗漏了审计引擎文件')


if __name__ == '__main__':
    unittest.main()
