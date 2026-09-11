#!/usr/bin/env python3
"""从 Git 历史中挖掘候选“安全修复提交”，生成可复现的 (父提交, 修复提交) 对照池。

定位（诚实契约，勿删）：
- 本工具只产出 CANDIDATE。提交信息关键词与 diff 形状都只是线索，不等于已确认漏洞。
  真正确认属于评测侧：安全公告、补丁说明或人工复核。正式计分前必须复核。
- 每一对 ground truth 都是 {vulnerable: 父提交, fixed: 该提交}。输出带 tier 与
  channels，说明这条是靠什么被选中的，便于评测侧按证据强弱分批使用。
- 只读本地 clone：不修改目标仓库、不执行目标代码、不联网。

用法：
    py -3 scripts/mine_security_commits.py \
        --repo .data/security-pool/repos/llama-cpp-python \
        --out evaluation/reference/security-commit-pool.json \
        --md Docs/安全修复提交扩池调研.md --review 12

    # 大 monorepo（领域词汇与安全术语重叠、DIFF_SECURITY_PATH 精度崩塌）加 --strict
    py -3 scripts/mine_security_commits.py --strict --repo <大仓库> --out <json>
"""
import argparse
from pathlib import Path
import re
import subprocess
import sys
import json

# 需求给出的 8 个核心关键词，以及每一个的匹配质量判断。
# WEAK 的意思是：这些词在日常提交里大量出现于非安全语境（validat→参数校验、
# escape→JSON 转义、auth→author/attention 前缀），必须配合 diff 证据才可用。
CORE_KEYWORDS = {
    'security':   ('HIGH', r'\bsecurity\b'),
    'bypass':     ('HIGH', r'\bbypass'),
    'injection':  ('HIGH', r'\binject'),
    'sanitiz':    ('HIGH', r'\bsanitiz|\bsanitis'),
    'permission': ('HIGH', r'\bpermission'),
    'auth':       ('WEAK', r'\bauth(?!or\b)'),
    'validat':    ('WEAK', r'\bvalidat'),
    'escape':     ('WEAK', r'\bescap'),
}
EXTRA_KEYWORDS = {
    'vuln': ('HIGH', r'\bvuln'),
    'cve': ('HIGH', r'\bcve-\d'),
    'traversal': ('HIGH', r'\btraversal\b'),
    'privilege': ('HIGH', r'\bprivileg'),
    'csrf': ('HIGH', r'\bcsrf\b'),
    'ssrf': ('HIGH', r'\bssrf\b'),
    'xss': ('HIGH', r'\bxss\b'),
    'rce': ('HIGH', r'\brce\b'),
    'unauthoriz': ('HIGH', r'un[- ]?authori[sz]'),
    'insecure': ('HIGH', r'\binsecure\b'),
    'harden': ('HIGH', r'\bharden'),
    'arbitrary-file': ('HIGH', r'arbitrary file'),
    'arbitrary-code': ('HIGH', r'arbitrary code'),
    'buffer-overflow': ('HIGH', r'buffer overflow'),
    'out-of-bounds': ('HIGH', r'out[- ]of[- ]bounds'),
    'off-by-one': ('HIGH', r'off[- ]by[- ]one'),
    'memory-corruption': ('HIGH', r'memory corruption'),
    'use-after-free': ('HIGH', r'use[- ]after[- ]free'),
    'path-traversal': ('HIGH', r'(path|directory) traversal'),
    'overflow': ('WEAK', r'\boverflow'),
    'leak': ('WEAK', r'\bleak'),
    'deserializ': ('WEAK', r'deseriali[sz]'),
    'tamper': ('WEAK', r'\btamper'),
    'spoof': ('WEAK', r'\bspoof'),
}

# 高置信度短语：一旦出现在提交信息里，基本可以直接判定类别。
PHRASES = [
    ('PATH_TRAVERSAL', r'path traversal|directory traversal|arbitrary file '
                       r'(read|write|delete|access)|outside (the )?(root|target|'
                       r'directory)|traverse|\bsafe[_ ]?path\b|\bsafe[_ ]?join\b'),
    ('INJECTION', r'command injection|code injection|injection|arbitrary code '
                  r'execution|shell injection|template injection|unescap|'
                  r'cross-site scripting|\bxss\b|jinja|immutable sandbox|'
                  r'escape .*(argument|param|shell|command|sql|html)'),
    ('AUTHORIZATION', r'unauth(enticated|orized)|permission check|privilege '
                      r'escalation|access control|missing (auth|check)|'
                      r'bypass .*(auth|permission|check)|cors|origin check|'
                      r'credential|api key'),
    ('MEMORY_BOUNDS', r'buffer overflow|out[- ]of[- ]bounds|off[- ]by[- ]one|'
                      r'heap overflow|memory corruption|use[- ]after[- ]free|'
                      r'null pointer|index out of range|bounds check|'
                      r'integer overflow|overflow'),
]
CATEGORY_RULES = [
    ('PATH_TRAVERSAL', [r'path traversal', r'directory traversal', r'\.\./',
                        r'os\.path\.join', r'path\.join', r'realpath', r'abspath',
                        r'normpath', r'commonpath', r'\bbasename\b', r'\bresolve\(',
                        r'send_file', r'symlink', r'filepath\.join', r'safe_join']),
    ('INJECTION', [r'\beval\(', r'\bexec\(', r'os\.system', r'subprocess',
                   r'shell\s*=\s*true', r'pickle\.load', r'yaml\.load',
                   r'command injection', r'code injection', r'format string',
                   r'argv', r'cross-site scripting', r'\bxss\b',
                   r'\bjinja2?\b|immutable sandbox|sandboxedenvironment',
                   r'escape\b|escaping']),
    ('AUTHORIZATION', [r'\bauth(?!or\b)', r'permission', r'\bbearer\b',
                       r'\bcors\b', r'privileg', r'csrf', r'credential',
                       r'api[_-]?key', r'unmask', r'allowlist', r'whitelist',
                       r'\bjwt\b', r'oauth', r'unauthenticated',
                       r'0o666|0o777|0777|chmod',
                       r'file (permission|mode)|insecure (permission|default)']),
    ('MEMORY_BOUNDS', [r'\bmemcpy\b', r'\bmemmove\b', r'\bbuffer\b', r'overflow',
                       r'out[- ]of[- ]bounds', r'\bbounds\b', r'\bstrcpy\b',
                       r'\bstrlen\b', r'\bnbytes\b', r'index out',
                       r'off[- ]by[- ]one', r'\bmalloc\b', r'\brealloc\b']),
]
GUARD_ADD = re.compile(
    r'if\s+not|raise\s|reject|deny|forbid|return\s+(none|nil|null|err)|'
    r'basename|realpath|normpath|commonpath|shlex|escape|sanitiz|validat|'
    r'allowlist|whitelist|compare_digest|is_absolute|hasprefix|startswith|'
    r'\.resolve\(|clip\(|clamp|\bbound', re.I)
DANGER_REMOVE = re.compile(
    r'eval\(|exec\(|os\.system|shell\s*=\s*true|pickle\.load|yaml\.load|'
    r'verify\s*=\s*false|check_hostname\s*=\s*false|chmod\s+777|0\.0\.0\.0|'
    r'allow_origins\s*=\s*\[\s*["\']\*|\.\./\.\.', re.I)
# --strict 口径：DIFF_SECURITY_PATH 通道的强边界原语。GUARD_ADD 里的
# if not / validat / bound / clip / escape 在 agent 类大仓库里是领域词汇
# （上下文注入、token 预算、工具授权），会让生命周期/并发/CI 改动成批进候选；
# 这里只保留真正在做边界处理的写法。
GUARD_STRICT = re.compile(
    r'basename|realpath|normpath|commonpath|shlex|allowlist|whitelist|'
    r'compare_digest|is_absolute|safe[_ ]?join|secure[_ ]?join|'
    r'filepath\.join|path\.join|filepath\.dir|startswith|hasprefix', re.I)
STRICT_MAX_CHANGED_LINES = 40
STRICT_MAX_FILES = 2
FIX_VERB = re.compile(r'fix|patch|guard|sanitiz|escap|deny|restrict|limit|avoid|'
                      r'prevent|harden|reject|forbid|correct|require|enforce|'
                      r'block|add check|validate', re.I)
NOISE = re.compile(r'^\s*(readme|typo|grammar|wording|changelog|badge|screenshot|'
                   r'license|citation|bump|release v|revert|format|lint|style|'
                   r'refactor|benchmark|perf|comment|docstring|docs?\b)', re.I)
TRAILER = re.compile(r'^(co-authored-by|signed-off-by|reviewed-by|tested-by|'
                     r'acked-by|reported-by|fixes|closes|refs|cc):.*$',
                     re.IGNORECASE | re.MULTILINE)
# 放宽限制型改动：方向与"修漏洞"相反，例如移除边界检查、放开 CORS、追加白名单、
# 重试/容错、放宽校验。这类必须排除，否则会把“功能放开”当成安全修复。
LOOSENING = re.compile(
    r'remove\s+.*(check|bound|validat|limit|restrict)|no\s+longer\s+(check|validat)|'
    r'relax|loosen|widen|increase\s+.*(limit|bound)|allow\s+(all|any|more)|'
    r'accept\s+(additional|more|any)|skip\s+(the\s+)?(check|validat)|'
    r'disable\s+(the\s+)?(check|validat|verif)|retry|revert|'
    r'unescape|setescapehtml\(false\)|don\'?t\s+escape|not\s+escape|'
    r'add\s+support|support\s+for|bring\s+back|feature', re.I)
SECURITY_PATH = re.compile(
    r'(^|/)(server|api|route|routes|handler|handlers|middleware|auth|login|session|'
    r'token|permission|acl|util|utils|file|files|path|paths|fs|storage|download|'
    r'upload|template|templates|cmd|command|exec|shell|process|sandbox|zip|tar|'
    r'archive|registry|config|web|http|network|url)(s)?(/|\.|_|-|$)', re.I)
# ADR 反查用的信号：架构决策记录里描述"边界/越权/信任"的措辞。
ADR_SIGNALS = [
    ('TRUST_BOUNDARY', r'trust boundary|confused deputy|untrusted'),
    ('AUTHENTICATION', r'authenticat|\btoken\b|credential|authoriz'),
    ('PERMISSION', r'permission|privileg|\bacl\b|approval'),
    ('SANDBOX', r'sandbox|\bescape\b|confine'),
    ('INJECTION', r'inject|spoof|rebind|\bxss\b|escap(e|ing)\b'),
    ('NETWORK', r'loopback|0\.0\.0\.0|reachab'),
]
CODE_SUFFIX = {'.py', '.go', '.rs', '.c', '.h', '.cc', '.cpp', '.cxx', '.hpp',
               '.js', '.ts', '.tsx', '.jsx', '.java', '.rb', '.php', '.sh', '.ps1'}
DOC_SUFFIX = {'.md', '.rst', '.txt', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.pdf'}
MANIFEST = re.compile(r'(^|/)(requirements[^/]*\.txt|pyproject\.toml|setup\.py|'
                      r'setup\.cfg|Cargo\.(toml|lock)|go\.(mod|sum)|'
                      r'package(-lock)?\.json|Dockerfile|Makefile)$', re.I)
SKIP_PATH = re.compile(r'(^|/)(\.github|docs?|examples?|scripts?|tests?|test|'
                       r'benchmarks?)/', re.I)


def git(repo, args):
    result = subprocess.run(['git', '-C', str(repo)] + args, capture_output=True,
                            text=True, encoding='utf-8', errors='replace')
    if result.returncode != 0:
        raise RuntimeError(f'git {" ".join(args[:3])} failed: {result.stderr.strip()[:300]}')
    return result.stdout


def read_history(repo):
    """一次 git log 拿到全部非合并提交：哈希/父提交/日期/作者/标题/正文 + 改动文件。"""
    raw = git(repo, ['log', '--no-merges', '--date=short', '--name-only',
                     '--format=%x01%H%x1f%P%x1f%ad%x1f%an%x1f%s%x1f%b%x02'])
    commits = []
    for block in raw.split('\x01'):
        block = block.strip('\n')
        if not block:
            continue
        header, _, files_text = block.partition('\x02')
        fields = header.split('\x1f')
        if len(fields) < 5:
            continue
        sha, parents, date, author, subject = fields[:5]
        body = TRAILER.sub('', fields[5] if len(fields) > 5 else '').strip()
        commits.append({
            'sha': sha.strip(), 'parents': parents.split(), 'date': date,
            'author': author, 'subject': subject.strip(), 'body': body,
            'files': [line.strip() for line in files_text.splitlines() if line.strip()],
        })
    return commits


def fetch_batch(repo, shas, extra, chunk=40):
    """批量取 numstat 或 -U0 patch，避免逐提交起进程。

    仓库里可能有 .pdf/.ipynb 之类的 textconv 驱动（例如 DeepSeek-V3 附带论文 PDF），
    所以显式关闭 textconv；单批失败时跳过该批并记录，而不是让整轮挖掘中断。
    """
    output, skipped = {}, []
    for start in range(0, len(shas), chunk):
        batch = shas[start:start + chunk]
        try:
            raw = git(repo, ['-c', 'core.pager=cat', 'show', '--no-color',
                             '--no-textconv'] + extra + ['--format=%x01%H'] + batch)
        except RuntimeError:
            skipped.extend(batch)
            continue
        for block in raw.split('\x01'):
            if block.strip():
                output[block.split('\n', 1)[0].strip()] = block
    return output, skipped


def parse_numstat(block):
    files = ins = dele = 0
    for line in block.splitlines()[1:]:
        parts = line.split('\t')
        if len(parts) == 3 and (parts[0].isdigit() or parts[0] == '-'):
            files += 1
            ins += int(parts[0]) if parts[0].isdigit() else 0
            dele += int(parts[1]) if parts[1].isdigit() else 0
    return {'files_changed': files, 'insertions': ins, 'deletions': dele}


def diff_lines(patch):
    added, removed = [], []
    for line in patch.splitlines():
        if line.startswith('+++') or line.startswith('---') or line.startswith('@@'):
            continue
        if line.startswith('+'):
            added.append(line[1:].strip())
        elif line.startswith('-'):
            removed.append(line[1:].strip())
    return added, removed


def categories_from(text, rules=CATEGORY_RULES):
    lowered = text.lower()
    return [name for name, patterns in rules
            if any(re.search(pattern, lowered) for pattern in patterns)]


def assess(commit, patch, stat, option_keywords, max_changed, max_files, strict=False):
    message = (commit['subject'] + ' ' + commit['body']).strip()
    added, removed = diff_lines(patch)
    guard = [line for line in added if GUARD_ADD.search(line)]
    danger = [line for line in removed if DANGER_REMOVE.search(line)]
    strong = [line for line in guard if GUARD_STRICT.search(line)]
    signal_text = ' '.join(guard + danger)
    changed = stat['insertions'] + stat['deletions']

    highs = [k for k, (tier, pattern) in option_keywords.items()
             if tier == 'HIGH' and re.search(pattern, message, re.I)]
    weaks = [k for k, (tier, pattern) in option_keywords.items()
             if tier == 'WEAK' and re.search(pattern, message, re.I)]
    phrases = [(name, match.group(0)) for name, pattern in PHRASES
               if (match := re.search(pattern, message, re.I))]
    fixy = bool(FIX_VERB.search(commit['subject'])) and not NOISE.search(message)

    code_files = [f for f in commit['files'] if Path(f).suffix.lower() in CODE_SUFFIX]
    docs_only = bool(commit['files']) and not code_files
    in_skipped_tree = bool(code_files) and all(SKIP_PATH.search(f) for f in commit['files'])
    security_path = any(SECURITY_PATH.search(f) for f in commit['files'])

    # 三类证据通道，各自记录来源，便于按强弱分批使用。
    channels = []
    if highs:
        channels.append('MESSAGE_HIGH')
    if phrases:
        channels.append('MESSAGE_PHRASE')
    if weaks and (guard or danger):
        channels.append('MESSAGE_WEAK+DIFF')
    if (guard or danger) and security_path and fixy:
        # --strict 只收窄本通道：大 monorepo 上"路径像安全相关 + 有防护型改动"
        # 会成批误报，要求确有强边界原语，且改动足够小（与 curated 的极小改动口径一致）。
        if not strict or (strong and changed <= STRICT_MAX_CHANGED_LINES
                          and stat['files_changed'] <= STRICT_MAX_FILES):
            channels.append('DIFF_SECURITY_PATH')
    if not channels:
        return None

    tier = 'HIGH' if {'MESSAGE_HIGH', 'MESSAGE_PHRASE'} & set(channels) else 'MEDIUM'

    categories = []
    for name, _ in phrases:
        if name not in categories:
            categories.append(name)
    keyword_categories = categories_from(message, [
        (name, rules) for name, rules in CATEGORY_RULES
        if name in ('PATH_TRAVERSAL', 'INJECTION', 'AUTHORIZATION', 'MEMORY_BOUNDS')])
    for name in keyword_categories:
        if name not in categories:
            categories.append(name)
    if not categories and signal_text:
        categories = categories_from(signal_text)
    if not categories and security_path:
        categories = categories_from(' '.join(commit['files']))

    # 简单漏洞加权：小 diff、少文件、单一类别、有防护型改动。
    points = 0
    points += 3 if changed <= 30 else 2 if changed <= 60 else 1 if changed <= 120 else 0
    points += 3 if stat['files_changed'] <= 2 else 1 if stat['files_changed'] <= 3 else 0
    points += 2 if len(categories) == 1 else 1 if len(categories) == 2 else 0
    points += 2 if (guard or danger) else 0
    points += 2 if tier == 'HIGH' else 0
    points += 1 if code_files and not docs_only else 0
    notes = []
    if docs_only:
        points -= 4
        notes.append('只改文档/清单，无代码文件')
    if in_skipped_tree:
        points -= 3
        notes.append('改动集中在 tests/examples/docs 等非产品目录')
    if NOISE.search(commit['subject']):
        points -= 4
        notes.append('提交信息像噪声')
    if not fixy:
        points -= 1
        notes.append('提交信息不像修复动词')
    if stat['files_changed'] > 5:
        points -= 2
        notes.append('改动文件过多')

    simple = bool(tier in ('HIGH', 'MEDIUM') and points >= 7 and not docs_only
                  and not in_skipped_tree and code_files and categories
                  and changed <= max_changed and stat['files_changed'] <= max_files)
    loosening = bool(LOOSENING.search(commit['subject']))
    # 高置信子集：收紧型、有新增防护语句、单类别、极小的改动。
    curated = bool(simple and tier == 'HIGH' and not loosening
                   and guard and len(categories) == 1
                   and changed <= 40 and stat['files_changed'] <= 2)
    return {
        'tier': tier, 'channels': channels, 'categories': categories,
        'score': points, 'simple': simple, 'curated': curated,
        'loosening': loosening, 'notes': notes,
        'guard_lines': guard[:3], 'danger_lines': danger[:2],
        'changed_lines': changed, 'guard_hits': len(guard),
        'danger_hits': len(danger), 'security_path': security_path,
    }


def plausible(commit, keywords):
    """预筛：只对可能成为候选的提交取 diff，避免给几千条无关提交起 git show。"""
    message = commit['subject'] + ' ' + commit['body']
    if any(re.search(pattern, message, re.I) for _, pattern in keywords.values()):
        return True
    if any(re.search(pattern, message, re.I) for _, pattern in PHRASES):
        return True
    if FIX_VERB.search(commit['subject']) and any(
            SECURITY_PATH.search(f) for f in commit['files']):
        return True
    return False


def mine(repo_path, label, keywords, max_changed, max_files, with_diff, strict=False):
    commits = [c for c in read_history(repo_path) if len(c['parents']) == 1]
    if with_diff:
        wanted = [c for c in commits if plausible(c, keywords)]
        shas = [c['sha'] for c in wanted]
    else:
        wanted, shas = commits, []

    stats, patches, skipped = {}, {}, []
    if with_diff:
        raw_stats, skipped_stats = fetch_batch(repo_path, shas, ['--numstat'], 40)
        raw_patches, skipped_patches = fetch_batch(repo_path, shas, ['-U0', '--no-renames'], 40)
        stats = {s: parse_numstat(b) for s, b in raw_stats.items()}
        patches = raw_patches
        skipped = sorted(set(skipped_stats) | set(skipped_patches))

    candidates = []
    for commit in (wanted if with_diff else commits):
        sha = commit['sha']
        stat = stats.get(sha, {'files_changed': len(commit['files']),
                               'insertions': 0, 'deletions': 0})
        detail = assess(commit, patches.get(sha, ''), stat, keywords,
                        max_changed, max_files, strict)
        if detail is None:
            continue
        candidates.append({
            'repo': label, 'fixed_rev': sha, 'vulnerable_rev': commit['parents'][0],
            'pair': {'vulnerable': commit['parents'][0], 'fixed': sha},
            'date': commit['date'], 'author': commit['author'],
            'subject': commit['subject'], 'tier': detail['tier'],
            'channels': detail['channels'], 'categories': detail['categories'],
            'files': commit['files'], 'files_changed': stat['files_changed'],
            'insertions': stat['insertions'], 'deletions': stat['deletions'],
            'changed_lines': detail['changed_lines'], 'score': detail['score'],
            'simple': detail['simple'], 'curated': detail['curated'],
            'loosening': detail['loosening'], 'notes': detail['notes'],
            'guard_hits': detail['guard_hits'], 'danger_hits': detail['danger_hits'],
            'guard_lines': detail['guard_lines'], 'danger_lines': detail['danger_lines'],
            'evidence_level': 'MESSAGE_AND_DIFF' if with_diff else 'MESSAGE_ONLY',
            'confirm_required': True,
            'how_to_reproduce': f"git diff {commit['parents'][0]} {sha} -- "
                                + ' '.join(commit['files'][:4]),
        })
    candidates.sort(key=lambda c: (-int(c['simple']), -c['score'], c['date']))
    return {
        'repo': label, 'path': str(repo_path),
        'head': git(repo_path, ['rev-parse', 'HEAD']).strip(),
        'commits_total': len(commits),
        'diff_scanned': len(shas) if with_diff else 0,
        'diff_skipped': skipped,
        'candidates_total': len(candidates),
        'high_tier': sum(1 for c in candidates if c['tier'] == 'HIGH'),
        'simple_candidates': sum(1 for c in candidates if c['simple']),
        'curated_candidates': sum(1 for c in candidates if c['curated']),
        'candidates': candidates,
    }


def review(pools, count):
    for pool in pools:
        chosen = [c for c in pool['candidates'] if c['curated']][:count]
        if not chosen:
            chosen = [c for c in pool['candidates'] if c['simple']][:count]
        print(f"\n===== {pool['repo']} | 高置信 {pool['curated_candidates']} / "
              f"简单 {pool['simple_candidates']} / tier-HIGH {pool['high_tier']} / "
              f"全部 {pool['candidates_total']}")
        for c in chosen:
            flag = 'curated' if c['curated'] else 'simple'
            print(f"  [{c['tier']:<6}][{flag:<7}] {c['score']:>3} {c['fixed_rev'][:9]} "
                  f"{c['date']} {'/'.join(c['categories']) or '-'} L{c['changed_lines']} "
                  f"{c['subject'][:56]}")
            for line in c['guard_lines'][:2]:
                print(f"        + {line[:96]}")
            for line in c['danger_lines'][:1]:
                print(f"        - {line[:96]}")


def render_markdown(document):
    lines = ['# 安全修复提交扩池调研', '',
             f'> {document["truthfulness"]}', '',
             '## 关键词与匹配质量', '',
             '| 关键词 | 匹配质量 | 说明 |', '| --- | --- | --- |',
             '| security / bypass / injection / sanitiz / permission | HIGH | '
             '在提交信息中基本只在安全语境出现 |',
             '| auth / validat / escape | WEAK | 大量非安全语境（author、参数校验、'
             'JSON 转义），必须配合 diff 证据 |', '',
             '## 各仓库统计', '',
             '| 仓库 | HEAD | 非合并提交 | 候选 | tier=HIGH | 简单候选 |',
             '| --- | --- | --- | --- | --- | --- |']
    for pool in document['pools']:
        lines.append(f'| {pool["repo"]} | `{pool["head"][:10]}` | {pool["commits_total"]} '
                     f'| {pool["candidates_total"]} | {pool["high_tier"]} '
                     f'| {pool["simple_candidates"]} |')
    lines += ['', '## 简单候选', '']
    for pool in document['pools']:
        simple = [c for c in pool['candidates'] if c['simple']]
        lines += [f'### {pool["repo"]}（{len(simple)} 条）', '']
        if not simple:
            lines.append('无。该仓库的历史里没有符合关键词 + diff 证据的安全修复提交。')
            lines.append('')
            continue
        lines += ['| 有洞版本(父) | 已修复版本 | 日期 | tier | 分类 | 文件 | 改动行 | 标题 |',
                  '| --- | --- | --- | --- | --- | --- | --- | --- |']
        for c in simple:
            lines.append(f'| `{c["vulnerable_rev"][:10]}` | `{c["fixed_rev"][:10]}` '
                         f'| {c["date"]} | {c["tier"]} '
                         f'| {"/".join(c["categories"]) or "-"} | {c["files_changed"]} '
                         f'| {c["changed_lines"]} | {c["subject"][:56]} |')
        lines.append('')
    return '\n'.join(lines) + '\n'


def mine_adr(repo_path, label, adr_dir, max_changed, max_files, with_diff):
    """ADR 反查法：大型仓库里安全修复的提交信息常是领域语言（neutralize terminal
    controls / pin to loopback / empty environment），关键词法必然漏。但这类仓库往往把
    边界决策写成架构决策记录（ADR），一条记录对应一次实现提交，正好给出 (父, 修复) 对。

    注意：必须用 --all --diff-filter=A 按 basename 匹配，因为仓库可能把笔记搬到
    archived/ 目录；只按当前路径查会错认成归档提交。
    """
    try:
        listing = git(repo_path, ['ls-files', f'{adr_dir}/**/*.md'])
    except RuntimeError:
        return None
    notes = [p for p in listing.split() if p.endswith('.md') and not p.endswith('.zh.md')]
    candidates = []
    for note in notes:
        try:
            body = (Path(repo_path) / note).read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        hits = sorted({k for k, pattern in ADR_SIGNALS
                       if re.search(pattern, body, re.I)})
        if not hits:
            continue
        basename = note.rsplit('/', 1)[-1]
        try:
            log = git(repo_path, ['log', '--all', '--diff-filter=A', '--date=short',
                                  '--format=%H%x1f%P%x1f%ad%x1f%s',
                                  '--', f'**/{basename}'])
        except RuntimeError:
            continue
        lines = [line for line in log.strip().splitlines() if line.count('\x1f') == 3]
        if not lines:
            continue
        sha, parents, date, subject = lines[-1].split('\x1f')  # 最早一次新增
        if len(parents.split()) != 1:
            continue
        candidates.append({
            'repo': label, 'note': note, 'note_signals': hits,
            'fixed_rev': sha, 'vulnerable_rev': parents.split()[0],
            'pair': {'vulnerable': parents.split()[0], 'fixed': sha},
            'date': date, 'subject': subject,
            'channel': 'ADR_REVERSE_LOOKUP',
            'confirm_required': True,
            'how_to_reproduce': f'git diff {parents.split()[0]} {sha}',
        })
    candidates.sort(key=lambda c: c['date'])
    return {
        'repo': label, 'path': str(repo_path), 'adr_dir': adr_dir,
        'notes_scanned': len(notes),
        'adr_candidates': candidates,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--repo', action='append', required=True, help='本地 Git 仓库路径，可重复')
    parser.add_argument('--label', action='append', default=[], help='与 --repo 顺序对应的展示名')
    parser.add_argument('--out', help='候选池 JSON 输出路径')
    parser.add_argument('--md', help='Markdown 报告输出路径')
    parser.add_argument('--core-only', action='store_true', help='只用需求给出的 8 个关键词')
    parser.add_argument('--max-changed-lines', type=int, default=80)
    parser.add_argument('--max-files', type=int, default=3)
    parser.add_argument('--no-diff', action='store_true', help='只按提交信息匹配，不取 diff')
    parser.add_argument('--strict', action='store_true',
                        help='收窄 DIFF_SECURITY_PATH 通道（大 monorepo 用）：'
                             '要求新增行含强边界原语（basename/realpath/allowlist/'
                             'path.join/startswith 等），且改动 ≤40 行、≤2 文件。'
                             '默认关闭，保持小仓库上的既有召回')
    parser.add_argument('--review', type=int, default=0, help='打印前 N 条候选供人工判读')
    parser.add_argument('--adr-dir', help='架构决策记录目录（如 .agents/notes/implemented）。'
                                          '大型仓库里安全修复的提交信息常是领域语言，'
                                          '关键词法会失效；用 ADR 反查实现提交更可靠')
    options = parser.parse_args()

    keywords = dict(CORE_KEYWORDS)
    if not options.core_only:
        keywords.update(EXTRA_KEYWORDS)

    pools = []
    for index, repo in enumerate(options.repo):
        label = options.label[index] if index < len(options.label) else Path(repo).name
        print(f'[mine] {label} ...', flush=True)
        pool = mine(Path(repo), label, keywords, options.max_changed_lines,
                    options.max_files, not options.no_diff, options.strict)
        pools.append(pool)
        print(f'  非合并提交 {pool["commits_total"]}，候选 {pool["candidates_total"]}，'
              f'tier=HIGH {pool["high_tier"]}，简单候选 {pool["simple_candidates"]}，'
              f'高置信 {pool["curated_candidates"]}', flush=True)

    adr_pools = []
    if options.adr_dir:
        for index, repo in enumerate(options.repo):
            label = options.label[index] if index < len(options.label) else Path(repo).name
            result = mine_adr(Path(repo), label, options.adr_dir,
                              options.max_changed_lines, options.max_files,
                              not options.no_diff)
            if result is None:
                print(f'[adr] {label}: 目录 {options.adr_dir} 不存在，已跳过', flush=True)
                continue
            adr_pools.append(result)
            print(f'[adr] {label}: 扫描笔记 {result["notes_scanned"]}，'
                  f'反查到实现提交 {len(result["adr_candidates"])}', flush=True)

    document = {
        'purpose': '为漏洞挖掘评测扩充 ground truth 池：父提交=有洞版本，该提交=已修复版本',
        'truthfulness': '全部条目均为候选。关键词与 diff 形状只是线索，'
                        '正式计分前须由评测侧按公告或人工复核确认。',
        'keywords_core': {k: v[0] for k, v in CORE_KEYWORDS.items()},
        'keywords_extra': {} if options.core_only
                          else {k: v[0] for k, v in EXTRA_KEYWORDS.items()},
        'thresholds': {'max_changed_lines': options.max_changed_lines,
                       'max_files': options.max_files, 'min_score': 7,
                       'strict': options.strict},
        'adr_pools': adr_pools,
        'pools': pools,
    }
    if options.out:
        Path(options.out).parent.mkdir(parents=True, exist_ok=True)
        Path(options.out).write_text(json.dumps(document, ensure_ascii=False, indent=2) + '\n',
                                     encoding='utf-8')
        print(f'[out] {options.out}', flush=True)
    if options.md:
        Path(options.md).parent.mkdir(parents=True, exist_ok=True)
        Path(options.md).write_text(render_markdown(document), encoding='utf-8')
        print(f'[out] {options.md}', flush=True)
    if options.review:
        review(pools, options.review)
    return 0


if __name__ == '__main__':
    sys.exit(main())
