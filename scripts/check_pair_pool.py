#!/usr/bin/env python3
"""把已核实的安全修复对照池接成可执行评测：漏洞版应命中、修复版应零命中。

判定四分列，**不许合并**：
    命中        = 类别匹配 + reviewStatus==VALIDATED + 引文覆盖目标文件
    有候选未成立 = 有 finding 但非 VALIDATED
    未检出      = 目标文件已被 AUDITOR 覆盖但零 finding
    未覆盖      = 目标文件下没有任何成功的 AUDITOR 任务（**不算"安全"**）

纪律（勿改）：
- 只读：不修改对照池 JSON、不修改本地 clone、不写受版本控制的文件。
- **盲测**：喂给模型的输入只有源码本身；不得把 CVE 编号、公告文本或修复提交信息写进输入或提示词。
- 不因"没检出"而加预算重跑；只在"未覆盖"时提高 max-units。
- 失败与超时一律保留原始证据，不用成功批次覆盖。

用法：
    # 0) 先做连通性探测（真实调用一次模型，几十 token）
    py -3 scripts/check_pair_pool.py --check-model

    # 1) 管道自检：不调模型，只验证 ZIP→快照→能解析出目标单元
    py -3 scripts/check_pair_pool.py --pair p04-ollama-history --structure-only

    # 2) 单对端到端（C1）
    py -3 scripts/check_pair_pool.py --pair p04-ollama-history

    # 3) 一个阶段（阶段1 = 4 个小文件对）
    py -3 scripts/check_pair_pool.py --stage 1

    # 4) 只构造输入看一眼，不连服务
    py -3 scripts/check_pair_pool.py --stage 1 --dry-run

    # 5) 离线复判一个已有批次（读 *-audit.json + git diff 改动行），不连服务不花钱
    py -3 scripts/check_pair_pool.py --rejudge .data/verification/pair-pool/stage3-p01
"""
import argparse
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import subprocess
import sys
import time
import uuid
import zipfile

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tests'))
from smoke import API  # noqa: E402

PAIRS_FILE = ROOT / 'evaluation/reference/security-commit-pairs-verified.json'
REPOS_ROOT = ROOT / '.data/security-pool/repos'

# 短 id → 对照池 JSON 中的 id。放这里而不是 JSON，是因为 scripts/ 允许出现仓库名，
# 而 crates/proto 等产品代码不允许（tests/test_audit_generality.py 强制）。
PAIR_KEYS = {
    'p01-llama-jinja': 'llama-cpp-python-jinja-template-sandbox',
    'p02-llama-buffer': 'llama-cpp-python-detokenize-buffer-size',
    'p03-fastchat-xss': 'fastchat-gradio-xss-unsanitized-user-input',
    'p04-ollama-history': 'ollama-history-file-world-readable',
    'p05-ollama-gpusize': 'ollama-gpu-size-index-out-of-range',
    'p06-ollama-parts': 'ollama-download-parts-index-out-of-range',
    'p07-ollama-images': 'ollama-relative-path-containment',
    'p08-ollama-authkey': 'ollama-private-key-file-type-and-readability',
    'p09-ollama-zerolen': 'ollama-zero-length-image-unvalidated',
}
# 语言通道支持范围（import.rs）：ts/tsx 等为 unsupported，本脚本会显式拒绝。
SUPPORTED_SUFFIX = {'.py': 'python', '.go': 'go', '.c': 'c', '.h': 'c',
                    '.cc': 'cpp', '.cpp': 'cpp', '.cxx': 'cpp', '.hpp': 'cpp'}

STAGE_LIMITS = {1: 200, 2: 1300}  # 行数上限；>1300 归阶段 3


def git(repo, args):
    result = subprocess.run(['git', '-C', str(repo)] + args,
                            capture_output=True, text=True, encoding='utf-8', errors='replace')
    if result.returncode != 0:
        raise RuntimeError(f'git {" ".join(args[:2])} failed: {result.stderr.strip()[:200]}')
    return result.stdout


def load_pairs():
    document = json.loads(PAIRS_FILE.read_text(encoding='utf-8'))
    by_id = {entry['id']: entry for entry in document['pairs']}
    return by_id


def pair_file(pair):
    """返回要钉死的文件路径；对照池里个别条目写的是范围描述，取第一个像路径的片段。"""
    raw = pair.get('file') or ''
    for token in raw.replace('与', ' ').replace('；', ' ').split():
        token = token.strip('，,。')
        if '.' in token and '/' in token:
            return token
    raise ValueError(f"{pair['id']}: 无法从 file 字段解析出目标文件：{raw!r}")


HUNK = None


def changed_lines(clone, vrev, frev, path):
    """算出这一对改动点在各侧的真实行号。

    返回 (旧侧行号集合, 新侧行号集合)：旧侧对应漏洞版快照，新侧对应修复版快照。
    用 -U0 的 hunk 头 @@ -a,b +c,d @@ 直接取，不靠猜。空集合表示只改了文件模式等
    非行级内容（例如 0o666→0o600 就是行级改动，能取到）。
    """
    global HUNK
    if HUNK is None:
        import re as _re
        HUNK = _re.compile(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@')
    text = git(clone, ['diff', '-U0', '--no-color', '--no-textconv', vrev, frev, '--', path])
    old, new = set(), set()
    for line in text.splitlines():
        m = HUNK.match(line)
        if not m:
            continue
        o_start, o_count, n_start, n_count = m.group(1), m.group(2), m.group(3), m.group(4)
        o_count = int(o_count) if o_count is not None else 1
        n_count = int(n_count) if n_count is not None else 1
        old.update(range(int(o_start), int(o_start) + o_count))
        new.update(range(int(n_start), int(n_start) + n_count))
    return old, new


def build_package(clone, rev, path):
    data = subprocess.run(['git', '-C', str(clone), 'show', f'{rev}:{path}'],
                          capture_output=True).stdout
    if not data:
        raise RuntimeError(f'git show {rev}:{path} 返回空')
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(path, data)
    return buffer.getvalue(), data.decode('utf-8', 'replace')


def staged_inputs(batch_dir, short, path, tag):
    candidate = batch_dir / 'inputs' / short / tag / path
    return candidate if candidate.is_file() else None


def classify(audit, name_by_unit, target_path, expected_category, focus_lines=frozenset()):
    findings = audit.get('findings', []) or []
    tasks = audit.get('tasks', []) or []
    audited = {t.get('itemKey') or t.get('item_key') for t in tasks
               if t.get('role') == 'AUDITOR' and t.get('status') == 'SUCCEEDED'}
    covered_paths = {name_by_unit.get(unit) for unit in audited if unit}

    def on_target(finding):
        evidence = finding.get('evidence', []) or []
        if any((e.get('path') or '') == target_path for e in evidence):
            return True
        return name_by_unit.get(finding.get('unitId') or finding.get('unit_id')) == target_path

    def lines_of(finding):
        spans = set()
        for e in finding.get('evidence', []) or []:
            if (e.get('path') or '') != target_path:
                continue
            start = e.get('startLine') or e.get('start_line') or 0
            end = e.get('endLine') or e.get('end_line') or start
            spans.update(range(int(start), int(end) + 1))
        return spans

    hits = [f for f in findings
            if f.get('category') == expected_category
            and f.get('reviewStatus') == 'VALIDATED' and on_target(f)]
    # 更严的一档：证据行号必须落在 git diff 给出的改动点上，才算"找到了那个缺陷"。
    on_point = [f for f in hits if focus_lines and lines_of(f) & focus_lines]
    pending = [f for f in findings if f.get('reviewStatus') != 'VALIDATED' and on_target(f)]
    off_target = [f for f in findings if not on_target(f)]
    covered = target_path in covered_paths

    if on_point:
        verdict = '命中改动点'
    elif hits:
        verdict = '命中类别但不在改动点'
    elif pending:
        verdict = '有候选未成立'
    elif covered:
        verdict = '未检出'
    else:
        verdict = '未覆盖'
    return {
        'verdict': verdict,
        'audited_unit_count': len(audited),
        'target_covered': covered,
        'findings_total': len(findings),
        'focus_line_count': len(focus_lines),
        'hits': [{'id': f.get('id'), 'title': f.get('title'), 'category': f.get('category'),
                  'cwe': f.get('cwe'), 'severity': f.get('severity')} for f in hits],
        'hits_on_change_point': [{'id': f.get('id'), 'title': f.get('title')} for f in on_point],
        'pending': [{'id': f.get('id'), 'title': f.get('title'), 'category': f.get('category'),
                     'reviewStatus': f.get('reviewStatus')} for f in pending],
        'off_target_findings': len(off_target),
    }


def rejudge(batch_dir, repos_root, pairs_by_id):
    """离线复判：读批次里的 *-audit.json，用 git diff -U0 的改动行重算判定。

    与在线判定同源（同一个 classify），但不连服务、不调模型，用于结果文档复核。
    只读证据文件；需要写盘时由 --out 指定输出 JSON 路径，不往批次目录里加文件。
    """
    if not batch_dir.is_dir():
        raise SystemExit(f'批次目录不存在：{batch_dir}')
    rows = []
    for audit_path in sorted(batch_dir.glob('*-audit.json')):
        stem = audit_path.name[:-len('-audit.json')]
        short, _, tag = stem.rpartition('-')
        if tag not in ('vuln', 'fixed') or short not in PAIR_KEYS:
            print(f'[skip] 文件名无法解析成 短id-tag：{audit_path.name}')
            continue
        pair = pairs_by_id[PAIR_KEYS[short]]
        clone = repos_root / pair['repo'].split('/')[1]
        path = pair_file(pair)
        old_lines, new_lines = changed_lines(clone, pair['vulnerable_rev'],
                                             pair['fixed_rev'], path)
        document = json.loads(audit_path.read_text(encoding='utf-8'))
        name_by_unit = {u['id']: u.get('path', '') for u in document.get('units') or []}
        verdict = classify(document.get('audit') or {}, name_by_unit, path,
                           pair['category'], old_lines if tag == 'vuln' else new_lines)
        rows.append({'file': audit_path.name, 'batch': batch_dir.name, 'short': short,
                     'tag': tag, 'pair_id': pair['id'], 'target_path': path,
                     'state': (document.get('run') or {}).get('state'), **verdict})
    for row in rows:
        print(f"{row['short']:<22} {row['tag']:<6} {str(row['state']):<22} "
              f"{row['verdict']:<14} 候选={row['findings_total']} "
              f"类别命中={len(row['hits'])} 改动点命中={len(row['hits_on_change_point'])} "
              f"未成立={len(row['pending'])} 目标覆盖={row['target_covered']} "
              f"已审单元={row['audited_unit_count']}", flush=True)
    return rows


def wait_run(api, run_id, timeout):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        run = api.rpc('RunService', 'GetRun', runId=run_id)['run']
        state = run['state'].split('_STATE_')[-1]
        if state != last:
            print(f'      run state -> {state}', flush=True)
            last = state
        if state in ('COMPLETED', 'PARTIAL'):
            return run
        if state in ('FAILED', 'CANCELLED', 'LIMIT_REACHED'):
            return run
        time.sleep(2)
    api.rpc('RunService', 'CancelRun', runId=run_id)
    raise RuntimeError('审计超时，已请求取消')


def run_package(api, project_id, short, tag, package, scope, options, out_dir):
    artifact = api.upload(f'{short}-{tag}.zip', package, 'application/zip')
    snapshot = api.rpc('ProjectService', 'CreateSnapshot', requestId=str(uuid.uuid4()),
                       projectId=project_id, kind='TARGET_KIND_SOURCE', artifactId=artifact,
                       name=f'{short}-{tag}')['snapshot']
    snapshot = api.wait('ProjectService', 'GetSnapshot', 'snapshot', ('READY', 'PARTIAL'),
                        timeout=900, snapshotId=snapshot['id'])
    request = {'requestId': str(uuid.uuid4()), 'snapshotId': snapshot['id'], 'scope': scope,
               'maxModelCalls': options.max_model_calls, 'maxUnits': options.max_units,
               'maxToolRounds': options.max_tool_rounds, 'timeoutSeconds': options.timeout_seconds,
               'reasoningEffort': 'high'}
    run = api.rpc('RunService', 'CreateRun', **request)['run']
    print(f'      {tag}: run={run["id"]}', flush=True)
    run = wait_run(api, run['id'], options.timeout_seconds + 600)
    audit = api.rpc('FindingService', 'GetAudit', runId=run['id'])
    units = api.rpc('ProgramService', 'ListUnits', runId=run['id'], limit=500).get('units', [])
    name_by_unit = {u['id']: u.get('path', '') for u in units}
    (out_dir / f'{short}-{tag}-audit.json').write_text(
        json.dumps({'run': run, 'audit': audit, 'units': units}, ensure_ascii=False, indent=2),
        encoding='utf-8')
    reports = {}
    for fmt, suffix in (('json', 'json'), ('html', 'html'), ('markdown', 'md')):
        report = api.rpc('ReportService', 'CreateReport', requestId=str(uuid.uuid4()),
                         runId=run['id'], format=fmt)['report']
        (out_dir / f'{short}-{tag}-report.{suffix}').write_bytes(api.download(report['artifactId']))
        reports[fmt] = report['artifactId']
    return run, audit, name_by_unit, units, reports


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--server', default='http://127.0.0.1:7331')
    parser.add_argument('--pair', action='append', default=[], help='短 id，可重复')
    parser.add_argument('--stage', type=int, choices=[1, 2, 3])
    parser.add_argument('--all', action='store_true', help='全部 9 对（含阶段 3，成本高）')
    parser.add_argument('--structure-only', action='store_true',
                        help='只跑 STRUCTURE_ANALYSIS（不调模型），用于 C0 管道自检')
    parser.add_argument('--only', choices=['vuln', 'fixed'],
                        help='只跑其中一个包（另一包已有结果时省额度）')
    parser.add_argument('--check-model', action='store_true', help='只做一次模型连通性探测')
    parser.add_argument('--dry-run', action='store_true', help='只构造输入并打印计划')
    parser.add_argument('--rejudge', type=Path, metavar='BATCH_DIR',
                        help='离线复判已有批次目录（读 *-audit.json + git diff 改动行），'
                             '不连服务不调模型；结果打印到 stdout')
    parser.add_argument('--out', type=Path, help='批次目录')
    parser.add_argument('--repos-root', type=Path, default=REPOS_ROOT)
    parser.add_argument('--max-units', type=int, default=20)
    parser.add_argument('--max-model-calls', type=int, default=240)
    parser.add_argument('--max-tool-rounds', type=int, default=8)
    parser.add_argument('--timeout-seconds', type=int, default=1800)
    options = parser.parse_args()

    if options.rejudge:
        rejudge(options.rejudge, options.repos_root, load_pairs())
        return 0

    stamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
    out_dir = options.out or (ROOT / f'.data/verification/pair-pool/pair-pool-{stamp}')
    out_dir.mkdir(parents=True, exist_ok=True)

    if options.check_model:
        api = API(options.server)
        capabilities = api.rpc('SystemService', 'GetCapabilities', requestId=str(uuid.uuid4()))
        print('model_connection =', json.dumps(capabilities.get('modelConnection'), ensure_ascii=False))
        call = api.rpc('SystemService', 'CheckModelConnection',
                       requestId=str(uuid.uuid4())).get('call')
        print('check_model_connection =', json.dumps(call, ensure_ascii=False))
        (out_dir / 'model-connection.json').write_text(
            json.dumps({'capabilities': capabilities, 'call': call}, ensure_ascii=False, indent=2),
            encoding='utf-8')
        return 0

    pairs_by_id = load_pairs()
    selected = []
    for short in options.pair:
        if short not in PAIR_KEYS:
            raise SystemExit(f'未知短 id：{short}；可用：{", ".join(sorted(PAIR_KEYS))}')
        selected.append(short)
    if options.all:
        selected = sorted(PAIR_KEYS)

    plans = []
    for short in (selected or sorted(PAIR_KEYS)):
        pair = pairs_by_id[PAIR_KEYS[short]]
        clone = options.repos_root / pair['repo'].split('/')[1]
        path = pair_file(pair)
        suffix = Path(path).suffix.lower()
        if suffix not in SUPPORTED_SUFFIX:
            print(f'[跳过] {short}: {suffix} 不在源码通道支持范围（语言不支持）', flush=True)
            continue
        vuln, _ = build_package(clone, pair['vulnerable_rev'], path)
        fixed, fixed_text = build_package(clone, pair['fixed_rev'], path)
        old_lines, new_lines = changed_lines(clone, pair['vulnerable_rev'], pair['fixed_rev'], path)
        lines = fixed_text.count('\n') + 1
        stage = 1 if lines <= STAGE_LIMITS[1] else 2 if lines <= STAGE_LIMITS[2] else 3
        plans.append({'short': short, 'pair': pair, 'clone': clone, 'path': path,
                      'lines': lines, 'stage': stage,
                      'old_lines': old_lines, 'new_lines': new_lines,
                      'vuln_zip': vuln, 'fixed_zip': fixed})

    if options.stage:
        plans = [p for p in plans if p['stage'] == options.stage]
    if not plans:
        raise SystemExit('没有选中任何对照。用 --pair / --stage / --all 指定。')

    print(f'批次目录：{out_dir}')
    for plan in plans:
        print(f"  阶段{plan['stage']} {plan['short']:<22} {plan['path']:<44} "
              f"{plan['lines']:>5} 行  类别={plan['pair']['category']}")

    if options.dry_run:
        inputs = out_dir / 'inputs'
        for plan in plans:
            for tag, data in (('vuln', plan['vuln_zip']), ('fixed', plan['fixed_zip'])):
                target = inputs / plan['short'] / tag / plan['path']
                target.parent.mkdir(parents=True, exist_ok=True)
                target.with_suffix(target.suffix + '.zip').write_bytes(data)
        print(f'[dry-run] 输入包已写入 {inputs}；未连接服务，未消耗模型额度。')
        return 0

    scope = 'STRUCTURE_ANALYSIS' if options.structure_only else 'SECURITY_AUDIT'
    api = API(options.server)
    capabilities = api.rpc('SystemService', 'GetCapabilities', requestId=str(uuid.uuid4()))
    connection = capabilities.get('modelConnection') or {}
    print('model_connection =', json.dumps(connection, ensure_ascii=False))
    if scope == 'SECURITY_AUDIT' and str(connection.get('configured')).lower() not in ('true', '1'):
        raise SystemExit('模型未配置：先配置 DeepSeek 凭据再做漏洞审计。')

    project = api.rpc('ProjectService', 'CreateProject', requestId=str(uuid.uuid4()),
                      name=f'对照池评测 {stamp}')['project']
    results = []
    for plan in plans:
        short = plan['short']
        print(f"\n== {short} ({plan['path']}, {plan['lines']} 行, {plan['pair']['category']})", flush=True)
        record = {'short': short, 'pair_id': plan['pair']['id'], 'repo': plan['pair']['repo'],
                  'file': plan['path'], 'lines': plan['lines'], 'stage': plan['stage'],
                  'expected_category': plan['pair']['category'], 'scope': scope,
                  'vulnerable_rev': plan['pair']['vulnerable_rev'],
                  'fixed_rev': plan['pair']['fixed_rev'], 'packages': {}}
        for tag, package in (('vuln', plan['vuln_zip']), ('fixed', plan['fixed_zip'])):
            if options.only and tag != options.only:
                continue
            try:
                run, audit, name_by_unit, units, reports = run_package(
                    api, project['id'], short, tag, package, scope, options, out_dir)
                if options.structure_only:
                    # 结构自检只验证"能不能解析出目标单元"，**不判定漏洞**。
                    # 这里若不特判，会让空 findings 被误报成"未覆盖"，污染证据。
                    target_units = [u for u in units if u.get('path') == plan['path']]
                    verdict = {'verdict': '结构自检',
                               'unit_count': len(units),
                               'target_unit_count': len(target_units),
                               'target_functions': [u.get('name') for u in target_units],
                               'target_covered': bool(target_units),
                               'findings_total': 0, 'hits': [], 'pending': [],
                               'off_target_findings': 0}
                else:
                    verdict = classify(audit, name_by_unit, plan['path'],
                                       plan['pair']['category'],
                                       plan['old_lines'] if tag == 'vuln' else plan['new_lines'])
                usage = json.loads(run.get('summaryJson') or '{}').get('model_usage')
                record['packages'][tag] = {
                    'run_id': run['id'], 'state': run['state'], 'usage': usage,
                    'reports': reports, **verdict}
                if options.structure_only:
                    print(f"      {tag}: 结构自检  单元={verdict['unit_count']} "
                          f"其中目标文件单元={verdict['target_unit_count']} "
                          f"函数={verdict['target_functions']}", flush=True)
                else:
                    print(f"      {tag}: {verdict['verdict']}  候选={verdict['findings_total']} "
                          f"类别命中={len(verdict['hits'])} 落在改动点={len(verdict['hits_on_change_point'])} "
                          f"未成立={len(verdict['pending'])} 目标已覆盖={verdict['target_covered']} "
                          f"(改动点 {verdict['focus_line_count']} 行)", flush=True)
            except Exception as error:  # 保留失败证据，继续后面的对照
                record['packages'][tag] = {'error': str(error)}
                print(f'      {tag}: ERROR {error}', flush=True)
        vuln, fixed = record['packages'].get('vuln', {}), record['packages'].get('fixed', {})
        # PASS 只看 VALIDATED 数（命中数），**不看**"有候选未成立"这个标签：
        # 修复版快照里往往仍有 ground-truth 提交未修的其他真实问题（实测 p08 修复包
        # 就产出了一条 NewNonce DoS 的 VALIDATED，类别与预期不同），因此把
        # "修复包必须判为未检出"当作 PASS 条件会让 PASS 永假。正确的判据是：
        # 漏洞包在该类别上有 ≥1 条 VALIDATED，且修复包在该类别上有 0 条。
        record['pass'] = None if (options.structure_only or options.only) else (
            len(vuln.get('hits_on_change_point') or []) >= 1
            and len(fixed.get('hits_on_change_point') or []) == 0)
        results.append(record)

    summary = {'batch': out_dir.name, 'scope': scope, 'server': options.server,
               'generated_at': datetime.now(timezone.utc).isoformat(),
               'budget': {'max_units': options.max_units, 'max_model_calls': options.max_model_calls,
                          'max_tool_rounds': options.max_tool_rounds,
                          'timeout_seconds': options.timeout_seconds},
               'results': results}
    (out_dir / 'summary.json').write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    passed = sum(1 for r in results if r.get('pass'))
    if options.structure_only:
        print(f"\n[汇总] 结构自检完成 {len(results)} 对（**不判定漏洞**）；证据：{out_dir}")
    else:
        print(f"\n[汇总] {passed}/{len(results)} 对 PASS；证据：{out_dir}")
    print(json.dumps({r['short']: {t: v.get('verdict') or v.get('error')
                                   for t, v in r['packages'].items()} for r in results},
                     ensure_ascii=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())
