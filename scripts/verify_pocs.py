#!/usr/bin/env python3
"""Replay every archived reuse PoC against its frozen target binary.

The audit produces the PoC (evidence JSON + recipe + replay script); this script
starts from those archived files only, rebuilds the test directory and checks
that the recorded observation still reproduces. Nothing is inferred from the
audit database.

Usage: py -3 scripts/verify_pocs.py --batch protected-poc-20260911-r1
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import time

from aegis import ROOT


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--batch', required=True)
    parser.add_argument('--output', type=Path)
    options = parser.parse_args()
    if Path(options.batch).name != options.batch:
        parser.error('--batch must be a single directory name')
    batch = ROOT / '.data/verification/protected-acceptance' / options.batch
    summary = json.loads((batch / 'summary.json').read_text(encoding='utf-8'))
    results = []
    for target_id, spec in summary['results'].items():
        defect = spec.get('defect', {})
        poc = defect.get('poc', {})
        evidence = poc.get('evidence') or {}
        folder = batch / target_id
        runner, recipe = folder / 'poc-replay.py', folder / 'poc-recipe.json'
        target = ROOT / defect.get('path', '')
        record = {'id': target_id, 'name': spec.get('name'), 'exploit_class': evidence.get('exploit_class'),
                  'evidence_kind': evidence.get('kind'), 'target': str(target.relative_to(ROOT)),
                  'exploitation': defect.get('runtime', {}).get('exploitation')}
        if not (runner.is_file() and recipe.is_file() and target.is_file()):
            record.update({'status': 'MISSING_ARTIFACT',
                           'missing': [str(item) for item in (runner, recipe, target)
                                       if not item.is_file()]})
            results.append(record)
            continue
        work = folder / ('poc-replay-' + time.strftime('%Y%m%d-%H%M%S'))
        completed = subprocess.run(
            [sys.executable, str(runner), '--target', str(target), '--recipe', str(recipe),
             '--work', str(work)],
            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=300,
            check=False)
        trials = []
        for line in completed.stdout.splitlines():
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if 'attempt' in item:
                trials.append(item)
            elif 'observed' in item:
                record['observed'] = item.get('observed')
                record['expected'] = item.get('expected')
        record.update({
            'status': 'REPRODUCED' if completed.returncode == 0 else 'NOT_REPRODUCED',
            'exit_code': completed.returncode,
            'trials': trials,
            'observed': record.get('observed'),
            'expected': record.get('expected'),
            'work': str(work.relative_to(ROOT)),
            'stderr': completed.stderr[-2000:],
        })
        results.append(record)
        print(target_id + ': ' + json.dumps({k: record[k] for k in
                                             ('status', 'observed', 'expected', 'exploit_class')}),
              flush=True)
    document = {
        'schema_version': 1,
        'batch': options.batch,
        'verified_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'platform': 'windows/x64',
        'scope': 'REUSE_POC_REPLAY',
        'purpose': 'Independent replay of the archived PoC inputs against the frozen target binaries',
        'targets': results,
        'passed': bool(results) and all(item['status'] == 'REPRODUCED' for item in results),
    }
    output = options.output or (batch / 'poc-replay.json')
    output.write_text(json.dumps(document, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'passed': document['passed'], 'evidence': str(output)}, ensure_ascii=False))
    return 0 if document['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
