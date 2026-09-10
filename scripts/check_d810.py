#!/usr/bin/env python3
"""Run the configured D-810 bridge on the benign MBA fixture and retain before/after evidence."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from aegis import ROOT, require_windows


def main():
    require_windows()
    settings = json.loads((ROOT / '.tools/ida-d810.json').read_text(encoding='utf-8'))
    parent = ROOT / '.data/verification/ida-d810'
    parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='mba-', dir=parent))
    shutil.copy2(ROOT / 'tools/ida/d810_export.py', work / 'd810_export.py')
    shutil.copy2(ROOT / 'tests/fixtures/recovery/sample.exe', work / 'target.bin')
    (work / 'd810-request.json').write_text(json.dumps({'plugin_root': settings['plugin_root'], 'dependencies': settings['dependencies'],
                                                      'profile': 'instructions', 'snapshot_path': 'sample.exe', 'max_functions': 80}), encoding='utf-8')
    with (work / 'console.log').open('wb') as log:
        done = subprocess.run([settings['executable'], '-A', '-Lida.log', '-Sd810_export.py', '-oanalysis.i64', 'target.bin'],
                              cwd=work, stdout=log, stderr=subprocess.STDOUT, timeout=240, creationflags=subprocess.CREATE_NO_WINDOW)
    if done.returncode or not (work / 'd810-result.json').is_file():
        raise SystemExit('IDA/D-810 check failed; evidence: ' + str(work))
    data = json.loads((work / 'd810-result.json').read_text(encoding='utf-8'))
    summary = {'ida': data['metadata']['ida_version'], 'changed_functions': data['metadata']['d810_changed_functions'],
               'rule_matches': data['metadata']['d810_rule_matches'], 'evidence': str(work), 'target_executed': False}
    print(json.dumps(summary, ensure_ascii=True))
    if not summary['changed_functions'] or not summary['rule_matches']:
        raise SystemExit('D-810 loaded but did not demonstrate code simplification on the MBA fixture')


if __name__ == '__main__':
    main()
