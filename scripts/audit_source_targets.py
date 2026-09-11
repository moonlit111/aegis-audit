#!/usr/bin/env python3
"""Start and collect real source audits for already-imported workspace snapshots.

Works on the running service: it finds the snapshot by project and snapshot name,
creates one SECURITY_AUDIT run per snapshot (idempotent, resumable), then exports
the audit evidence and the JSON/HTML/Markdown reports.

Usage:
  py -3 scripts/audit_source_targets.py --batch open-source-two-20260911 \
      --project "llama-cpp-python · Jinja 模板注入" --project "FastChat · Gradio 消息 XSS"
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time
import uuid

from aegis import ROOT

sys.path.insert(0, str(ROOT / 'tests'))
from smoke import API


TERMINAL = ('COMPLETED', 'PARTIAL', 'FAILED', 'CANCELLED', 'LIMIT_REACHED')


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def save(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    for attempt in range(6):
        try:
            temporary.replace(path)
            return
        except PermissionError:
            if attempt == 5:
                raise
            time.sleep(0.05 * (2 ** attempt))


def state(value: str) -> str:
    return value.split('_STATE_')[-1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', default='http://127.0.0.1:7331')
    parser.add_argument('--batch', required=True)
    parser.add_argument('--project', action='append', required=True)
    parser.add_argument('--snapshot', action='append', default=None,
                        help='Snapshot name filter; default: every snapshot of the project')
    parser.add_argument('--max-units', type=int, default=20)
    parser.add_argument('--max-model-calls', type=int, default=300)
    parser.add_argument('--max-tool-rounds', type=int, default=8)
    parser.add_argument('--timeout-seconds', type=int, default=3600)
    parser.add_argument('--model-timeout-seconds', type=int, default=240)
    parser.add_argument('--reasoning-effort', default='high')
    parser.add_argument('--collect-only', action='store_true')
    options = parser.parse_args()
    if Path(options.batch).name != options.batch:
        parser.error('--batch must be a single directory name')
    output = ROOT / '.data/verification/source-audits' / options.batch
    output.mkdir(parents=True, exist_ok=True)
    path = output / 'summary.json'
    config = {'maxModelCalls': options.max_model_calls, 'maxUnits': options.max_units,
              'maxToolRounds': options.max_tool_rounds, 'timeoutSeconds': options.timeout_seconds,
              'maxOutputTokens': 0, 'reasoningEffort': options.reasoning_effort,
              'modelTimeoutSeconds': options.model_timeout_seconds}
    document = json.loads(path.read_text(encoding='utf-8')) if path.exists() else {
        'schema_version': 1, 'batch': options.batch, 'created_at': now(),
        'server': options.server, 'audit_config': config,
        'scope': 'SOURCE_SECURITY_AUDIT', 'targets': [],
    }
    api = API(options.server)
    projects = {item['name']: item for item in api.rpc('ProjectService', 'ListProjects')['projects']}
    for name in options.project:
        if name not in projects:
            print('missing project: ' + name, flush=True)
            return 2
    for name in options.project:
        detail = api.rpc('ProjectService', 'GetProject', projectId=projects[name]['id'])
        for snapshot in detail.get('snapshots', []):
            if options.snapshot and snapshot['name'] not in options.snapshot:
                continue
            entry = next((item for item in document['targets']
                          if item['snapshotId'] == snapshot['id']), None)
            if entry is None:
                entry = {'project': name, 'snapshot': snapshot['name'],
                         'snapshotId': snapshot['id'], 'targetSha256': snapshot['targetSha256']}
                document['targets'].append(entry)
                save(path, document)
            folder = output / name.replace(' ', '_').replace('·', '-') / snapshot['name']
            folder.mkdir(parents=True, exist_ok=True)
            if not options.collect_only and not entry.get('runId'):
                run = api.rpc('RunService', 'CreateRun', requestId=str(uuid.uuid4()),
                              snapshotId=snapshot['id'], scope='SECURITY_AUDIT', **config)['run']
                entry['runId'] = run['id']
                entry['url'] = options.server + '/#/runs/' + run['id']
                save(path, document)
                print(name + ' / ' + snapshot['name'] + ': ' + entry['url'], flush=True)
            if not entry.get('runId') or entry.get('auditComplete'):
                continue
            run = api.rpc('RunService', 'GetRun', runId=entry['runId'])['run']
            deadline = time.monotonic() + options.timeout_seconds + 600
            while state(run['state']) not in TERMINAL and time.monotonic() < deadline:
                print(name + ' / ' + snapshot['name'] + ': ' + json.dumps(
                    [state(run['state']),
                     json.loads(run.get('summaryJson', '{}')).get('audited_unit_count'),
                     json.loads(run.get('summaryJson', '{}')).get('finding_count')]), flush=True)
                time.sleep(15)
                run = api.rpc('RunService', 'GetRun', runId=entry['runId'])['run']
            audit = api.rpc('FindingService', 'GetAudit', runId=entry['runId'])
            save(folder / 'audit.json', {'run': run, 'audit': audit})
            summary = json.loads(run.get('summaryJson', '{}'))
            entry.update({
                'state': run['state'],
                'error': run.get('error', ''),
                'audited_units': summary.get('audited_unit_count'),
                'eligible_units': summary.get('eligible_unit_count'),
                'findings': [{'id': item['id'], 'category': item.get('category'),
                              'review_status': item.get('reviewStatus'),
                              'verification_status': item.get('verificationStatus'),
                              'title': item.get('title')} for item in audit.get('findings', [])],
                'model_calls': len(audit.get('modelCalls', [])),
            })
            entry['reports'] = {}
            for fmt, extension in (('json', 'json'), ('html', 'html'), ('markdown', 'md')):
                request = str(uuid.uuid4())
                report = api.rpc('ReportService', 'CreateReport', requestId=request,
                                 runId=entry['runId'], format=fmt)['report']
                data = api.download(report['artifactId'])
                (folder / ('report.' + extension)).write_bytes(data)
                entry['reports'][fmt] = report['artifactId']
            entry['auditComplete'] = True
            entry['updatedAt'] = now()
            save(path, document)
            print(name + ' / ' + snapshot['name'] + ': ' + json.dumps(
                {'state': state(run['state']), 'findings': len(entry['findings']),
                 'validated': sum(1 for item in entry['findings']
                                  if item['review_status'] == 'VALIDATED')}), flush=True)
    save(path, document)
    print(json.dumps({'evidence': str(path), 'targets': [
        {'project': item['project'], 'snapshot': item['snapshot'], 'state': item.get('state'),
         'findings': len(item.get('findings', [])),
         'validated': sum(1 for f in item.get('findings', []) if f['review_status'] == 'VALIDATED')}
        for item in document['targets']]}, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
