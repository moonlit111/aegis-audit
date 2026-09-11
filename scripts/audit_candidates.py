#!/usr/bin/env python3
"""Run resumable, source-only candidate audits without executing target software.

Inputs are the pinned public identities and existing structure snapshots, never
the reference-answer catalog. Static results do not satisfy formal acceptance.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tests'))
from smoke import API

CATALOG = ROOT / 'evaluation/targets/structure-candidates.json'
STRUCTURE = ROOT / '.data/verification/candidate-structure.json'
TERMINAL = {'COMPLETED', 'PARTIAL', 'FAILED', 'CANCELLED', 'LIMIT_REACHED'}


def now():
    return datetime.now(timezone.utc).isoformat()


def state(value):
    return value.split('_STATE_')[-1]


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    for attempt in range(6):
        try:
            temporary.replace(path)
            return
        except PermissionError:
            # Windows indexers can briefly hold a file without delete sharing.
            # Keep the previous checkpoint intact if replacement stays blocked.
            if attempt == 5:
                raise
            time.sleep(0.05 * (2 ** attempt))


def verify_snapshot(candidate, evidence, snapshot):
    if evidence['candidate'] != candidate or snapshot['id'] != evidence['snapshot_id']:
        raise ValueError('Candidate identity or snapshot changed; start a separate batch')
    if snapshot.get('kind') != 'TARGET_KIND_GIT':
        raise ValueError('Only pinned Git source snapshots are eligible; binaries are not executed')
    if state(snapshot['state']) not in {'READY', 'PARTIAL'}:
        raise ValueError('Source snapshot is not ready')
    if not re.fullmatch(r'[a-f0-9]{40}', candidate['revision']):
        raise ValueError('Source revision must be a full commit ID')
    if snapshot.get('resolvedRevision') != candidate['revision']:
        raise ValueError('Imported source does not match the pinned revision')
    if (not re.fullmatch(r'[a-f0-9]{64}', evidence['target_sha256'])
            or snapshot.get('targetSha256') != evidence['target_sha256']):
        raise ValueError('Source hash differs from retained structure evidence')


def start_candidate(api, result, config, checkpoint):
    if result.get('run_id'):
        return
    # Persist the idempotency key before the RPC, including a lost-response retry.
    result.setdefault('request_id', str(uuid.uuid4()))
    checkpoint()
    run = api.rpc('RunService', 'CreateRun', requestId=result['request_id'],
                  snapshotId=result['snapshot_id'], scope='SECURITY_AUDIT', **config)['run']
    result['run_id'] = run['id']
    result['state'] = run['state']
    result['url'] = api.base + '/#/runs/' + run['id']
    checkpoint()


def summarize(run, audit):
    summary = json.loads(run.get('summaryJson', '{}'))
    findings = audit.get('findings', [])
    tasks = audit.get('tasks', [])
    audited = {task['itemKey'] for task in tasks
               if task['role'] == 'AUDITOR' and task['status'] == 'SUCCEEDED'}
    eligible = int(summary.get('eligible_unit_count', run.get('unitCount', 0)))
    if audit.get('runtime'):
        raise ValueError('Unexpected runtime activity in a source-only audit; inspect raw evidence')
    return {
        'state': run['state'],
        'error': run.get('error', ''),
        'units': int(run.get('unitCount', 0)),
        'eligible_units': eligible,
        'audited_units': len(audited),
        'all_eligible_units_audited': eligible > 0 and len(audited) == eligible,
        'structure_partial': summary.get('structure_partial', True),
        'unparsed_files': [item for item in summary.get('files', [])
                           if item['status'] not in ('PARSED', 'NOT_SOURCE')],
        'findings': len(findings),
        'review_statuses': dict(Counter(item.get('reviewStatus', 'UNKNOWN') for item in findings)),
        'validated_categories': dict(Counter(item['category'] for item in findings
                                             if item.get('reviewStatus') == 'VALIDATED')),
        'model_calls': len(audit.get('modelCalls', [])),
        'model_usage': summary.get('model_usage', {}),
        'task_statuses': dict(Counter(item['status'] for item in tasks)),
        'vulnerability_audit': summary.get('vulnerability_audit', 'NOT_RUN'),
        'independent_review': summary.get('independent_review', 'NOT_RUN'),
        'target_executed': False,
        'exploitation': 'NOT_RUN',
        'formal_acceptance': False,
        'checked_at': now(),
    }


def collect(api, result, run, output, checkpoint):
    audit = api.rpc('FindingService', 'GetAudit', runId=run['id'])
    folder = output / result['candidate']['id']
    save(folder / 'audit.json', {'run': run, 'audit': audit})
    result.update(summarize(run, audit))
    result.setdefault('reports', {})
    checkpoint()
    if state(run['state']) not in TERMINAL:
        return
    for fmt, extension in [('json', 'json'), ('html', 'html'), ('markdown', 'md')]:
        item = result['reports'].setdefault(fmt, {'request_id': str(uuid.uuid4())})
        checkpoint()
        if 'report' not in item:
            item['report'] = api.rpc('ReportService', 'CreateReport', requestId=item['request_id'],
                                     runId=run['id'], format=fmt)['report']
            checkpoint()
        data = api.download(item['report']['artifactId'])
        (folder / ('report.' + extension)).write_bytes(data)
        item['sha256'] = hashlib.sha256(data).hexdigest()
        if fmt == 'json':
            checks = json.loads(data)['checks']
            result['report_checks'] = checks
            if any(checks.get(key) != 'NOT_RUN'
                   for key in ('fuzzing', 'runtime_verification', 'exploitation')):
                raise ValueError('Static report must not imply target execution')
        checkpoint()
    result['evidence_complete'] = True
    checkpoint()


def exercise(api, candidates, source_evidence, output, config, collect_only=False):
    path = output / 'summary.json'
    inputs = []
    for candidate in candidates:
        matches = [item for item in source_evidence if item['candidate']['id'] == candidate['id']]
        if len(matches) != 1:
            raise ValueError('Exactly one structure snapshot is required for ' + candidate['id'])
        evidence = matches[0]
        snapshot = api.rpc('ProjectService', 'GetSnapshot', snapshotId=evidence['snapshot_id'])['snapshot']
        verify_snapshot(candidate, evidence, snapshot)
        inputs.append({'candidate': candidate, 'snapshot_id': snapshot['id'],
                       'target_sha256': snapshot['targetSha256']})
    identity = {'server': api.base, 'inputs': inputs, 'config': config}
    if path.exists():
        document = json.loads(path.read_text(encoding='utf-8'))
        if document['identity'] != identity:
            raise ValueError('Server, target set or budget changed; use a new batch name')
    elif collect_only:
        raise ValueError('No saved batch to collect')
    else:
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        document = {'schema_version': 1, 'identity': identity, 'created_at': now(),
                    'checkout_revision': revision, 'scope': 'SOURCE_STATIC_AUDIT',
                    'formal_acceptance': False, 'results': [dict(item) for item in inputs]}

    def checkpoint():
        document['updated_at'] = now()
        save(path, document)

    checkpoint()
    for result in document['results']:
        if collect_only and not result.get('run_id'):
            continue
        start_candidate(api, result, config, checkpoint)
        deadline = time.monotonic() + config['timeoutSeconds'] + config['modelTimeoutSeconds'] + 120
        previous = None
        while True:
            run = api.rpc('RunService', 'GetRun', runId=result['run_id'])['run']
            if run.get('snapshotId') != result['snapshot_id'] or run.get('scope') != 'SECURITY_AUDIT':
                raise ValueError('Saved run does not belong to the expected source audit')
            summary = json.loads(run.get('summaryJson', '{}'))
            progress = (run['state'], summary.get('audited_unit_count', 0),
                        summary.get('finding_count', 0))
            if progress != previous:
                result['state'] = run['state']
                result['last_progress'] = list(progress)
                checkpoint()
                print(result['candidate']['id'] + ': ' + json.dumps(progress), flush=True)
                previous = progress
            if state(run['state']) in TERMINAL or collect_only:
                collect(api, result, run, output, checkpoint)
                break
            if time.monotonic() >= deadline:
                collect(api, result, run, output, checkpoint)
                raise TimeoutError('Client wait ended; run and request IDs are saved. Resume this batch; do not create another run.')
            time.sleep(5)
    return document


def exit_code(document):
    results = document['results']
    if not results or any(not item.get('evidence_complete') for item in results):
        return 2
    return 0 if all(state(item['state']) == 'COMPLETED'
                    and item.get('all_eligible_units_audited') for item in results) else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', default='http://127.0.0.1:7331')
    parser.add_argument('--batch', required=True)
    parser.add_argument('--candidate', action='append', help='Public candidate ID; default: both source candidates')
    parser.add_argument('--source-evidence', type=Path, default=STRUCTURE)
    parser.add_argument('--live-model', action='store_true', help='Allow real configured model calls')
    parser.add_argument('--collect-only', action='store_true', help='Export existing runs without starting new work')
    parser.add_argument('--max-model-calls', type=int, default=2000)
    parser.add_argument('--max-units', type=int, default=500)
    parser.add_argument('--max-tool-rounds', type=int, default=12)
    parser.add_argument('--timeout-seconds', type=int, default=3600)
    parser.add_argument('--model-timeout-seconds', type=int, default=180)
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}', args.batch):
        parser.error('Batch must be a plain identifier, not a path')
    if not args.collect_only and not args.live_model:
        parser.error('--live-model is required to start real source audits')
    for name, low, high in [('max_model_calls', 4, 2000), ('max_units', 1, 500),
                            ('max_tool_rounds', 1, 100), ('timeout_seconds', 60, 86400),
                            ('model_timeout_seconds', 30, 3600)]:
        if not low <= getattr(args, name) <= high:
            parser.error(f'{name} must be in {low}..{high}')
    catalog = json.loads(CATALOG.read_text(encoding='utf-8'))
    selected = set(args.candidate or [item['id'] for item in catalog])
    if not selected.issubset({item['id'] for item in catalog}):
        parser.error('Unknown source candidate ID')
    config = {'maxModelCalls': args.max_model_calls, 'maxUnits': args.max_units,
              'maxToolRounds': args.max_tool_rounds, 'timeoutSeconds': args.timeout_seconds,
              'modelTimeoutSeconds': args.model_timeout_seconds,
              'maxOutputTokens': 0, 'reasoningEffort': 'high'}
    output = ROOT / '.data/verification/candidate-audits' / args.batch
    document = exercise(API(args.server), [item for item in catalog if item['id'] in selected],
                        json.loads(args.source_evidence.read_text(encoding='utf-8')), output,
                        config, args.collect_only)
    print('Evidence: ' + str(output / 'summary.json'), flush=True)
    return exit_code(document)


if __name__ == '__main__':
    raise SystemExit(main())
