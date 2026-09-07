#!/usr/bin/env python3
"""Import pinned public software source for structure testing, with no vulnerability answers."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tests'))
from smoke import API


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', default='http://127.0.0.1:7331')
    args = parser.parse_args()
    api = API(args.server)
    candidates = json.loads((ROOT / 'evaluation/targets/structure-candidates.json').read_text(encoding='utf-8'))
    results = []
    for candidate in candidates:
        print('Importing ' + candidate['name'], flush=True)
        project = api.rpc('ProjectService', 'CreateProject', requestId=str(uuid.uuid4()), name=candidate['name'] + ' · 结构调研')['project']
        snapshot = api.rpc('ProjectService', 'CreateSnapshot', requestId=str(uuid.uuid4()), projectId=project['id'], kind='TARGET_KIND_GIT', gitUrl=candidate['url'], gitRevision=candidate['revision'], name=candidate['name'] + ' @ ' + candidate['revision'][:8])['snapshot']
        snapshot = api.wait('ProjectService', 'GetSnapshot', 'snapshot', ('READY', 'PARTIAL'), snapshotId=snapshot['id'])
        assert snapshot['resolvedRevision'] == candidate['revision']
        run = api.rpc('RunService', 'CreateRun', requestId=str(uuid.uuid4()), snapshotId=snapshot['id'])['run']
        run = api.wait('RunService', 'GetRun', 'run', ('COMPLETED', 'PARTIAL'), runId=run['id'])
        summary = json.loads(run['summaryJson'])
        report = api.rpc('ReportService', 'CreateReport', requestId=str(uuid.uuid4()), runId=run['id'], format='json')['report']
        document = json.loads(api.download(report['artifactId']))
        assert document['checks']['exploitation'] == 'NOT_RUN'
        statuses = {}
        for file in summary['files']:
            statuses[file['status']] = statuses.get(file['status'], 0) + 1
        result = {'candidate': candidate, 'checked_at': datetime.now(timezone.utc).isoformat(), 'scope': 'STRUCTURE_ANALYSIS', 'snapshot_id': snapshot['id'], 'run_id': run['id'], 'state': run['state'], 'target_sha256': snapshot['targetSha256'], 'files': int(snapshot['fileCount']), 'units': int(run.get('unitCount', 0)), 'functions': summary['function_count'], 'calls': summary['edge_count'], 'coverage': statuses, 'vulnerability_audit': 'NOT_RUN', 'exploitation': 'NOT_RUN', 'formal_acceptance': False}
        results.append(result)
        print(json.dumps(result, ensure_ascii=False), flush=True)
    path = ROOT / '.data/verification/candidate-structure.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(results, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
