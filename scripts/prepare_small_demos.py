#!/usr/bin/env python3
"""Measure pinned, complete source repositories and prepare local structure demos.

This does not execute target code, download model weights, call an audit model,
or count a demo as formal vulnerability/exploitation acceptance.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import urllib.request
import uuid
import zipfile

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tests'))
from smoke import API

CATALOG = ROOT / 'evaluation/targets/small-demos.json'
OUTPUT = ROOT / '.data/verification/small-demos.json'
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_EXPANDED_BYTES = 128 * 1024 * 1024
SOURCE_SUFFIXES = {'.py', '.go', '.c', '.h', '.cc', '.cpp', '.cxx', '.hpp'}


def measure_archive(data, expected_root):
    """Count physical source lines once per file, not overlapping parser units."""
    sources = []
    paths = set()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        if len(entries) > 20_000 or sum(item.file_size for item in entries) > MAX_EXPANDED_BYTES:
            raise ValueError('Repository archive exceeds the demo size limit')
        for item in entries:
            path = PurePosixPath(item.filename)
            if (path.is_absolute() or not path.parts or path.parts[0] != expected_root
                    or '..' in path.parts or '\\' in item.orig_filename or ':' in item.orig_filename
                    or stat.S_ISLNK(item.external_attr >> 16)):
                raise ValueError('Unexpected or unsafe repository archive entry')
            if item.is_dir():
                continue
            relative = PurePosixPath(*path.parts[1:]).as_posix()
            if relative in paths or relative == '.':
                raise ValueError('Duplicate or empty repository archive entry')
            paths.add(relative)
            if path.suffix.lower() in SOURCE_SUFFIXES:
                if item.file_size > 4 * 1024 * 1024:
                    raise ValueError('Source file exceeds the demo size limit')
                content = archive.read(item)
                lines = content.decode('utf-8-sig').splitlines()
                sources.append({
                    'path': relative,
                    'bytes': len(content),
                    'lines': len(lines),
                    'nonblank_lines': sum(bool(line.strip()) for line in lines),
                    'sha256': hashlib.sha256(content).hexdigest(),
                })
    if not sources:
        raise ValueError('Repository has no supported source files')
    return {
        'archive_files': len(paths),
        'source_files': len(sources),
        'source_bytes': sum(item['bytes'] for item in sources),
        'source_lines': sum(item['lines'] for item in sources),
        'source_nonblank_lines': sum(item['nonblank_lines'] for item in sources),
        'line_metric': 'physical lines including comments and blanks, all supported source files',
        'files': sorted(sources, key=lambda item: item['path']),
    }


def prepare(candidate):
    revision = candidate['revision']
    repository = candidate['repository']
    if not re.fullmatch(r'[0-9a-f]{40}', revision) or not re.fullmatch(r'[\w.-]+/[\w.-]+', repository):
        raise ValueError('Demo repositories must be pinned to full commit IDs')
    name = repository.split('/')[1]
    archive = ROOT / '.data/demo-samples/small' / f'{name}-{revision}.zip'
    url = f'https://codeload.github.com/{repository}/zip/{revision}'
    if archive.exists():
        if archive.stat().st_size > MAX_ARCHIVE_BYTES:
            raise ValueError('Cached archive exceeds the demo size limit')
        data = archive.read_bytes()
    else:
        request = urllib.request.Request(url, headers={'User-Agent': 'AegisAudit-demo-preparation'})
        with urllib.request.urlopen(request, timeout=120) as response:
            data = response.read(MAX_ARCHIVE_BYTES + 1)
        if len(data) > MAX_ARCHIVE_BYTES:
            raise ValueError('Downloaded archive exceeds the demo size limit')
    metrics = measure_archive(data, f'{name}-{revision}')
    if metrics['source_lines'] > candidate['max_source_lines']:
        raise ValueError(f'{name} exceeds its declared small-source limit')
    if not archive.exists():
        archive.parent.mkdir(parents=True, exist_ok=True)
        archive.write_bytes(data)
    return {
        'candidate': candidate,
        'archive': archive.relative_to(ROOT).as_posix(),
        'archive_url': url,
        'archive_sha256': hashlib.sha256(data).hexdigest(),
        'metrics': metrics,
        'target_executed': False,
        'model_weights_downloaded': False,
        'vulnerability_audit': 'NOT_RUN',
        'exploitation': 'NOT_RUN',
        'formal_acceptance': False,
    }


def save(document):
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(document, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', default='http://127.0.0.1:7331')
    parser.add_argument('--prepare-only', action='store_true')
    args = parser.parse_args()
    base = args.server.rstrip('/')
    document = json.loads(OUTPUT.read_text(encoding='utf-8')) if OUTPUT.exists() else {}
    if document.get('server') != base:
        document = {'server': base, 'results': []}
    api = None if args.prepare_only else API(base)
    for candidate in json.loads(CATALOG.read_text(encoding='utf-8')):
        measured = prepare(candidate)
        result = next((item for item in document['results']
                       if item['candidate'] == candidate), None)
        if result is None:
            result = measured
            document['results'].append(result)
        elif result['archive_sha256'] != measured['archive_sha256']:
            raise ValueError('Cached demo archive changed; existing evidence was not overwritten')
        save(document)
        if api:
            if not result.get('project_id'):
                project = api.rpc('ProjectService', 'CreateProject', requestId=str(uuid.uuid4()),
                                  name=candidate['name'] + ' | small source demo')['project']
                result['project_id'] = project['id']
                save(document)
            if not result.get('snapshot_id'):
                snapshot = api.rpc('ProjectService', 'CreateSnapshot', requestId=str(uuid.uuid4()),
                                   projectId=result['project_id'], kind='TARGET_KIND_GIT',
                                   gitUrl=f'https://github.com/{candidate["repository"]}.git',
                                   gitRevision=candidate['revision'],
                                   name=f'{candidate["name"]} @ {candidate["revision"][:8]}')['snapshot']
                result['snapshot_id'] = snapshot['id']
                save(document)
            snapshot = api.wait('ProjectService', 'GetSnapshot', 'snapshot', ('READY', 'PARTIAL'),
                                timeout=600, snapshotId=result['snapshot_id'])
            if snapshot['resolvedRevision'] != candidate['revision']:
                raise ValueError('Imported revision does not match the pinned source')
            result['target_sha256'] = snapshot['targetSha256']
            if not result.get('run_id'):
                run = api.rpc('RunService', 'CreateRun', requestId=str(uuid.uuid4()),
                              snapshotId=result['snapshot_id'], scope='STRUCTURE_ANALYSIS')['run']
                result['run_id'] = run['id']
                save(document)
            run = api.wait('RunService', 'GetRun', 'run', ('COMPLETED', 'PARTIAL'),
                           timeout=600, runId=result['run_id'])
            summary = json.loads(run['summaryJson'])
            result.update({
                'state': run['state'],
                'units': int(run.get('unitCount', 0)),
                'functions': summary['function_count'],
                'unparsed_source_files': [item for item in summary['files']
                                          if item['status'] not in ('PARSED', 'NOT_SOURCE')],
                'warnings': summary.get('warnings', []),
                'url': f'{base}/#/runs/{run["id"]}',
            })
        result['checked_at'] = datetime.now(timezone.utc).isoformat()
        save(document)
        print(json.dumps({key: value for key, value in result.items() if key != 'metrics'}
                         | {'source_files': result['metrics']['source_files'],
                            'source_lines': result['metrics']['source_lines']}, ensure_ascii=True), flush=True)


if __name__ == '__main__':
    main()
