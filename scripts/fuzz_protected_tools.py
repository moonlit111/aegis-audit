#!/usr/bin/env python3
"""Mutation-fuzz the four frozen acceptance binaries on the Windows host.

Each target gets a seed corpus, a mutation loop and an explicit security oracle
(the property the program must uphold). A hit is deduplicated by signature,
shrunk with delta debugging, then replayed twice before it is archived. This is
a standalone campaign: the product's own FUZZ mode only accepts prebuilt
libFuzzer targets, which these shipped PEs are not.

Usage:
  py -3 scripts/fuzz_protected_tools.py --batch fuzz-20260911 --iterations 4000
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import random
import shutil
import subprocess
import sys
import time

from aegis import ROOT


CRASH_STATUS = {0xC0000005, 0xC000001D, 0xC00000FD, 0xC0000374, 0xC0000409}
BUILD_BATCH = 'protected-tools-20260911-r3'


def status_of(code: int) -> str:
    return format(code & 0xFFFFFFFF, '08X')


def text(data: bytes) -> str:
    return data.decode('utf-8', 'replace')


class Target:
    """One frozen binary plus the corpus, mutator inputs and oracle it needs."""

    def __init__(self, ident, name, seed_files, seeds, dictionary, kind):
        self.id = ident
        self.name = name
        self.seed_files = seed_files
        self.seeds = seeds
        self.dictionary = dictionary
        self.kind = kind

    @property
    def binary(self) -> Path:
        return ROOT / '.data/verification/protected-tools' / BUILD_BATCH / 'targets' / self.id / '1.0.0' / self.name

    def prepare(self, work: Path) -> None:
        work.mkdir(parents=True, exist_ok=True)
        for name, content in self.seed_files.items():
            (work / name).write_text(content, encoding='utf-8', newline='')

    def reset(self, work: Path, keep: set[str]) -> None:
        for item in work.iterdir():
            if item.name in keep:
                continue
            if item.is_dir():
                shutil.rmtree(item, ignore_errors=True)
            else:
                item.unlink(missing_ok=True)

    def execute(self, work: Path, data: bytes) -> dict:
        raise NotImplementedError

    def oracle(self, observation: dict) -> str:
        raise NotImplementedError


class ParcelDrop(Target):
    def execute(self, work: Path, data: bytes) -> dict:
        name = text(data)
        completed = subprocess.run(
            [str(self.binary), 'inbox', name, 'payload.txt'], cwd=work, capture_output=True,
            text=True, encoding='utf-8', errors='replace', timeout=20, check=False)
        outside = sorted(item.name for item in work.iterdir()
                         if item.is_file() and item.name not in self.seed_files)
        return {'exit_code': completed.returncode, 'outside_files': outside}

    def oracle(self, observation: dict) -> str | None:
        return 'PATH_TRAVERSAL:file-outside-inbox' if observation['outside_files'] else None


class RowVault(Target):
    def execute(self, work: Path, data: bytes) -> dict:
        (work / 'record.rv').write_bytes(data)
        completed = subprocess.run(
            [str(self.binary), 'record.rv'], cwd=work, capture_output=True, text=True,
            encoding='utf-8', errors='replace', timeout=20, check=False)
        return {'exit_code': completed.returncode, 'status': status_of(completed.returncode)}

    def oracle(self, observation: dict) -> str | None:
        return ('MEMORY_BOUNDS:crash-' + observation['status']
                if (observation['exit_code'] & 0xFFFFFFFF) in CRASH_STATUS else None)


class PermitLedger(Target):
    def execute(self, work: Path, data: bytes) -> dict:
        role = text(data)
        completed = subprocess.run(
            [str(self.binary), 'account.txt', 'alice', 'secret', role, 'export',
             'record.txt', 'exported.txt'],
            cwd=work, capture_output=True, text=True, encoding='utf-8', errors='replace',
            timeout=20, check=False)
        return {'exit_code': completed.returncode, 'exported': (work / 'exported.txt').is_file()}

    def oracle(self, observation: dict) -> str | None:
        return 'AUTHORIZATION:export-with-forged-role' if observation['exported'] else None


class TextRelay(Target):
    def execute(self, work: Path, data: bytes) -> dict:
        document = text(data)
        completed = subprocess.run(
            [str(self.binary), document], cwd=work, capture_output=True, text=True,
            encoding='utf-8', errors='replace', timeout=20, check=False)
        created = sorted(item.name for item in work.iterdir()
                         if item.is_file() and item.name not in self.seed_files
                         and item.name != 'relay.txt')
        return {'exit_code': completed.returncode, 'injected_files': created}

    def oracle(self, observation: dict) -> str | None:
        return 'INJECTION:extra-file-created' if observation['injected_files'] else None


TARGETS = [
    ParcelDrop('P1', 'ParcelDrop.exe', {'payload.txt': 'parcel'},
               ['entry.txt', 'a.txt', 'report.txt'],
               ['.', '\\\\', '/', '..', ':', 'entry.txt'], 'text'),
    RowVault('P2', 'RowVault.exe', {},
             ['RV1 ' + 'A' * 32, 'RV1\x08' + 'D' * 8, 'RV1\x10' + 'E' * 16],
             [], 'binary'),
    PermitLedger('O1', 'PermitLedger.exe',
                 {'account.txt': 'alice|secret|guest', 'record.txt': 'ledger-entry'},
                 ['guest', 'user', 'alice', 'operator'],
                 ['admin', 'root', 'guest', ' '], 'text'),
    TextRelay('O2', 'TextRelay.exe', {'doc.txt': 'report-body'},
              ['doc.txt', 'report.txt', 'a.doc'],
              ['&', '|', '>', 'echo', 'whoami', 'cmd', '/c', '.txt'], 'text'),
]


def mutate(data: bytes, rng: random.Random, dictionary: list[str], kind: str) -> bytes:
    if kind == 'binary' and rng.random() < 0.35:
        # Grammar-aware record: the format is magic "RV1", one length byte, then
        # exactly that many payload bytes. Any other shape is rejected before the
        # interesting code path, so a structure-aware mutation is what a fuzzer
        # needs here; the length value itself stays uniformly random.
        count = rng.randrange(256)
        payload = bytes(rng.choice(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(count))
        return b'RV1' + bytes([count]) + payload
    if kind == 'text' and dictionary and rng.random() < 0.25:
        # Dictionary-only mutation: try a vocabulary token as the whole input.
        return rng.choice(dictionary).encode('utf-8')
    result = bytearray(data)
    operations = rng.randint(1, 3)
    for _ in range(operations):
        choice = rng.random()
        if choice < 0.25 and dictionary:
            token = rng.choice(dictionary).encode('utf-8')
            position = rng.randrange(0, len(result) + 1)
            result[position:position] = token
        elif choice < 0.45 and len(result) > 1:
            del result[rng.randrange(len(result))]
        elif choice < 0.65 and result:
            result[rng.randrange(len(result))] = rng.randrange(256)
        elif choice < 0.8 and result:
            position = rng.randrange(len(result))
            result.insert(position, result[position])
        elif choice < 0.9 and len(result) > 2:
            start = rng.randrange(len(result) - 1)
            end = rng.randrange(start + 1, len(result))
            del result[start:end]
        elif result:
            position = rng.randrange(len(result))
            result[position:position] = bytes([rng.choice(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                                                         b'abcdefghijklmnopqrstuvwxyz0123456789'
                                                         b' .\\\\/:&|<>%$"\'-_')])
        if kind == 'text' and len(result) > 256:
            del result[256:]
        if kind == 'binary' and len(result) > 4096:
            del result[4096:]
    if kind == 'text':
        # A Windows command line cannot carry a NUL byte; drop them instead of
        # letting the spawn fail.
        result = bytearray(value for value in result if value != 0)
    return bytes(result)


def delta_debug(target: Target, work: Path, data: bytes, signature: str, keep: set[str]) -> bytes:
    """Shrink an input that still triggers the same oracle signature."""
    best = data
    granularity = max(2, len(best) // 2)
    while len(best) > 1:
        changed = False
        chunk = max(1, len(best) // granularity)
        for start in range(0, len(best), chunk):
            candidate = best[:start] + best[start + chunk:]
            if not candidate:
                continue
            target.reset(work, keep)
            try:
                observation = target.execute(work, candidate)
            except (subprocess.TimeoutExpired, ValueError, OSError):
                continue
            if target.oracle(observation) == signature:
                best = candidate
                changed = True
                break
        if not changed:
            if granularity >= len(best):
                break
            granularity = min(len(best), granularity * 2)
    return best


def campaign(target: Target, work_root: Path, iterations: int, seed: int, output: Path) -> dict:
    work = work_root / target.id
    target.prepare(work)
    keep = set(target.seed_files)
    rng = random.Random(seed)
    corpus = [item.encode('utf-8') for item in target.seeds]
    hits: dict[str, dict] = {}
    executed = 0
    started = time.monotonic()
    # Every fuzzer runs its seed corpus first; a seed that already violates the
    # property is reported with found_at_iteration 0.
    for seed_index, seed in enumerate(target.seeds):
        target.reset(work, keep)
        try:
            observation = target.execute(work, seed.encode('utf-8'))
        except (subprocess.TimeoutExpired, ValueError, OSError):
            continue
        executed += 1
        signature = target.oracle(observation)
        if signature:
            hits.setdefault(signature, {'input': seed.encode('utf-8'),
                                        'observation': observation, 'iteration': 0})
    for index in range(iterations):
        base = corpus[rng.randrange(len(corpus))]
        data = mutate(base, rng, target.dictionary, target.kind)
        target.reset(work, keep)
        try:
            observation = target.execute(work, data)
        except (subprocess.TimeoutExpired, ValueError, OSError):
            continue
        executed += 1
        signature = target.oracle(observation)
        if not signature:
            if rng.random() < 0.02:
                corpus.append(data)
                del corpus[:max(0, len(corpus) - 64)]
            continue
        record = hits.get(signature)
        if record is None or len(data) < len(record['input']):
            hits[signature] = {'input': data, 'observation': observation,
                               'iteration': index + 1}
    results = []
    for signature, record in hits.items():
        target.reset(work, keep)
        minimized = delta_debug(target, work, record['input'], signature, keep)
        replays = []
        for attempt in range(2):
            target.reset(work, keep)
            try:
                observation = target.execute(work, minimized)
            except (subprocess.TimeoutExpired, ValueError, OSError) as error:
                observation = {'exit_code': None, 'error': str(error)}
            replays.append({'attempt': attempt + 1, 'observed': target.oracle(observation),
                            'exit_code': observation['exit_code']})
        folder = output / 'findings'
        folder.mkdir(parents=True, exist_ok=True)
        (folder / f'{target.id}-{signature.split(":")[0].lower()}.bin').write_bytes(minimized)
        results.append({
            'signature': signature,
            'found_at_iteration': record['iteration'],
            'original_size': len(record['input']),
            'minimized_size': len(minimized),
            'minimized_hex': minimized.hex(),
            'minimized_text': text(minimized) if target.kind == 'text' else '',
            'minimized_sha256': hashlib.sha256(minimized).hexdigest(),
            'replays_reproduced': sum(1 for item in replays if item['observed'] == signature),
            'replays': replays,
        })
    elapsed = time.monotonic() - started
    return {
        'id': target.id,
        'target': str(target.binary.relative_to(ROOT)),
        'target_sha256': hashlib.sha256(target.binary.read_bytes()).hexdigest(),
        'kind': target.kind,
        'seeds': target.seeds,
        'dictionary': target.dictionary,
        'iterations_requested': iterations,
        'executions': executed,
        'seconds': round(elapsed, 2),
        'executions_per_second': round(executed / elapsed, 1) if elapsed else 0,
        'signatures': sorted(hits),
        'findings': results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--batch', default='fuzz-' + time.strftime('%Y%m%d-%H%M%S'))
    parser.add_argument('--iterations', type=int, default=4000)
    parser.add_argument('--seed', type=int, default=20260911)
    parser.add_argument('--target', action='append', help='Limit to one target ID; repeatable')
    options = parser.parse_args()
    if Path(options.batch).name != options.batch:
        parser.error('--batch must be a single directory name')
    output = ROOT / '.data/verification/fuzz-protected' / options.batch
    output.mkdir(parents=True, exist_ok=True)
    selected = [item for item in TARGETS if not options.target or item.id in options.target]
    results = []
    for target in selected:
        if not target.binary.is_file():
            print(target.id + ': missing binary ' + str(target.binary), flush=True)
            continue
        report = campaign(target, output / 'work', options.iterations, options.seed
                          + sum(ord(char) for char in target.id), output)
        results.append(report)
        print(target.id + ' ' + target.name + ': ' + json.dumps(
            {'executions': report['executions'], 'per_second': report['executions_per_second'],
             'signatures': report['signatures'],
             'minimized': [item['minimized_text'] or item['minimized_hex'][:32]
                           for item in report['findings']]}), flush=True)
    document = {
        'schema_version': 1,
        'batch': options.batch,
        'created_at': datetime.now(timezone.utc).isoformat(),
        'platform': 'windows/x64',
        'scope': 'MUTATION_FUZZING',
        'method': 'Seed corpus plus dictionary-assisted byte mutation executed against the frozen binaries; hits are deduplicated by oracle signature, shrunk with delta debugging and replayed twice.',
        'build_batch': BUILD_BATCH,
        'random_seed': options.seed,
        'targets': results,
        'limitations': [
            'Standalone host campaign, not the product FUZZ path (which accepts prebuilt libFuzzer targets only).',
            'No coverage feedback: mutations are corpus and dictionary driven, so the numbers are executions, not edge coverage.',
            'Each oracle encodes the security property the program must uphold; a hit proves that property was violated, not that remote code execution is possible.',
        ],
    }
    path = output / 'summary.json'
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    found = sum(len(item['findings']) for item in results)
    print(json.dumps({'targets': len(results), 'findings': found, 'evidence': str(path)},
                     ensure_ascii=False))
    return 0 if found else 1


if __name__ == '__main__':
    sys.exit(main())
