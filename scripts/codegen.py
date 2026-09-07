#!/usr/bin/env python3
"""Generate both Connect clients from the single protobuf contract."""
import argparse
import hashlib
import subprocess
from aegis import ROOT, environment


def snapshot():
    paths = [ROOT / 'crates/protocol/src/generated', ROOT / 'frontend/src/gen']
    return {str(file.relative_to(ROOT)): hashlib.sha256(file.read_bytes()).hexdigest()
            for directory in paths for file in directory.rglob('*') if file.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    options = parser.parse_args()
    before = snapshot()
    subprocess.run(['buf', 'lint'], cwd=ROOT, env=environment(), check=True)
    subprocess.run(['buf', 'generate'], cwd=ROOT, env=environment(), check=True)
    after = snapshot()
    if options.check and before != after:
        changed = sorted(key for key in before.keys() | after.keys() if before.get(key) != after.get(key))
        raise SystemExit('Generated files were stale; regenerate and commit:\n' + '\n'.join(changed))
    print('Protocol generation is reproducible.' if options.check else 'Rust and TypeScript protocol files generated.')


if __name__ == '__main__':
    main()
