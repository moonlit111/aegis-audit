#!/usr/bin/env python3
"""Store a DeepSeek key locally with a non-echoing prompt; never writes a tracked file."""
import argparse
import getpass
import json
import os
from pathlib import Path
from aegis import ROOT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model', default='deepseek-v4-flash')
    parser.add_argument('--data-dir', type=Path, default=ROOT / '.data/server')
    options = parser.parse_args()
    key = getpass.getpass('DeepSeek API key (hidden): ').strip()
    if not key or any(character.isspace() for character in key):
        raise SystemExit('The key is empty or contains whitespace.')
    options.data_dir.mkdir(parents=True, exist_ok=True)
    if os.name != 'nt': options.data_dir.chmod(0o700)
    path = options.data_dir / 'deepseek.token'
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, 'w') as target:
        target.write(key)
    if os.name != 'nt': path.chmod(0o600)
    (options.data_dir / 'model.json').write_text(json.dumps({'model': options.model}, indent=2) + '\n', encoding='utf-8')
    print('DeepSeek configuration saved locally. Use Execution Environment to check the connection.')


if __name__ == '__main__':
    main()
