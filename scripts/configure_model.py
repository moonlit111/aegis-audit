#!/usr/bin/env python3
"""Store a DeepSeek key locally with a non-echoing prompt; never writes a tracked file."""
import argparse
import getpass
import json
import os
from pathlib import Path
import sys
import tempfile
from aegis import ROOT, require_windows
from windows_secrets import protect_secret


def atomic_write(path, value):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                                         prefix='credential-', suffix='.tmp', delete=False) as output:
            temporary = Path(output.name)
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def save_settings(data_dir, key, model):
    require_windows()
    key = key.strip()
    model = model.strip()
    if not key or len(key) > 4096 or any(character.isspace() for character in key):
        raise ValueError('The key is empty, too long or contains whitespace.')
    if not model.startswith('deepseek-') or len(model) > 100 or any(character.isspace() for character in model):
        raise ValueError('Use an official DeepSeek model identifier.')
    protected = protect_secret(key)
    data_dir.mkdir(parents=True, exist_ok=True)
    atomic_write(data_dir / 'model.json', json.dumps({'model': model}, indent=2) + '\n')
    atomic_write(data_dir / 'deepseek.token', protected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model', default='deepseek-v4-flash')
    parser.add_argument('--data-dir', type=Path, default=ROOT / '.data/server')
    parser.add_argument('--stdin', action='store_true', help='Read the key from a private stdin pipe instead of an interactive prompt')
    options = parser.parse_args()
    key = sys.stdin.readline().strip() if options.stdin else getpass.getpass('DeepSeek API key (hidden): ').strip()
    try:
        save_settings(options.data_dir, key, options.model)
    except ValueError as error:
        raise SystemExit(str(error)) from error
    print('DeepSeek configuration saved locally. Use Execution Environment to check the connection.')


if __name__ == '__main__':
    main()
