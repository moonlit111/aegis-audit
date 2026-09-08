"""Invoke one local Python function with JSON data. The supervisor owns the verdict."""
import asyncio
import importlib.util
import inspect
import json
import os
from pathlib import Path
import sys


def main():
    request = json.loads(Path(sys.argv[1]).read_text())
    target = (Path('/target') / request['path']).resolve()
    target.relative_to('/target')
    sys.path.insert(0, str(target.parent))
    spec = importlib.util.spec_from_file_location('aegis_target', target)
    module = importlib.util.module_from_spec(spec)
    result_fd = os.dup(1)
    # Target prints and inherited child stdout belong to the captured log, not the result envelope.
    os.dup2(2, 1)
    result = {'exception': '', 'value': ''}
    try:
        spec.loader.exec_module(module)
        for key, value in request['globals'].items():
            setattr(module, key, value)
        value = getattr(module, request['function'])(*request['args'], **request['kwargs'])
        if inspect.isawaitable(value):
            value = asyncio.run(value)
        result['value'] = json.dumps(value, ensure_ascii=False, default=str)[:65536]
    except BaseException as error:
        result['exception'] = type(error).__name__
        result['value'] = str(error)[:4096]
    sys.stdout.flush()
    os.write(result_fd, json.dumps(result, ensure_ascii=False).encode())
    os.close(result_fd)


if __name__ == '__main__':
    main()
