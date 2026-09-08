"""Trusted container supervisor for bounded local verification and fuzzing.

Only this script produces observations. The control service derives the verdict.
Imported programs and their children have no network or host filesystem access.
"""
import hashlib
import ctypes
import json
import os
from pathlib import Path
import random
import re
import secrets
import selectors
import shutil
import signal
import subprocess
import sys
import time

LIMIT = 65536
WORK = Path('/work')
CASE = WORK / 'case'


def descendants():
    parents = {}
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():
            continue
        try:
            stat = (path / 'stat').read_text().rsplit(')', 1)[1].split()
            parents[int(path.name)] = int(stat[1])
        except (OSError, ValueError, IndexError):
            continue
    owned = {os.getpid()}
    while True:
        found = {pid for pid, parent in parents.items() if parent in owned}
        if found.issubset(owned):
            return owned - {os.getpid()}
        owned.update(found)


def reap_children(process):
    # As a subreaper, also own descendants that started a new session or double-forked.
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        for pid in descendants():
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=0.1)
        except subprocess.TimeoutExpired:
            continue
        while True:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
                if pid == 0:
                    break
            except ChildProcessError:
                break
        if not descendants():
            return True
        time.sleep(0.01)
    return False


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(argv, timeout, stdin=b'', env=None, cwd=CASE):
    if sys.platform != 'linux' or ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) != 0:
        raise RuntimeError('Linux child subreaper could not be enabled')
    process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    selector = selectors.DefaultSelector()
    output = {'stdout': bytearray(), 'stderr': bytearray()}
    for name in output:
        stream = getattr(process, name)
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, name)
    os.set_blocking(process.stdin.fileno(), False)
    pending = memoryview(stdin)
    if pending:
        selector.register(process.stdin, selectors.EVENT_WRITE, 'stdin')
    else:
        process.stdin.close()
    deadline = time.monotonic() + timeout
    timed_out = truncated = False
    killed = False
    try:
        while selector.get_map() or process.poll() is None:
            if time.monotonic() >= deadline and process.poll() is None:
                timed_out = True
            if (timed_out or process.poll() is not None) and not killed:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                killed = True
            if killed and time.monotonic() >= deadline + 2:
                break
            for key, _ in selector.select(0.05):
                if key.data == 'stdin':
                    try:
                        count = os.write(key.fileobj.fileno(), pending[:4096])
                        pending = pending[count:]
                    except (BrokenPipeError, OSError):
                        pending = pending[:0]
                    if not pending:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                    continue
                try:
                    chunk = os.read(key.fileobj.fileno(), 8192)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                else:
                    data = output[key.data]
                    truncated |= len(data) + len(chunk) > LIMIT
                    data.extend(chunk[:max(0, LIMIT-len(data))])
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        reaped = reap_children(process)
        selector.close()
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()
    return {'exit_code': process.returncode, 'timed_out': timed_out, 'processes_reaped': reaped,
            'stdout': bytes(output['stdout']).decode('utf-8', errors='replace'),
            'stderr': bytes(output['stderr']).decode('utf-8', errors='replace'), 'truncated': truncated}


def replace(value, canary=''):
    if isinstance(value, str):
        return value.replace('{{work}}', str(CASE)).replace('{{canary}}', canary)
    if isinstance(value, list):
        return [replace(item, canary) for item in value]
    if isinstance(value, dict):
        return {key: replace(item, canary) for key, item in value.items()}
    return value


def reset_case(config, canary):
    if CASE.exists():
        shutil.rmtree(CASE)
    CASE.mkdir()
    for fixture in config['fixtures']:
        path = CASE / fixture['path']
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(replace(fixture['content'], canary), encoding='utf-8')


def runtime_env():
    return dict(os.environ, ASAN_OPTIONS='detect_leaks=0:abort_on_error=1:allocator_may_return_null=1',
                UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1', HOME='/tmp')


def prepare(config):
    source = (Path('/target') / config['path']).resolve()
    source.relative_to('/target')
    if not source.is_file():
        raise ValueError('configured target file is missing')
    info = {'status': 'READY', 'source_sha256': digest(source.read_bytes()), 'command': []}
    if config['adapter'] == 'PYTHON_CALL':
        return info
    executable = WORK / 'program'
    if config['adapter'] == 'ELF':
        if source.read_bytes()[:4] != b'\x7fELF':
            raise ValueError('the original-binary adapter requires ELF')
        shutil.copyfile(source, executable)
        executable.chmod(0o555)
    else:
        cpp = source.suffix != '.c'
        afl = config['mode'] == 'FUZZ' and config['fuzz']['engine'] == 'AFLPP'
        compiler = ('afl-clang-fast++' if cpp else 'afl-clang-fast') if afl else ('clang++' if cpp else 'clang')
        argv = [compiler, '-g', '-O1', '-fno-omit-frame-pointer', '-fno-optimize-sibling-calls',
                '-fsanitize=address,undefined', '-I/target', str(source), '-o', str(executable), '-lm']
        info['command'] = argv
        info['output'] = run(argv, 90, env=runtime_env(), cwd=WORK)
        if info['output']['exit_code'] != 0 or info['output']['timed_out']:
            info['status'] = 'ERROR'
            return info
    info['executable_sha256'] = digest(executable.read_bytes())
    return info


def crash_signature(output):
    if output['timed_out']:
        return ''
    text = output['stderr']
    match = re.search(r'(?:ERROR: AddressSanitizer:|SUMMARY: (?:AddressSanitizer|UndefinedBehaviorSanitizer):|runtime error:)\s*([^\n]+)', text)
    if match:
        # Remove process IDs, addresses and offsets; preserve the source location when reported.
        detail = re.sub(r'0x[0-9a-fA-F]+|==\d+==|\+0x[0-9a-fA-F]+', '?', match.group(0))
        location = re.search(r'/target/[^\s:]+:\d+(?::\d+)?', text)
        return detail[:400] + (' ' + location.group(0) if location else '')
    if output['exit_code'] in (-signal.SIGSEGV, -signal.SIGABRT, -signal.SIGBUS, -signal.SIGILL):
        return 'signal:' + str(-output['exit_code'])
    return ''


def trial(config, label):
    canary = 'aegis-' + secrets.token_hex(24)
    reset_case(config, canary)
    original = config[label]
    invocation = replace(original)
    stdin = invocation['stdin'].encode()
    if config['adapter'] == 'PYTHON_CALL':
        request = dict(path=config['path'], function=config['function'],
                       globals=replace(config['globals'], canary), args=invocation['args'], kwargs=invocation['kwargs'])
        request_path = WORK / 'invocation.json'
        request_path.write_text(json.dumps(request))
        output = run(['python3', '/runner/invoke.py', str(request_path)], config['timeout_seconds'], stdin, runtime_env())
        try:
            value = json.loads(output['stdout'])
            exception = value['exception']
            returned = value['value']
        except (ValueError, KeyError, TypeError):
            exception, returned = 'InvalidInvocationResult', ''
    else:
        output = run([str(WORK / 'program'), *invocation['args']], config['timeout_seconds'], stdin, runtime_env())
        exception, returned = '', output['stdout']
    if config['observer'] == 'RETURN_CANARY':
        observed = not exception and canary in returned
    elif config['observer'] == 'FILE_CREATED':
        marker = CASE / config['marker_path']
        observed = marker.is_file() and not marker.is_symlink() and marker.resolve().is_relative_to(CASE)
    else:
        observed = bool(crash_signature(output))
    # The fresh canary is excluded from archived output; its comparison was made by the supervisor.
    for key in ('stdout', 'stderr'):
        output[key] = output[key].replace(canary, '[CONTROLLED_CANARY]')
    input_json = json.dumps(original, sort_keys=True, ensure_ascii=False)
    return dict(output, label=label, input_json=input_json, input_sha256=digest(input_json.encode()),
                observed=observed, exception=exception, crash_signature=crash_signature(output))


def fuzz_command(config, data, afl=False):
    mode = config['fuzz']['input_mode']
    if mode == 'ARGUMENT':
        # Keep the actual recorded input identical to the bytes supplied to argv.
        argument = data.decode('utf-8', errors='replace').replace('\0', '_')
        data = argument.encode()
    elif mode == 'FILE':
        argument = '@@' if afl else str(CASE / 'input.bin')
        if not afl:
            (CASE / 'input.bin').write_bytes(data)
    else:
        argument = ''
    argv = [str(WORK / 'program'), *[replace(arg).replace('{{input}}', argument) for arg in config['baseline']['args']]]
    return argv, data if mode == 'STDIN' else b'', data


def mutated(seeds, number, rng):
    seed = seeds[number % len(seeds)]
    if number < len(seeds):
        return seed
    lengths = [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 1024, 8192]
    if number < len(seeds) + len(lengths):
        size = lengths[number-len(seeds)]
        return (seed * (size//len(seed)+1))[:size]
    value = bytearray(seed)
    op = rng.randrange(4)
    at = rng.randrange(len(value)+1)
    if op == 0:
        value[at:at] = bytes([rng.randrange(256)]) * rng.randint(1, 64)
    elif op == 1 and value:
        value[min(at, len(value)-1)] ^= 1 << rng.randrange(8)
    elif op == 2:
        del value[at:at+rng.randint(1, max(1, len(value)))]
    else:
        value.extend(value[:rng.randint(1, len(value))] * rng.randint(1, 64))
    return bytes(value[:65536])


def replay(config, data, timeout=None):
    reset_case(config, '')
    argv, stdin, data = fuzz_command(config, data)
    output = run(argv, timeout or config['timeout_seconds'], stdin, runtime_env())
    signature = crash_signature(output)
    record = dict(output, label='replay', input_json='', input_sha256=digest(data),
                  observed=bool(signature), exception='', crash_signature=signature)
    return signature, data, record


def minimize(config, data, signature, deadline):
    original = data
    chunk = max(1, len(data)//2)
    attempts = 0
    while chunk and attempts < 24 and time.monotonic() < deadline:
        changed = False
        for pos in range(0, len(data), chunk):
            candidate = data[:pos] + data[pos+chunk:]
            if not candidate or attempts >= 24 or time.monotonic() >= deadline:
                continue
            attempts += 1
            found, actual, _ = replay(config, candidate, min(config['timeout_seconds'], max(0.1, deadline-time.monotonic())))
            if found == signature:
                data, changed = actual, True
                break
        if not changed:
            chunk //= 2
    return data, data != original


def fuzz(config):
    options = config['fuzz']
    reset_case(config, '')
    start = time.monotonic()
    deadline = start + options['budget_seconds']
    seeds = [s.encode() for s in options['seeds']]
    crashes = {}
    stats = {'engine': options['engine'], 'coverage_feedback': options['engine'] == 'AFLPP',
             'executions': 0, 'timeouts': 0, 'random_seed': options['random_seed'], 'stop_reason': 'TIME_BUDGET'}
    if options['engine'] == 'AFLPP':
        corpus = WORK / 'seeds'
        corpus.mkdir()
        for index, seed in enumerate(seeds):
            (corpus / str(index)).write_bytes(seed)
        output_dir = WORK / 'afl'
        argv, _, _ = fuzz_command(config, b'', afl=True)
        env = dict(runtime_env(), AFL_NO_UI='1', AFL_SKIP_CPUFREQ='1', AFL_NO_AFFINITY='1',
                   AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES='1', AFL_FORKSRV_INIT_TMOUT='20000')
        # AFL++ requires symbolization disabled while fuzzing. Replays use the normal
        # environment again so retained diagnostics include actual source locations.
        env['ASAN_OPTIONS'] += ':symbolize=0'
        output = run(['afl-fuzz', '-i', str(corpus), '-o', str(output_dir), '-m', 'none',
                      '-t', str(config['timeout_seconds']*1000), '-V', str(options['budget_seconds']),
                      '-E', str(options['max_cases']), '--', *argv], options['budget_seconds']+30, env=env)
        stats['tool_output'] = output
        statistics = output_dir / 'default/fuzzer_stats'
        if not statistics.is_file():
            raise RuntimeError('AFL++ did not produce fuzzer_stats: ' + output['stderr'][-1200:] + output['stdout'][-1200:])
        raw = dict(line.split(':', 1) for line in statistics.read_text().splitlines() if ':' in line)
        raw = {key.strip(): value.strip() for key, value in raw.items()}
        stats.update(executions=int(raw.get('execs_done', 0)), timeouts=int(raw.get('saved_hangs', raw.get('unique_hangs', 0))),
                     bitmap_cvg=raw.get('bitmap_cvg', ''), edges_found=raw.get('edges_found', ''), raw_stats=raw)
        for path in sorted((output_dir/'default/crashes').glob('id:*'))[:16]:
            data = path.read_bytes()[:65536]
            signature, data, _ = replay(config, data)
            if signature:
                crashes.setdefault(signature, data)
    else:
        rng = random.Random(options['random_seed'])
        for number in range(options['max_cases']):
            if time.monotonic() >= deadline:
                break
            reset_case(config, '')
            argv, stdin, data = fuzz_command(config, mutated(seeds, number, rng))
            output = run(argv, min(config['timeout_seconds'], max(0.1, deadline-time.monotonic())), stdin, runtime_env())
            stats['executions'] += 1
            stats['timeouts'] += int(output['timed_out'])
            signature = crash_signature(output)
            if signature and len(crashes) < 16:
                crashes.setdefault(signature, data)
        else:
            stats['stop_reason'] = 'CASE_BUDGET'
    samples = []
    replay_deadline = time.monotonic() + 60
    for signature, data in crashes.items():
        data, minimized = minimize(config, data, signature, min(time.monotonic()+10, replay_deadline))
        replays = []
        for _ in range(2):
            if time.monotonic() >= replay_deadline:
                break
            _, data, record = replay(config, data, min(config['timeout_seconds'], max(0.1, replay_deadline-time.monotonic())))
            replays.append(record)
        reproduced = len(replays) == 2 and all(r['processes_reaped'] and not r['timed_out'] and not r['truncated']
                                                and r['observed'] and r['crash_signature'] == signature for r in replays)
        samples.append(dict(input_hex=data.hex(), input_sha256=digest(data), signature=signature,
                            reproduced=reproduced, minimized=minimized, replays=replays))
    stats.update(duration_ms=round((time.monotonic()-start)*1000), unique_crashes=len(samples))
    return stats, samples


def main():
    config = json.loads(Path(sys.argv[1]).read_text())
    result = dict(schema_version=1, mode=config['mode'], adapter=config['adapter'], path=config['path'],
                  build={}, trials=[], fuzz={}, crashes=[], error='')
    try:
        CASE.mkdir(exist_ok=True)
        result['build'] = prepare(config)
        if result['build']['status'] == 'ERROR':
            result['error'] = 'Target compilation failed; see the retained compiler output.'
        elif config['mode'] == 'VERIFY':
            result['trials'] = [trial(config, 'baseline')] + [trial(config, 'probe') for _ in range(config['repeats'])]
        else:
            result['fuzz'], result['crashes'] = fuzz(config)
    except Exception as error:
        result['error'] = type(error).__name__ + ': ' + str(error)[:3000]
    print(json.dumps(result, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
