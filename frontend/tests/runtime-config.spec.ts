import { create } from '@bufbuild/protobuf';
import { expect, test } from '@playwright/test';
import {
  ProgramUnitSchema,
  RuntimeRecordSchema,
  SnapshotSchema,
  TargetKind,
} from '../src/gen/audit/v1/audit_pb';
import {
  fuzzConfigError,
  matchingRuntime,
  readRuntimeConfig,
  runtimeConfigKey,
  runtimeTemplate,
  supportsFuzz,
  withRuntimeDefaults,
} from '../src/lib/runtime';

const snapshot = (format = 'PE', architecture = 'x86_64', name = 'target.exe', kind = TargetKind.BINARY) =>
  create(SnapshotSchema, { name, kind, metadataJson: JSON.stringify({ format, architecture }) });
const configuration = () =>
  readRuntimeConfig(runtimeTemplate('WINDOWS_LIBFUZZER_PREBUILT', 'FUZZ', undefined, snapshot()))!;

test('runtime config: fuzz eligibility is limited to x86/x64 PE executables', () => {
  expect(supportsFuzz(snapshot())).toBe(true);
  expect(supportsFuzz(snapshot('PE', 'x86', 'TARGET.EXE'))).toBe(true);
  for (const target of [
    undefined,
    snapshot('ELF'),
    snapshot('PE', 'aarch64'),
    snapshot('PE', ''),
    snapshot('PE', 'x86_64', 'target.dll'),
    snapshot('PE', 'x86_64', 'target.exe', TargetKind.SOURCE),
  ])
    expect(supportsFuzz(target)).toBe(false);
});

test('runtime config: templates use the immutable binary name, not a decompiled source path', () => {
  const unit = create(ProgramUnitSchema, { name: 'entry', language: 'c', path: 'decompiled/entry.c' });
  const config = readRuntimeConfig(runtimeTemplate('WINDOWS_ORIGINAL_PE64', 'FUZZ', unit, snapshot()))!;
  expect(config.path).toBe('target.exe');
  expect(config.adapter).toBe('WINDOWS_LIBFUZZER_PREBUILT');
  expect(config.observer).toBe('SANITIZER');
  expect(fuzzConfigError(config)).toBe('');
  expect(readRuntimeConfig(runtimeTemplate('WINDOWS_NATIVE_SOURCE', 'VERIFY', unit))?.path).toBe(unit.path);
});

test('runtime config: defaulted fields match persisted recipes without changing the draft', () => {
  const config = {
    mode: 'FUZZ',
    adapter: 'WINDOWS_LIBFUZZER_PREBUILT',
    path: 'target.exe',
    fuzz: { engine: 'LLVM_LIBFUZZER', input_mode: 'FILE' },
  };
  const original = JSON.stringify(config);
  expect(fuzzConfigError(config)).toBe('');
  const persisted = withRuntimeDefaults(config);
  expect(persisted.fuzz).toMatchObject({
    seeds: ['hello'],
    max_cases: 256,
    budget_seconds: 30,
    random_seed: 71413,
  });
  expect(runtimeConfigKey(config)).toBe(runtimeConfigKey(persisted));
  expect(JSON.stringify(config)).toBe(original);
  const records = ['NO_CRASH_OBSERVED', 'RUNNING', 'CANCELLED'].map((status, index) =>
    create(RuntimeRecordSchema, {
      id: String(index),
      findingId: 'finding',
      status,
      configJson: JSON.stringify(persisted),
    }),
  );
  expect(matchingRuntime(records, 'finding', config)?.status).toBe('RUNNING');
  expect(matchingRuntime(records, '', config)).toBeUndefined();
  expect(matchingRuntime(records, 'finding', { ...config, mode: 'VERIFY' })).toBeUndefined();
});

test('runtime config: malformed JSON is not treated as a configuration object', () => {
  for (const json of ['', '{', 'null', '[]', 'true', '7', '"config"']) {
    expect(readRuntimeConfig(json)).toBeNull();
    expect(fuzzConfigError(readRuntimeConfig(json))).not.toBe('');
  }
});

test('runtime config: reject unsafe paths, unsupported fields and malformed nested values', () => {
  const config = configuration();
  for (const value of [
    '',
    '../target.exe',
    '/target.exe',
    'C:/target.exe',
    'dir\\target.exe',
    './target.exe',
    'dir//target.exe',
    'target\n.exe',
    'target\0.exe',
    'target.dll',
    'a'.repeat(513) + '.exe',
    null,
  ]) {
    expect(fuzzConfigError({ ...config, path: value })).not.toBe('');
  }
  for (const patch of [
    { adapter: 'WINDOWS_ORIGINAL_PE64' },
    { mode: 'VERIFY' },
    { observer: 'FILE_CREATED' },
    { marker_path: '../marker.txt' },
    { marker_path: null },
    { shell: 'not-supported' },
    { function: false },
    { function: 'entry' },
    { globals: [] },
    { globals: null },
    { globals: { x: 1 } },
    { fixtures: {} },
    { fixtures: null },
    { fixtures: [{ path: 'input', content: 'seed' }] },
    { baseline: null },
    { baseline: [] },
    { baseline: { args: {} } },
    { baseline: { args: ['seed'] } },
    { baseline: { kwargs: [] } },
    { baseline: { stdin: null } },
    { probe: { stdin: 'seed' } },
    { probe: { unknown: '' } },
    { repeats: null },
    { repeats: 1 },
    { repeats: 6 },
    { timeout_seconds: null },
    { timeout_seconds: 0 },
    { timeout_seconds: 16 },
  ])
    expect(fuzzConfigError({ ...config, ...patch })).not.toBe('');
  for (const fuzz of [
    null,
    [],
    'fuzz',
    {},
    { engine: 'AFLPP', input_mode: 'FILE' },
    { engine: 'LLVM_LIBFUZZER', input_mode: 'STDIN' },
    { ...(config.fuzz as object), unknown: 1 },
  ]) {
    expect(fuzzConfigError({ ...config, fuzz })).not.toBe('');
  }
  expect(fuzzConfigError({ ...config, path: 'subdir/TARGET.EXE', marker_path: 'marker.txt' })).toBe('');
});

test('runtime config: validate numeric limits, UTF-8 seed sizes and total serialized size', () => {
  const config = configuration();
  const fuzz = config.fuzz as Record<string, unknown>;
  for (const [field, max] of [
    ['max_cases', 1_000_000],
    ['budget_seconds', 900],
    ['random_seed', Number.MAX_SAFE_INTEGER],
  ] as const) {
    for (const value of [0, -1, 1.5, max + 1, null, '1']) {
      expect(fuzzConfigError({ ...config, fuzz: { ...fuzz, [field]: value } })).not.toBe('');
    }
    for (const value of [1, max])
      expect(fuzzConfigError({ ...config, fuzz: { ...fuzz, [field]: value } })).toBe('');
  }
  for (const seeds of [
    [],
    [''],
    [null],
    [1],
    ['{{placeholder}}'],
    Array(33).fill('seed'),
    ['\u00e9'.repeat(4097)],
  ]) {
    expect(fuzzConfigError({ ...config, fuzz: { ...fuzz, seeds } })).not.toBe('');
  }
  expect(fuzzConfigError({ ...config, fuzz: { ...fuzz, seeds: ['\u00e9'.repeat(4096)] } })).toBe('');
  expect(fuzzConfigError({ ...config, fuzz: { ...fuzz, seeds: Array(32).fill('a'.repeat(8192)) } })).not.toBe(
    '',
  );
});
