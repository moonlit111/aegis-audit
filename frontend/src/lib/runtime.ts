import {
  TargetKind,
  type AgentTask,
  type ProgramUnit,
  type RuntimeRecord,
  type Snapshot,
} from '../gen/audit/v1/audit_pb';
import { parseJson } from './format';

export type RuntimeMode = 'VERIFY' | 'FUZZ';

function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function targetPath(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    Boolean(value) &&
    new TextEncoder().encode(value).length <= 512 &&
    !/[\\:\0\n\r]/.test(value) &&
    value.split('/').every((part) => part && part !== '.' && part !== '..')
  );
}

export function supportsFuzz(snapshot?: Snapshot): boolean {
  const metadata = parseJson<{ format?: string; architecture?: string }>(snapshot?.metadataJson || '', {});
  return (
    snapshot?.kind === TargetKind.BINARY &&
    metadata.format === 'PE' &&
    ['x86', 'x86_64'].includes(metadata.architecture || '') &&
    /\.exe$/i.test(snapshot.name)
  );
}

export function readRuntimeConfig(json: string): Record<string, unknown> | null {
  const value = parseJson<unknown>(json, null);
  return isObject(value) ? value : null;
}

export function fuzzConfigError(config: Record<string, unknown> | null): string {
  if (!config) return '请提供有效的运行配置 JSON 对象。';
  const allowed = [
    'mode',
    'adapter',
    'path',
    'function',
    'globals',
    'fixtures',
    'baseline',
    'probe',
    'observer',
    'marker_path',
    'repeats',
    'timeout_seconds',
    'fuzz',
  ];
  if (Object.keys(config).some((key) => !allowed.includes(key))) return '运行配置包含后端不支持的字段。';
  if (
    !isObject(config.fuzz) ||
    Object.keys(config.fuzz).some(
      (key) => !['engine', 'input_mode', 'seeds', 'max_cases', 'budget_seconds', 'random_seed'].includes(key),
    )
  )
    return 'fuzz 必须是仅包含引擎、输入方式、种子和预算的配置对象。';
  const normalized = withRuntimeDefaults(config);
  const fuzz = normalized.fuzz as Record<string, unknown>;
  if (
    config.mode !== 'FUZZ' ||
    config.adapter !== 'WINDOWS_LIBFUZZER_PREBUILT' ||
    normalized.observer !== 'SANITIZER' ||
    fuzz.engine !== 'LLVM_LIBFUZZER' ||
    fuzz.input_mode !== 'FILE'
  )
    return 'Fuzz 需要预构建 libFuzzer、文件输入和 SANITIZER 观察方式。';
  const bytes = (value: string) => new TextEncoder().encode(value).length;
  if (!targetPath(config.path) || !/\.exe$/i.test(config.path))
    return '目标入口必须是快照内的相对 EXE 路径。';
  if (normalized.marker_path !== '' && !targetPath(normalized.marker_path))
    return 'marker_path 必须为空或测试目录内的相对文件路径。';
  for (const [label, value, max] of [
    ['最大执行次数', fuzz.max_cases, 1_000_000],
    ['时间预算', fuzz.budget_seconds, 900],
    ['单次超时', normalized.timeout_seconds, 15],
    ['随机种子', fuzz.random_seed, Number.MAX_SAFE_INTEGER],
  ] as const) {
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1 || value > max)
      return `${label}必须是 1 至 ${max} 的整数。`;
  }
  if (!Array.isArray(fuzz.seeds) || fuzz.seeds.length < 1 || fuzz.seeds.length > 32)
    return '初始种子数量必须为 1 至 32 个。';
  for (const [index, seed] of fuzz.seeds.entries()) {
    if (typeof seed !== 'string' || !seed.length || bytes(seed) > 8192)
      return `种子 ${index + 1} 必须是非空 UTF-8 文本，且不超过 8192 字节。`;
  }
  if (
    normalized.function !== '' ||
    !isObject(normalized.globals) ||
    Object.keys(normalized.globals).length ||
    !Array.isArray(normalized.fixtures) ||
    normalized.fixtures.length
  )
    return 'Fuzz 配置不能包含函数、全局变量或测试文件。';
  for (const name of ['baseline', 'probe']) {
    const raw = config[name];
    if (
      raw !== undefined &&
      (!isObject(raw) || Object.keys(raw).some((key) => !['args', 'kwargs', 'stdin'].includes(key)))
    )
      return '正常输入和异常输入必须是有效的输入对象。';
    const input = normalized[name] as Record<string, unknown>;
    if (
      !Array.isArray(input.args) ||
      input.args.length ||
      !isObject(input.kwargs) ||
      Object.keys(input.kwargs).length ||
      input.stdin !== ''
    )
      return 'Fuzz 仅使用初始种子，正常输入和异常输入必须为空。';
  }
  const repeats = normalized.repeats;
  if (typeof repeats !== 'number' || !Number.isInteger(repeats) || repeats < 2 || repeats > 5)
    return 'repeats 必须为 2 至 5 次。';
  const json = JSON.stringify(normalized);
  if (json.includes('{{')) return 'Windows 运行配置不支持模板占位符。';
  if (bytes(json) > 128 * 1024) return '运行配置总大小不能超过 128 KiB。';
  return '';
}

export const runtimeLabels: Record<string, string> = {
  QUEUED: '排队中',
  RUNNING: '运行中',
  WAITING_EXECUTOR: '等待执行器',
  CANCELLING: '正在取消',
  CANCELLED: '已取消',
  FAILED: '执行失败',
  LIMIT_REACHED: '达到时限',
  ERROR: '执行出错',
  COMPLETED: '执行完成',
  PARTIAL: '部分完成',
  VERIFIED_COMPONENT: '组件内验证成立',
  REPRODUCED: '已重复观察到异常',
  NOT_REPRODUCED: '本次未复现',
  NO_CRASH_OBSERVED: '本次未观察到崩溃',
  INCONCLUSIVE: '结果不确定',
  COMPONENT: 'Python 组件',
  INSTRUMENTED_BUILD: '插桩构建',
  REBUILT_TARGET: '重新构建的程序',
  ORIGINAL: '原始二进制',
  READY: '方案就绪',
  NEEDS_CONFIGURATION: '需补充运行配置',
  UNSUPPORTED: '当前环境不支持',
  VERIFY: '运行验证',
  FUZZ: '动态模糊测试',
  MUTATION: '输入变异',
  AFLPP: 'AFL++ 覆盖引导',
  WINDOWS_PYTHON_CALL: 'Windows Python 组件',
  WINDOWS_NATIVE_SOURCE: 'Windows 本地构建',
  WINDOWS_ORIGINAL_PE32: '原始 PE32',
  WINDOWS_ORIGINAL_PE64: '原始 PE64',
  WINDOWS_LIBFUZZER_PREBUILT: '预构建 libFuzzer',
  LLVM_LIBFUZZER: 'LLVM libFuzzer',
  FILE: '文件输入',
};
export const runtimeLabel = (value: string) => runtimeLabels[value] || value;
export const runtimePending = (value: string) =>
  ['QUEUED', 'RUNNING', 'WAITING_EXECUTOR', 'CANCELLING'].includes(value);

export const verificationPlans = (tasks: AgentTask[] = []) =>
  tasks.filter((task) => task.role === 'VERIFIER' && task.status === 'SUCCEEDED');

export const readVerificationPlan = (task: AgentTask) =>
  parseJson<VerificationPlan>(task.resultJson, {
    status: '',
    rationale: '',
    limitations: [],
    config: null,
  });

function sortedJson(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortedJson);
  if (value && typeof value === 'object')
    return Object.fromEntries(
      Object.entries(value)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, item]) => [key, sortedJson(item)]),
    );
  return value;
}

// Match the server's optional defaults without changing the submitted draft.
export function withRuntimeDefaults(config: Record<string, unknown>): Record<string, unknown> {
  const invocation = { args: [], kwargs: {}, stdin: '' };
  return {
    mode: 'VERIFY',
    adapter: 'NATIVE_SOURCE',
    path: '',
    function: '',
    globals: {},
    fixtures: [],
    observer: 'SANITIZER',
    marker_path: 'marker.txt',
    repeats: 2,
    timeout_seconds: 5,
    ...config,
    baseline: { ...invocation, ...((config.baseline || {}) as object) },
    probe: { ...invocation, ...((config.probe || {}) as object) },
    fuzz: {
      engine: 'MUTATION',
      input_mode: 'STDIN',
      seeds: ['hello'],
      max_cases: 256,
      budget_seconds: 30,
      random_seed: 71413,
      ...((config.fuzz || {}) as object),
    },
  };
}

export function runtimeConfigKey(value: unknown): string {
  return JSON.stringify(sortedJson(withRuntimeDefaults(isObject(value) ? value : {})));
}

export function matchingRuntime(
  records: RuntimeRecord[],
  findingId: string,
  config: Record<string, unknown>,
) {
  const key = runtimeConfigKey(config);
  const matches = [...records]
    .reverse()
    .filter(
      (record) =>
        record.findingId === findingId && runtimeConfigKey(parseJson(record.configJson, {})) === key,
    );
  return matches.find((record) => runtimePending(record.status)) || matches[0];
}

export function mergeRuntimeRecords(current: RuntimeRecord[], incoming: RuntimeRecord[]): RuntimeRecord[] {
  const records = new Map(current.map((record) => [record.id, record]));
  for (const record of incoming) {
    const previous = records.get(record.id);
    // A read begun before create/cancel/completion cannot erase acknowledged work.
    if (
      previous &&
      ((previous.resultJson && !record.resultJson) ||
        (!runtimePending(previous.status) && runtimePending(record.status)) ||
        (previous.status === 'CANCELLING' && runtimePending(record.status) && record.status !== 'CANCELLING'))
    )
      continue;
    records.set(record.id, record);
  }
  return [...records.values()].sort((a, b) => a.createdAt.localeCompare(b.createdAt));
}

export function runtimeFeedback(record: RuntimeRecord, result: RuntimeResult | null) {
  const scope = result?.target_scope;
  const fuzz = readRuntimeConfig(record.configJson)?.mode === 'FUZZ';
  const action = fuzz ? '模糊测试' : '验证';
  switch (record.status) {
    case 'QUEUED':
      return {
        title: `${action}已提交，正在排队`,
        detail: '执行器领取后自动开始。进度与结果会持续显示在这里。',
        tone: 'neutral',
      };
    case 'WAITING_EXECUTOR':
      return {
        title: `${action}已提交，等待执行器`,
        detail: '当前没有可用的 Windows 运行执行器，连接后将自动继续。',
        tone: 'warning',
      };
    case 'RUNNING':
      return {
        title: `正在执行${action}`,
        detail: fuzz
          ? '正在变异种子并收集覆盖反馈；崩溃输入的缩减与复放结束后保存统计和证据。'
          : '正在运行测试并收集观察记录，完成后自动显示复现结论和证据。',
        tone: 'neutral',
      };
    case 'CANCELLING':
      return {
        title: `正在停止${action}`,
        detail: '取消请求已确认，等待执行进程回收。停止后会自动更新。',
        tone: 'neutral',
      };
    case 'CANCELLED':
      return {
        title: `${action}已取消`,
        detail: '本次执行已停止，未形成完整的复现结论。已保存的记录仍可查看。',
        tone: 'neutral',
      };
    case 'VERIFIED_COMPONENT':
      return {
        title: '组件内复现成功',
        detail: '指定现象已在组件测试中重复出现；尚不能据此确认完整程序中的利用效果。',
        tone: 'warning',
      };
    case 'REPRODUCED':
      if (fuzz)
        return {
          title: '崩溃已稳定复现',
          detail: '已用归档的崩溃输入重复复放；这证明当前插桩目标的异常，不代表任意代码执行。',
          tone: 'warning',
        };
      return {
        title: scope === 'ORIGINAL' ? '原始程序复现成功' : '已重复复现指定现象',
        detail:
          scope === 'ORIGINAL'
            ? '指定现象已在原始程序中重复出现。已确认的效果见下方观察记录，未测试的更高影响仍未确认。'
            : `指定现象已在${runtimeLabel(scope || '') || '本次测试环境'}中重复出现；原始发布程序中的效果仍需单独确认。`,
        tone: 'warning',
      };
    case 'NOT_REPRODUCED':
      return {
        title: '本次未复现',
        detail: '本次输入未满足复现判定条件；这不能证明漏洞不存在，可结合观察记录调整验证条件。',
        tone: 'neutral',
      };
    case 'NO_CRASH_OBSERVED':
      return {
        title: '本次未观察到崩溃',
        detail: '当前输入与测试预算内未观察到崩溃，不能据此排除漏洞。',
        tone: 'neutral',
      };
    case 'ERROR':
    case 'FAILED':
      return {
        title: `${action}执行失败`,
        detail: '执行遇到错误，尚不能判断是否复现。请查看错误原因、构建输出或任务事件。',
        tone: 'danger',
      };
    case 'LIMIT_REACHED':
      return {
        title: `${action}达到时限`,
        detail: '本次执行未能在时限内完成，尚不能确认利用效果。',
        tone: 'warning',
      };
    default:
      return {
        title: `${action}结论不确定`,
        detail: '现有记录不足以形成明确的复现结论，请核对正常输入、异常输入和执行条件。',
        tone: 'warning',
      };
  }
}

export type RuntimeTrial = {
  label: string;
  input_sha256: string;
  exit_code: number | null;
  timed_out: boolean;
  processes_reaped: boolean;
  observed: boolean;
  exception: string;
  stdout: string;
  stderr: string;
  truncated: boolean;
  crash_signature?: string;
};
export type RuntimeResult = {
  target_sha256: string;
  config_hash: string;
  image_id: string;
  target_scope: string;
  recipe_artifact_id: string;
  observation_artifact_id: string;
  observation: {
    error: string;
    trials: RuntimeTrial[];
    build: Record<string, unknown>;
    fuzz: {
      engine?: string;
      executions?: number;
      timeouts?: number;
      bitmap_cvg?: string;
      coverage_feedback?: boolean;
      stop_reason?: string;
    };
    crashes: {
      input_hex: string;
      input_sha256: string;
      signature: string;
      reproduced: boolean;
      minimized: boolean;
      replays?: RuntimeTrial[];
    }[];
  };
  tools: { name: string; log_artifact_id: string }[];
};
export type VerificationPlan = {
  status: string;
  rationale: string;
  limitations: string[];
  config: Record<string, unknown> | null;
};

export function runtimeTemplate(
  adapter: string,
  mode: string,
  unit?: ProgramUnit,
  snapshot?: Snapshot,
): string {
  const native = adapter !== 'WINDOWS_PYTHON_CALL';
  const config: Record<string, unknown> = {
    mode,
    adapter,
    path: snapshot?.kind === TargetKind.BINARY ? snapshot.name : unit?.path || '',
    baseline: { args: [], kwargs: {}, stdin: '' },
    probe: { args: [], kwargs: {}, stdin: '' },
    observer: native ? 'SANITIZER' : 'FILE_CREATED',
    marker_path: native ? '' : 'marker.txt',
    repeats: 2,
    timeout_seconds: 5,
  };
  if (!native) {
    config.function = unit?.language === 'python' ? unit.name : '';
    config.globals = {};
  }
  if (mode === 'FUZZ') {
    config.adapter = 'WINDOWS_LIBFUZZER_PREBUILT';
    config.function = '';
    config.observer = 'SANITIZER';
    config.marker_path = '';
    config.fuzz = {
      engine: 'LLVM_LIBFUZZER',
      input_mode: 'FILE',
      seeds: ['hello'],
      max_cases: 1000,
      budget_seconds: 60,
      random_seed: 71413,
    };
  }
  return JSON.stringify(config, null, 2);
}
