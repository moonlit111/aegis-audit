import type { AgentTask, ProgramUnit, RuntimeRecord } from '../gen/audit/v1/audit_pb';
import { parseJson } from './format';

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
  FUZZ: '动态测试',
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

// Match the server's RuntimeConfig defaults so an omitted optional field does
// not make a saved plan look different from its persisted execution recipe.
export function runtimeConfigKey(value: unknown): string {
  const config =
    value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
  const invocation = { args: [], kwargs: {}, stdin: '' };
  return JSON.stringify(
    sortedJson({
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
    }),
  );
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
  switch (record.status) {
    case 'QUEUED':
      return {
        title: '验证已提交，正在排队',
        detail: '执行器领取后自动开始。进度与结果会持续显示在这里。',
        tone: 'neutral',
      };
    case 'WAITING_EXECUTOR':
      return {
        title: '验证已提交，等待执行器',
        detail: '当前没有可用的 Windows 运行执行器，连接后将自动继续。',
        tone: 'warning',
      };
    case 'RUNNING':
      return {
        title: '正在执行验证',
        detail: '正在运行测试并收集观察记录，完成后自动显示复现结论和证据。',
        tone: 'neutral',
      };
    case 'CANCELLING':
      return {
        title: '正在停止验证',
        detail: '取消请求已确认，等待执行进程回收。停止后会自动更新。',
        tone: 'neutral',
      };
    case 'CANCELLED':
      return {
        title: '验证已取消',
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
        title: '验证执行失败',
        detail: '执行遇到错误，尚不能判断是否复现。请查看错误原因、构建输出或任务事件。',
        tone: 'danger',
      };
    case 'LIMIT_REACHED':
      return {
        title: '验证达到时限',
        detail: '本次执行未能在时限内完成，尚不能确认利用效果。',
        tone: 'warning',
      };
    default:
      return {
        title: '验证结论不确定',
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

export function runtimeTemplate(adapter: string, mode: string, unit?: ProgramUnit): string {
  const native = adapter !== 'WINDOWS_PYTHON_CALL';
  const config: Record<string, unknown> = {
    mode,
    adapter,
    path: unit?.path || '',
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
    config.path = unit?.path || 'fuzz.exe';
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
