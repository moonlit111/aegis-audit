import type { ProgramUnit } from '../gen/audit/v1/audit_pb';

export const runtimeLabels: Record<string, string> = {
  QUEUED: '排队中',
  RUNNING: '运行中',
  WAITING_EXECUTOR: '等待执行器',
  CANCELLING: '正在取消',
  CANCELLED: '已取消',
  FAILED: '执行失败',
  LIMIT_REACHED: '达到时限',
  ERROR: '执行出错',
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
