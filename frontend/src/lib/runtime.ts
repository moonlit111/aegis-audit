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
  ORIGINAL: '原始二进制',
  READY: '方案就绪',
  NEEDS_CONFIGURATION: '需补充运行配置',
  UNSUPPORTED: '当前环境不支持',
  VERIFY: '运行验证',
  FUZZ: '动态测试',
  MUTATION: '输入变异',
  AFLPP: 'AFL++ 覆盖引导',
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
  const native = adapter !== 'PYTHON_CALL';
  const config: Record<string, unknown> = {
    mode,
    adapter,
    path: unit?.path || '',
    baseline: { args: [], kwargs: {}, stdin: '' },
    probe: { args: [], kwargs: {}, stdin: '' },
    observer: native ? 'SANITIZER' : 'RETURN_CANARY',
    repeats: 2,
    timeout_seconds: 5,
  };
  if (!native) {
    config.function = unit?.language === 'python' ? unit.name : '';
    config.globals = {};
    config.fixtures = [{ path: 'controlled.txt', content: '{{canary}}' }];
  }
  if (mode === 'FUZZ') {
    config.fuzz = {
      engine: 'MUTATION',
      input_mode: 'STDIN',
      seeds: ['hello'],
      max_cases: 128,
      budget_seconds: 15,
      random_seed: 71413,
    };
  }
  return JSON.stringify(config, null, 2);
}
