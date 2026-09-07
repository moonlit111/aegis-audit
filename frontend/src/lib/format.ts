import { RunState, SnapshotState, TargetKind } from '../gen/audit/v1/audit_pb';

export const isTerminal = (state: RunState) => state >= RunState.COMPLETED;
export function runLabel(state: RunState): string {
  return (
    [
      '未知',
      '排队中',
      '分析中',
      '等待执行器',
      '正在取消',
      '分析完成',
      '部分完成',
      '分析失败',
      '已取消',
      '达到时限',
    ][state] || '未知'
  );
}
export function snapshotLabel(state: SnapshotState): string {
  return ['未知', '导入中', '可分析', '部分导入', '导入失败'][state] || '未知';
}
export const kindLabel = (kind: TargetKind) => ['未知', '源码 ZIP', 'PE / ELF', 'Git 仓库'][kind];
export const tone = (state: RunState) =>
  state === RunState.COMPLETED
    ? 'success'
    : state === RunState.PARTIAL || state === RunState.LIMIT_REACHED
      ? 'warning'
      : state === RunState.FAILED
        ? 'danger'
        : 'neutral';
export function dateTime(text: string): string {
  return text
    ? new Intl.DateTimeFormat('zh-CN', {
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        hour12: false,
      }).format(new Date(text))
    : '—';
}
export function bytes(value: bigint | number): string {
  const size = Number(value);
  return size < 1024
    ? `${size} B`
    : size < 1024 ** 2
      ? `${(size / 1024).toFixed(1)} KiB`
      : `${(size / 1024 ** 2).toFixed(1)} MiB`;
}
export function parseJson<T>(text: string, fallback: T): T {
  try {
    return (JSON.parse(text) || fallback) as T;
  } catch {
    return fallback;
  }
}
export type CoverageFile = {
  path: string;
  language: string;
  status: string;
  reason: string;
  unit_count: number;
};
export type ToolRecord = {
  name: string;
  version: string;
  exit_code: number | null;
  started_at: string;
  finished_at: string;
  log_artifact_id: string;
  command: string[];
};
export type Summary = {
  function_count?: number;
  edge_count?: number;
  unresolved_calls?: number;
  files?: CoverageFile[];
  exclusions?: { path: string; reason: string }[];
  warnings?: string[];
  tools?: ToolRecord[];
};
export type UnitMetadata = {
  kind?: string;
  rva?: string;
  image_base?: string;
  signature?: string;
  decompile_error?: string;
  branches?: { kind: string; line: number; condition: string }[];
  basic_blocks?: { start: string; end: string; successors: { address: string; flow_type: string }[] }[];
  pcode?: { address: string; opcode: string }[];
  strings?: { address: string; value: string }[];
};
