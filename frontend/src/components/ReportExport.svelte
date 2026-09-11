<script lang="ts">
  import { onMount } from 'svelte';
  import {
    AlertCircle,
    ArrowUpRight,
    CheckCircle2,
    ChevronDown,
    Download,
    FileDown,
    LoaderCircle,
  } from '@lucide/svelte';
  import { RunState, type AuditRun, type Report } from '../gen/audit/v1/audit_pb';
  import { artifactUrl, errorMessage, reportsApi, requestId } from '../lib/api';
  import { isTerminal } from '../lib/format';

  let {
    run,
    snapshotName,
    oncreated,
    onhistory,
  }: {
    run?: AuditRun;
    snapshotName: string;
    oncreated: () => void;
    onhistory: () => void;
  } = $props();
  let format = $state('html');
  let busy = $state(false);
  let error = $state('');
  let generated = $state<Report>();
  let attempt: { format: string; id: string } | undefined;
  const controller = new AbortController();
  const active = $derived(run && !isTerminal(run.state));
  const description = $derived.by(() => {
    if (!run) return '正在读取任务信息…';
    if (run.state === RunState.CANCELLING) return '保存当前进度与证据，任务正在停止。';
    if (run.state === RunState.CANCELLED) return '保存取消前已产生的结果与证据。';
    if (active) return '保存当前进度与证据，分析会继续进行。';
    if (run.state !== RunState.COMPLETED) return '包含已完成部分，并保留中断原因与证据。';
    return '保存本次结果与证据，便于查阅和分享。';
  });
  const reportName = (report: Report) =>
    `${report.format.toUpperCase()} ${report.interim ? '阶段报告' : '结果快照'}`;

  function download(report: Report) {
    const link = document.createElement('a');
    link.href = artifactUrl(report.artifactId);
    link.download = '';
    link.textContent = `${snapshotName} · ${reportName(report)}`;
    link.dataset.aegisDownloadNotice = report.interim
      ? '阶段报告已生成，保留导出时的进度与证据'
      : '报告已生成，可在报告历史中再次下载';
    link.hidden = true;
    document.body.appendChild(link);
    link.click();
    link.remove();
  }

  async function exportReport() {
    if (busy || !run) return;
    busy = true;
    error = '';
    generated = undefined;
    if (!attempt || attempt.format !== format) attempt = { format, id: requestId() };
    try {
      const response = await reportsApi.createReport(
        { requestId: attempt.id, runId: run.id, format: attempt.format },
        { signal: controller.signal },
      );
      if (controller.signal.aborted) return;
      if (!response.report?.artifactId) throw new Error('报告未返回有效的下载文件，请重试');
      generated = response.report;
      attempt = undefined;
      oncreated();
      download(response.report);
    } catch (failure) {
      if (!controller.signal.aborted) error = errorMessage(failure);
    } finally {
      busy = false;
    }
  }

  onMount(() => () => controller.abort());
</script>

<section class="report-export" aria-label="报告导出">
  <div class="export-heading">
    <div class="export-title">
      <FileDown size={18} />
      <h2>报告导出</h2>
    </div>
    <button class="text-button" onclick={onhistory} disabled={!run}>历史记录<ArrowUpRight size={14} /></button
    >
  </div>
  <p class="export-description">{description}</p>
  <div class="export-controls" aria-busy={busy}>
    <div class="format-select">
      <select aria-label="报告格式" bind:value={format} disabled={busy || !run}>
        <option value="html">HTML · 网页</option>
        <option value="pdf">PDF · 打印</option>
        <option value="markdown">Markdown · 文档</option>
        <option value="json">JSON · 数据</option>
      </select>
      <ChevronDown size={14} />
    </div>
    <button class="button primary" disabled={busy || !run} onclick={exportReport}>
      {#if busy}<LoaderCircle size={16} class="spin" />{:else}<Download size={16} />{/if}
      {busy ? '正在生成…' : error ? '重试导出' : active ? '导出阶段报告' : '导出报告'}
    </button>
  </div>
  <p class="export-note">每次导出保存一份快照，后续进度不会覆盖。</p>
  {#if error}
    <div class="export-feedback failed" role="alert">
      <AlertCircle size={16} />
      <div>
        <strong>报告生成未确认</strong>
        <p>{error}</p>
      </div>
    </div>
  {:else if busy}
    <div class="export-feedback" role="status">
      <LoaderCircle size={16} class="spin" /><span>正在生成 {format.toUpperCase()} 文件，请稍候。</span>
    </div>
  {:else if generated}
    <div class="export-feedback ready" role="status">
      <CheckCircle2 size={16} />
      <div>
        <strong>{reportName(generated)}已生成</strong>
        <p>已保存到报告历史。</p>
      </div>
      <button class="text-button" onclick={() => download(generated!)}>下载</button>
    </div>
  {/if}
</section>

<style>
  .report-export {
    width: 380px;
    max-width: 100%;
    flex-shrink: 0;
    padding: 16px 18px;
    border: 1px solid var(--accent-line);
    border-radius: var(--radius-lg);
    background: linear-gradient(120deg, var(--accent-soft), var(--surface) 75%);
    box-shadow: 0 3px 10px rgb(15 23 42 / 0.03);
  }
  .export-heading,
  .export-title {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .export-heading {
    justify-content: space-between;
  }
  .export-title {
    color: var(--accent);
  }
  h2 {
    color: var(--ink);
    font-size: var(--text-base);
  }
  .export-description {
    margin: 6px 0 14px;
    color: var(--muted);
    font-size: var(--text-xs);
  }
  .export-controls {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    gap: 8px;
  }
  .format-select {
    position: relative;
    min-width: 0;
  }
  select {
    appearance: none;
    width: 100%;
    height: 100%;
    min-height: var(--control-height);
    border: 1px solid var(--line-strong);
    border-radius: var(--radius-sm);
    padding: 8px 28px 8px 10px;
    background: var(--surface);
    color: var(--text-secondary);
    font-size: var(--text-sm);
    cursor: pointer;
    text-overflow: ellipsis;
  }
  select:disabled {
    cursor: not-allowed;
    background: var(--surface-subtle);
  }
  .format-select :global(svg) {
    position: absolute;
    top: 50%;
    right: 9px;
    transform: translateY(-50%);
    pointer-events: none;
    color: var(--muted);
  }
  .export-controls .button {
    font-size: var(--text-sm);
    padding-inline: 12px;
  }
  .export-controls .button:disabled {
    opacity: 0.75;
  }
  .export-note {
    margin-top: 10px;
    color: var(--muted);
    font-size: var(--text-xs);
  }
  .export-feedback {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    margin-top: 12px;
    padding-top: 12px;
    border-top: 1px solid var(--line);
    font-size: var(--text-xs);
    color: var(--accent);
    overflow-wrap: anywhere;
  }
  .export-feedback > :global(svg) {
    margin-top: 2px;
  }
  .export-feedback > div {
    flex: 1;
    min-width: 0;
  }
  .export-feedback strong {
    font-weight: 600;
  }
  .export-feedback p {
    margin-top: 2px;
    color: var(--muted);
  }
  .export-feedback.failed {
    color: var(--danger);
  }
  .export-feedback.ready {
    color: var(--success);
  }
  @media (max-width: 760px) {
    .report-export {
      width: 100%;
    }
  }
  @media (max-width: 380px) {
    .export-controls {
      grid-template-columns: 1fr;
    }
  }
</style>
