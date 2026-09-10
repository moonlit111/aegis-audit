<script lang="ts">
  import type { Report } from '../gen/audit/v1/audit_pb';
  import { onMount } from 'svelte';
  import { reportsApi, artifactUrl, errorMessage } from '../lib/api';
  import { dateTime } from '../lib/format';
  let { runId, version }: { runId: string; version: number } = $props();
  let reports = $state<Report[]>([]);
  let total = $state(0);
  let offset = $state(0);
  let error = $state('');
  let busy = $state('');
  let generation = 0;
  const controller = new AbortController();
  const states: Record<string, string> = {
    QUEUED: '排队中',
    WAITING_EXECUTOR: '等待执行器',
    RUNNING: '执行中',
    CANCELLING: '取消中',
    CANCELLED: '已取消',
    COMPLETED: '已完成',
    PARTIAL: '部分完成',
    FAILED: '失败',
    LIMIT_REACHED: '达到限制',
  };
  async function refresh() {
    const current = ++generation;
    try {
      const response = await reportsApi.listReports(
        { runId, offset, limit: 30 },
        { signal: controller.signal },
      );
      if (controller.signal.aborted || current !== generation) return;
      reports = response.reports;
      total = Number(response.total);
    } catch (failure) {
      if (!controller.signal.aborted) error = errorMessage(failure);
    }
  }
  async function download(id: string) {
    busy = id;
    error = '';
    try {
      const response = await reportsApi.getReport({ reportId: id }, { signal: controller.signal });
      if (!response.report || controller.signal.aborted) return;
      const link = document.createElement('a');
      link.href = artifactUrl(response.report.artifactId);
      link.download = '';
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (failure) {
      if (!controller.signal.aborted) error = errorMessage(failure);
    } finally {
      busy = '';
    }
  }
  $effect(() => {
    version;
    void refresh();
  });
  onMount(() => () => controller.abort());
</script>

<section class="panel report-history" aria-label="报告历史">
  <div class="panel-title">
    <h2>报告历史 · {total} 份</h2>
    <button class="text-button" onclick={refresh}>刷新历史</button>
  </div>
  <p class="muted">每份报告保留导出时的数据。后续分析、复核或标注变更不会修改已生成的文件。</p>
  {#if error}<div class="error-banner" role="alert">{error}</div>{/if}
  <div class="table-scroll">
    <table>
      <thead
        ><tr><th>数据截至</th><th>格式</th><th>报告类型</th><th>导出时任务状态</th><th>操作</th></tr></thead
      >
      <tbody
        >{#each reports as report}<tr>
            <td
              >{dateTime(report.snapshotAt || report.createdAt)}<small title={report.id}
                >{report.id.slice(0, 8)}</small
              ></td
            >
            <td>{report.format.toUpperCase()}</td>
            <td>{report.snapshotState ? (report.interim ? '阶段报告' : '结果快照') : '历史报告'}</td>
            <td>{states[report.snapshotState] || '早期版本未记录'}</td>
            <td
              ><button class="text-button" disabled={!!busy} onclick={() => download(report.id)}
                >{busy === report.id ? '读取中…' : '下载报告'}</button
              ></td
            >
          </tr>{/each}</tbody
      >
    </table>
  </div>
  {#if !reports.length}<p class="empty-panel">
      尚无导出记录。运行中的任务也可以从页面上方导出阶段报告。
    </p>{/if}
  {#if total > 30}<div class="history-pages">
      <button
        class="text-button"
        disabled={!offset}
        onclick={() => {
          offset -= 30;
          void refresh();
        }}>上一页</button
      >
      <span>{offset + 1}–{Math.min(offset + 30, total)} / {total}</span>
      <button
        class="text-button"
        disabled={offset + 30 >= total}
        onclick={() => {
          offset += 30;
          void refresh();
        }}>下一页</button
      >
    </div>{/if}
</section>

<style>
  .report-history p {
    margin: var(--space-3) 0;
  }
  small {
    display: block;
    color: var(--muted);
    font-family: var(--font-mono);
  }
  .history-pages {
    display: flex;
    gap: var(--space-3);
    margin-top: var(--space-3);
  }
</style>
