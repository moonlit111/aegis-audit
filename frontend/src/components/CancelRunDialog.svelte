<script lang="ts">
  import { onMount } from 'svelte';
  import { CircleStop, X } from '@lucide/svelte';
  import { RunState, type AuditRun } from '../gen/audit/v1/audit_pb';
  import { isTerminal, runLabel, scopeLabel } from '../lib/format';

  let {
    run,
    snapshotName,
    onclose,
    onconfirm,
  }: {
    run: AuditRun;
    snapshotName: string;
    onclose: () => void;
    onconfirm: () => void;
  } = $props();
  let dialog: HTMLDialogElement;
  const canCancel = $derived(!isTerminal(run.state) && run.state !== RunState.CANCELLING);

  function close() {
    dialog.close();
    onclose();
  }

  onMount(() => {
    dialog.showModal();
    return () => dialog.close();
  });
</script>

<dialog
  bind:this={dialog}
  class="import-dialog cancel-dialog"
  aria-labelledby="cancel-dialog-title"
  aria-describedby="cancel-dialog-description"
  oncancel={(event) => {
    event.preventDefault();
    close();
  }}
>
  <div class="dialog-heading">
    <div class="icon-tile"><CircleStop size={24} /></div>
    <button class="icon-button" aria-label="关闭取消确认" onclick={close}><X size={20} /></button>
  </div>
  <h2 id="cancel-dialog-title">{canCancel ? '取消当前任务？' : '任务状态已更新'}</h2>
  <div class="cancel-target">
    <strong>{snapshotName}</strong>
    <span>{scopeLabel(run.scope)} · <code>{run.id.slice(0, 8)}</code> · {runLabel(run.state)}</span>
  </div>
  <p id="cancel-dialog-description">
    {#if canCancel}
      {run.state === RunState.QUEUED || run.state === RunState.WAITING_EXECUTOR
        ? '任务将从队列中取消，不再开始执行。'
        : '正在执行的工作将停止，后续阶段不再继续。'}
      已完成的分析结果和证据会保留，仍可查看和导出。
    {:else if run.state === RunState.CANCELLING}
      取消请求已记录，正在等待执行停止，无需重复提交。
    {:else}
      当前任务已结束，无需再取消。可返回查看结果。
    {/if}
  </p>
  <div class="dialog-actions">
    <button class="button secondary" onclick={close}>{canCancel ? '继续任务' : '返回任务'}</button>
    {#if canCancel}
      <button
        class="button confirm-cancel"
        onclick={() => {
          dialog.close();
          onconfirm();
        }}><CircleStop size={16} />确认取消</button
      >
    {/if}
  </div>
</dialog>

<style>
  .cancel-dialog {
    width: 480px;
    padding-bottom: 0;
  }
  .icon-tile {
    color: var(--danger);
    background: var(--danger-soft);
    border-color: var(--danger-line);
  }
  .cancel-target {
    display: grid;
    gap: 4px;
    padding: 14px 16px;
    margin: 18px 0;
    border: 1px solid var(--line);
    background: var(--surface-subtle);
    border-radius: var(--radius-md);
    overflow-wrap: anywhere;
  }
  .cancel-target span,
  p {
    color: var(--muted);
    font-size: var(--text-sm);
    line-height: 1.8;
  }
  .button.confirm-cancel {
    background: var(--danger);
    color: white;
  }
  .button.confirm-cancel:hover {
    background: #991b1b;
  }
</style>
