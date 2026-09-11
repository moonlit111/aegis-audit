<script lang="ts">
  import { onMount } from 'svelte';
  import { FileDown, X } from '@lucide/svelte';
  import type { AuditRun } from '../gen/audit/v1/audit_pb';
  import { runLabel } from '../lib/format';

  let {
    run,
    snapshotName,
    format,
    description,
    onclose,
    onconfirm,
  }: {
    run: AuditRun;
    snapshotName: string;
    format: string;
    description: string;
    onclose: () => void;
    onconfirm: () => void;
  } = $props();
  let dialog: HTMLDialogElement;

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
  class="import-dialog export-dialog"
  aria-labelledby="export-dialog-title"
  aria-describedby="export-dialog-description"
  oncancel={(event) => {
    event.preventDefault();
    close();
  }}
>
  <div class="dialog-heading">
    <div class="icon-tile"><FileDown size={24} /></div>
    <button class="icon-button" aria-label="关闭报告生成确认" onclick={close}><X size={20} /></button>
  </div>
  <h2 id="export-dialog-title">确认生成报告</h2>
  <div class="export-target">
    <strong>{snapshotName}</strong>
    <span>{format.toUpperCase()} · {runLabel(run.state)} · <code>{run.id.slice(0, 8)}</code></span>
  </div>
  <p id="export-dialog-description">{description}</p>
  <p>确认后将生成 {format.toUpperCase()} 文件并保存到报告历史。后续进度不会覆盖这份快照。</p>
  <div class="dialog-actions">
    <button class="button secondary" onclick={close}>取消</button>
    <button
      class="button primary"
      onclick={() => {
        dialog.close();
        onconfirm();
      }}><FileDown size={16} />确认生成</button
    >
  </div>
</dialog>

<style>
  .export-dialog {
    width: 480px;
    padding-bottom: 0;
  }
  .export-target {
    display: grid;
    gap: 4px;
    padding: 14px 16px;
    margin: 18px 0;
    border: 1px solid var(--line);
    background: var(--surface-subtle);
    border-radius: var(--radius-md);
    overflow-wrap: anywhere;
  }
  .export-target span,
  p {
    color: var(--muted);
    font-size: var(--text-sm);
    line-height: 1.8;
  }
</style>
