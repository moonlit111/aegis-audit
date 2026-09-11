<script lang="ts">
  import { onMount } from 'svelte';
  import { Download, X } from '@lucide/svelte';

  let {
    url,
    label,
    artifactId,
    onclose,
    onconfirm,
  }: {
    url: string;
    label: string;
    artifactId: string;
    onclose: () => void;
    onconfirm: () => void;
  } = $props();

  let dialog: HTMLDialogElement;

  onMount(() => {
    dialog.showModal();
  });
</script>

<dialog
  bind:this={dialog}
  class="import-dialog download-dialog"
  oncancel={onclose}
  aria-labelledby="download-dialog-title"
>
  <div class="dialog-heading">
    <div class="icon-tile"><Download size={22} /></div>
    <button class="icon-button" aria-label="关闭下载确认" onclick={onclose}><X size={20} /></button>
  </div>
  <h2 id="download-dialog-title">下载文件确认</h2>
  <p class="muted">
    即将从本地控制服务下载文件。请确认该产物与分析任务相关，下载后可按响应中的 SHA-256 核对。
  </p>
  <div class="download-meta">
    <div><span>文件</span><strong title={label}>{label}</strong></div>
    <div><span>产物 ID</span><code>{artifactId}</code></div>
  </div>
  <div class="dialog-actions">
    <button type="button" class="button secondary" onclick={onclose}>取消</button>
    <button
      type="button"
      class="button primary"
      onclick={() => {
        onconfirm();
      }}><Download size={15} />下载文件</button
    >
  </div>
</dialog>
