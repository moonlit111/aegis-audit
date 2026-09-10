<script lang="ts">
  import { onMount } from 'svelte';
  import { ArrowRight, BrainCircuit, RotateCcw, X } from '@lucide/svelte';
  import type { Snapshot } from '../gen/audit/v1/audit_pb';
  import { errorMessage, requestId, runsApi } from '../lib/api';

  let {
    snapshot,
    onclose,
    oncreated,
  }: {
    snapshot: Snapshot;
    onclose: () => void;
    oncreated: (id: string) => void;
  } = $props();
  const defaults = {
    maxModelCalls: 240,
    maxUnits: 80,
    maxToolRounds: 24,
    timeoutSeconds: 10800,
    maxOutputTokens: 0,
    reasoningEffort: 'high',
    modelTimeoutSeconds: 900,
  };
  const fields = [
    { key: 'maxModelCalls', label: '总模型调用上限', min: 4, max: 2000 },
    { key: 'maxToolRounds', label: '每个子任务工具轮数', min: 1, max: 100 },
    { key: 'maxUnits', label: '程序单元上限', min: 1, max: 500 },
    { key: 'timeoutSeconds', label: '任务时限（秒）', min: 60, max: 86400 },
  ] as const;
  let options = $state({ ...defaults });
  let dialog: HTMLDialogElement;
  let busy = $state(false);
  let error = $state('');
  onMount(() => dialog.showModal());

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (busy) return;
    busy = true;
    error = '';
    try {
      const response = await runsApi.createRun({
        requestId: requestId(),
        snapshotId: snapshot.id,
        scope: 'SECURITY_AUDIT',
        ...options,
      });
      oncreated(response.run!.id);
    } catch (failure) {
      error = errorMessage(failure);
    } finally {
      busy = false;
    }
  }
</script>

<dialog
  bind:this={dialog}
  class="import-dialog audit-dialog"
  aria-labelledby="audit-dialog-title"
  oncancel={(event) => {
    event.preventDefault();
    if (!busy) onclose();
  }}
>
  <div class="dialog-heading">
    <div class="icon-tile"><BrainCircuit size={22} /></div>
    <button class="icon-button" title="关闭" aria-label="关闭审计设置" disabled={busy} onclick={onclose}
      ><X size={20} /></button
    >
  </div>
  <h2 id="audit-dialog-title">审计预算</h2>
  <p class="audit-target">{snapshot.name}</p>
  <form onsubmit={submit}>
    <fieldset disabled={busy}>
      <legend>模型思考</legend>
      <div class="audit-options-grid">
        <label class="field"
          >思考强度<select bind:value={options.reasoningEffort}>
            <option value="low">Low</option><option value="high">High</option><option value="max">Max</option>
          </select></label
        >
        <label class="field"
          >单次输出预算（0 = 不限制）<input
            type="number"
            min="0"
            step="1"
            required
            bind:value={options.maxOutputTokens}
          /></label
        >
        <label class="field"
          >单次模型时限（秒）<input
            type="number"
            min="30"
            max="3600"
            step="1"
            required
            bind:value={options.modelTimeoutSeconds}
          /></label
        >
      </div>
    </fieldset>
    <fieldset disabled={busy}>
      <legend>任务预算</legend>
      <div class="audit-options-grid">
        {#each fields as field}<label class="field"
            >{field.label}<input
              type="number"
              min={field.min}
              max={field.max}
              step="1"
              required
              bind:value={options[field.key]}
            /></label
          >{/each}
      </div>
    </fieldset>
    {#if error}<div class="error-banner" role="alert">{error}</div>{/if}
    <div class="dialog-actions">
      <button
        class="icon-button"
        type="button"
        title="恢复默认预算"
        aria-label="恢复默认预算"
        disabled={busy}
        onclick={() => {
          options = { ...defaults };
          error = '';
        }}><RotateCcw size={17} /></button
      >
      <button class="button secondary" type="button" disabled={busy} onclick={onclose}>取消</button>
      <button class="button primary" disabled={busy}
        >{busy ? '正在创建…' : '开始审计'}<ArrowRight size={15} /></button
      >
    </div>
  </form>
</dialog>

<style>
  .audit-dialog {
    width: 620px;
    border-radius: 8px;
  }
  .audit-target {
    margin: 0 0 22px;
    overflow-wrap: anywhere;
    font-size: 13px;
  }
  fieldset {
    border: 0;
    padding: 0;
    margin: 0 0 8px;
    min-width: 0;
  }
  legend {
    font-size: 13px;
    font-weight: 600;
    margin-bottom: 14px;
  }
  .audit-options-grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 0 18px;
  }
  .field {
    min-width: 0;
    font-size: 12px;
  }
  .field input,
  .field select {
    min-width: 0;
  }
  .dialog-actions > .icon-button {
    margin-right: auto;
    flex-shrink: 0;
  }
  @media (max-width: 520px) {
    .audit-options-grid {
      grid-template-columns: minmax(0, 1fr);
    }
    .dialog-actions {
      flex-wrap: wrap;
    }
  }
</style>
