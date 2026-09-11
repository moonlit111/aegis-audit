<script lang="ts">
  import { onMount } from 'svelte';
  import { ArrowRight, BrainCircuit, RotateCcw, X } from '@lucide/svelte';
  import type { AuditRun, Snapshot } from '../gen/audit/v1/audit_pb';
  import { TargetKind } from '../gen/audit/v1/audit_pb';
  import { errorMessage, requestId, runsApi } from '../lib/api';

  let {
    snapshot,
    activeRun,
    previousRun,
    onclose,
    oncreated,
  }: {
    snapshot: Snapshot;
    activeRun?: AuditRun;
    previousRun?: AuditRun;
    onclose: () => void;
    oncreated: (run: AuditRun) => void;
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
  let submittedKey = '';
  let submittedId = '';
  onMount(() => {
    if (previousRun) {
      try {
        const config = JSON.parse(previousRun.summaryJson).audit_config;
        if (config)
          options = {
            maxModelCalls: config.max_model_calls ?? defaults.maxModelCalls,
            maxUnits: config.max_units ?? defaults.maxUnits,
            maxToolRounds: config.max_tool_rounds ?? defaults.maxToolRounds,
            timeoutSeconds: config.timeout_seconds ?? defaults.timeoutSeconds,
            maxOutputTokens: config.max_output_tokens ?? defaults.maxOutputTokens,
            reasoningEffort: config.reasoning_effort ?? defaults.reasoningEffort,
            modelTimeoutSeconds: config.model_timeout_seconds ?? defaults.modelTimeoutSeconds,
          };
      } catch {
        /* Older runs may not contain an audit configuration. */
      }
    }
    dialog.showModal();
  });

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (busy) return;
    if (activeRun) {
      oncreated(activeRun);
      return;
    }
    busy = true;
    error = '';
    try {
      const key = JSON.stringify([snapshot.id, options]);
      if (key !== submittedKey) {
        submittedKey = key;
        submittedId = requestId();
      }
      const response = await runsApi.createRun({
        requestId: submittedId,
        snapshotId: snapshot.id,
        scope: 'SECURITY_AUDIT',
        ...options,
      });
      oncreated(response.run!);
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
  <h2 id="audit-dialog-title">{previousRun ? '重新运行漏洞审计' : '开始漏洞审计'}</h2>
  <p class="audit-target">{snapshot.name}</p>
  {#if activeRun}
    <p>此快照已有分析任务。可打开进度继续查看。</p>
    <div class="dialog-actions">
      <button class="button primary" onclick={() => oncreated(activeRun!)}
        >查看进度<ArrowRight size={15} /></button
      >
    </div>
  {:else}
    <p class="audit-description">
      {snapshot.kind === TargetKind.BINARY
        ? '准备目标 → 逆向与反编译 → 漏洞审计与独立复核 → 验证方案。兼容的已有反编译结果会自动复用。'
        : '结构解析 → 漏洞审计与独立复核 → 验证方案。'}
      实际运行验证可在结果中单独启动。
      {#if previousRun}本次将新建一轮审计，保留原结果；默认沿用上一轮预算。{/if}
    </p>
    <form onsubmit={submit}>
      <details class="advanced-options">
        <summary>高级设置：模型与预算</summary>
        <fieldset disabled={busy}>
          <legend>模型思考</legend>
          <div class="audit-options-grid">
            <label class="field"
              >思考强度<select bind:value={options.reasoningEffort}>
                <option value="low">Low</option><option value="high">High</option><option value="max"
                  >Max</option
                >
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
      </details>
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
  {/if}
</dialog>

<style>
  .audit-dialog {
    width: 620px;
    border-radius: var(--radius-lg);
  }
  .audit-target {
    margin: 0 0 22px;
    overflow-wrap: anywhere;
    font-size: var(--text-base);
  }
  .audit-description {
    color: var(--muted);
    line-height: 1.7;
    margin: 0 0 20px;
  }
  .advanced-options {
    margin-bottom: 20px;
  }
  .advanced-options summary {
    cursor: pointer;
    font-weight: 600;
    margin-bottom: 16px;
  }
  fieldset {
    border: 0;
    padding: 0;
    margin: 0 0 8px;
    min-width: 0;
  }
  legend {
    font-size: var(--text-base);
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
    font-size: var(--text-sm);
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
