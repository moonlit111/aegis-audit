<script lang="ts">
  import { onMount, tick, untrack } from 'svelte';
  import {
    Play,
    RefreshCw,
    ArrowUpRight,
    CheckCircle2,
    Info,
    LoaderCircle,
    FlaskConical,
    Sparkles,
  } from '@lucide/svelte';
  import type {
    AuditRun,
    ProgramUnit,
    RuntimeRecord,
    GetAuditResponse,
    AgentTask,
    Snapshot,
  } from '../gen/audit/v1/audit_pb';
  import { TargetKind } from '../gen/audit/v1/audit_pb';
  import { errorMessage, requestId, runtimeApi } from '../lib/api';
  import { parseJson } from '../lib/format';
  import {
    runtimeLabel,
    runtimePending,
    runtimeTemplate,
    matchingRuntime,
    readVerificationPlan,
    runtimeConfigKey,
    verificationPlans,
    supportsFuzz,
    readRuntimeConfig,
    fuzzConfigError,
    type RuntimeMode,
    type VerificationPlan,
  } from '../lib/runtime';
  import FuzzConfig from './FuzzConfig.svelte';

  let {
    run,
    snapshot,
    unit,
    mode = $bindable('VERIFY'),
    preset,
    findingId = '',
    audit,
    records,
    refreshing,
    loadError,
    onrefresh,
    onstarted,
    onshowresults,
    notify,
  }: {
    run: AuditRun;
    snapshot?: Snapshot;
    unit?: ProgramUnit;
    mode?: RuntimeMode;
    preset?: RuntimeRecord;
    findingId?: string;
    audit?: GetAuditResponse;
    records: RuntimeRecord[];
    refreshing: boolean;
    loadError: string;
    onrefresh: () => Promise<void>;
    onstarted: (record: RuntimeRecord) => void;
    onshowresults: (recordId?: string) => void;
    notify: (message: string) => void;
  } = $props();
  let configJson = $state('');
  let adapter = $state('NATIVE_SOURCE');
  let selectedFinding = $state('');
  let error = $state('');
  let errorPanel = $state<HTMLDivElement>();
  let failedSubmission = $state(false);
  let lastSubmissionFinding = '';
  let busy = $state(false);
  let suggesting = $state(false);
  let submittingFinding = $state<string | null>(null);
  let submittingMode = $state<RuntimeMode>('VERIFY');
  let attempt: { key: string; id: string } | undefined;
  let configOpen = $state(false);
  let configPanel = $state<HTMLDetailsElement>();
  let configEditor = $state<HTMLTextAreaElement>();
  let fuzzConfirmed = $state(false);
  let suggestion = $state<{ rationale: string; limitations: string[] }>();
  let draftMode: RuntimeMode = 'VERIFY';
  const drafts: Partial<Record<RuntimeMode, string>> = {};
  let alive = true;
  const controller = new AbortController();
  const snapshotMetadata = $derived(
    parseJson<{ architecture?: string; format?: string }>(snapshot?.metadataJson || '', {}),
  );
  const adapterOptions = $derived.by(() => {
    if (mode === 'FUZZ') {
      return supportsFuzz(snapshot)
        ? [{ value: 'WINDOWS_LIBFUZZER_PREBUILT', label: '预构建 libFuzzer' }]
        : [];
    }
    if (snapshot?.kind === TargetKind.BINARY) {
      return snapshotMetadata.format === 'PE' &&
        ['x86', 'x86_64'].includes(snapshotMetadata.architecture || '')
        ? [
            snapshotMetadata.architecture === 'x86'
              ? { value: 'WINDOWS_ORIGINAL_PE32', label: '原始 PE32' }
              : { value: 'WINDOWS_ORIGINAL_PE64', label: '原始 PE64' },
          ]
        : [];
    }
    return [
      { value: 'WINDOWS_PYTHON_CALL', label: 'Python 函数' },
      { value: 'WINDOWS_NATIVE_SOURCE', label: 'C / C++' },
    ];
  });
  const runtimeAdapterSupported = $derived(adapterOptions.some((option) => option.value === adapter));
  const fuzzSupported = $derived(supportsFuzz(snapshot));
  const config = $derived(readRuntimeConfig(configJson));
  const fuzzError = $derived(mode === 'FUZZ' ? fuzzConfigError(config) : '');
  const reusableFinding = $derived(
    fuzzSupported &&
      audit?.findings.some(
        (finding) => finding.id === selectedFinding && finding.category === 'MEMORY_BOUNDS',
      ),
  );
  $effect(() => {
    const nextMode = mode;
    const target = snapshot;
    untrack(() => {
      if (!target || (configJson && draftMode === nextMode)) return;
      if (configJson) drafts[draftMode] = configJson;
      const defaultAdapter =
        nextMode === 'FUZZ'
          ? 'WINDOWS_LIBFUZZER_PREBUILT'
          : target.kind === TargetKind.BINARY
            ? snapshotMetadata.architecture === 'x86'
              ? 'WINDOWS_ORIGINAL_PE32'
              : 'WINDOWS_ORIGINAL_PE64'
            : unit?.language === 'python'
              ? 'WINDOWS_PYTHON_CALL'
              : 'WINDOWS_NATIVE_SOURCE';
      // Switching modes preserves both drafts; a suggested plan must not be
      // overwritten by an adapter/template effect after it has been applied.
      applyConfig(drafts[nextMode] || runtimeTemplate(defaultAdapter, nextMode, unit, target));
      suggestion = undefined;
      error = '';
    });
  });
  $effect(() => {
    selectedFinding = findingId;
  });
  $effect(() => {
    const record = preset;
    if (!record) return;
    untrack(() => {
      applyConfig(record.configJson);
      selectedFinding = record.findingId;
      suggestion = undefined;
      fuzzConfirmed = false;
      configOpen = true;
    });
  });
  const plans = $derived(
    verificationPlans(audit?.tasks).sort(
      (a, b) => Number(b.itemKey === findingId) - Number(a.itemKey === findingId),
    ),
  );
  const visiblePlans = $derived(
    plans.filter((task) => (readVerificationPlan(task).config?.mode === 'FUZZ') === (mode === 'FUZZ')),
  );
  const configuredRecord = $derived(config ? matchingRuntime(records, selectedFinding, config) : undefined);

  function applyConfig(json: string) {
    const next = readRuntimeConfig(json);
    const nextMode = next?.mode === 'VERIFY' || next?.mode === 'FUZZ' ? next.mode : mode;
    if (draftMode !== nextMode && configJson) drafts[draftMode] = configJson;
    if (json !== configJson) fuzzConfirmed = false;
    configJson = json;
    draftMode = nextMode;
    mode = nextMode;
    if (typeof next?.adapter === 'string') adapter = next.adapter;
    if (mode === 'FUZZ') configOpen = true;
  }

  function template() {
    applyConfig(runtimeTemplate(adapter, mode, unit, snapshot));
    suggestion = undefined;
    error = '';
  }
  async function loadPlan(task: AgentTask) {
    const plan = parseJson<VerificationPlan>(task.resultJson, {
      status: '',
      rationale: '',
      limitations: [],
      config: null,
    });
    if (!plan.config) return;
    selectedFinding = task.itemKey;
    applyConfig(JSON.stringify(plan.config, null, 2));
    suggestion = { rationale: plan.rationale, limitations: plan.limitations };
    configOpen = true;
    await tick();
    configPanel?.scrollIntoView({ block: 'start' });
    configEditor?.focus({ preventScroll: true });
  }
  async function start(savedFinding = '') {
    if (busy) return;
    busy = true;
    submittingFinding = savedFinding;
    lastSubmissionFinding = savedFinding;
    failedSubmission = false;
    error = '';
    try {
      const savedPlan = plans.find((task) => task.itemKey === savedFinding);
      const config = savedFinding
        ? savedPlan && readVerificationPlan(savedPlan).config
        : JSON.parse(configJson);
      if (!config || typeof config !== 'object' || Array.isArray(config))
        throw new Error('请提供有效的运行配置');
      submittingMode = config.mode === 'FUZZ' ? 'FUZZ' : 'VERIFY';
      if (config.mode === 'FUZZ') {
        if (!fuzzSupported) throw new Error('当前目标不支持预构建 libFuzzer 模糊测试。');
        const invalid = fuzzConfigError(config);
        if (invalid) throw new Error(invalid);
        if (!fuzzConfirmed) throw new Error('请先确认目标支持 libFuzzer，并获授权在本机执行。');
      }
      const previous = matchingRuntime(records, savedFinding || selectedFinding, config);
      if (previous && (savedFinding || runtimePending(previous.status))) {
        onshowresults(previous.id);
        return;
      }
      const key = JSON.stringify([run.id, savedFinding || selectedFinding, runtimeConfigKey(config)]);
      if (!attempt || attempt.key !== key) attempt = { key, id: requestId() };
      const response = await runtimeApi.createRuntime(
        {
          requestId: attempt.id,
          sourceRunId: run.id,
          findingId: savedFinding || selectedFinding,
          configJson: savedFinding ? '' : JSON.stringify(config),
        },
        { signal: controller.signal },
      );
      if (!alive) return;
      if (!response.record?.id) throw new Error('未收到有效的运行记录，请重试');
      attempt = undefined;
      onstarted(response.record);
      notify(`${submittingMode === 'FUZZ' ? '模糊测试' : '验证'}已提交，已切换到“覆盖与产物”查看进度与结果`);
    } catch (failure) {
      if (alive) {
        error = errorMessage(failure);
        failedSubmission = true;
        await tick();
        errorPanel?.scrollIntoView({ block: 'center' });
        errorPanel?.focus({ preventScroll: true });
      }
    } finally {
      busy = false;
      submittingFinding = null;
    }
  }

  async function reuse() {
    if (busy || !reusableFinding) return;
    const requestedFinding = selectedFinding;
    const requestedMode = mode;
    busy = true;
    suggesting = true;
    error = '';
    failedSubmission = false;
    try {
      const response = await runtimeApi.suggestRuntime(
        {
          requestId: requestId(),
          sourceRunId: run.id,
          findingId: requestedFinding,
        },
        { signal: controller.signal },
      );
      if (!alive || selectedFinding !== requestedFinding || mode !== requestedMode) return;
      const invalid = fuzzConfigError(readRuntimeConfig(response.configJson));
      if (invalid) throw new Error(invalid);
      applyConfig(response.configJson);
      suggestion = { rationale: response.rationale, limitations: response.limitations };
    } catch (failure) {
      if (alive && selectedFinding === requestedFinding && mode === requestedMode)
        error = errorMessage(failure);
    } finally {
      busy = false;
      suggesting = false;
    }
  }
  onMount(() => {
    configOpen = mode === 'FUZZ' || plans.length === 0;
    return () => {
      alive = false;
      controller.abort();
    };
  });
</script>

<section class="runtime-panel" aria-label={mode === 'FUZZ' ? '动态模糊测试配置' : '验证方案与运行配置'}>
  <div class="panel-title">
    <div>
      <h2>{mode === 'FUZZ' ? '动态模糊测试' : '验证方案与运行配置'}</h2>
      <p class="subtle">
        {mode === 'FUZZ'
          ? 'LLVM libFuzzer · 文件输入 · Windows 宿主机'
          : '启动后自动前往“覆盖与产物”，查看验证进度、复现结论与执行证据。'}
      </p>
    </div>
    <button
      class="button secondary small refresh-runtime"
      onclick={() => onrefresh()}
      aria-label="刷新验证方案"
      title="重新获取验证方案和已有运行状态"
      disabled={refreshing}
      ><RefreshCw size={15} class={refreshing ? 'spin' : ''} />{refreshing ? '刷新中…' : '刷新方案'}</button
    >
  </div>
  {#if loadError}<div class="error-banner" role="alert">
      {loadError}<button class="text-button" onclick={() => onrefresh()}>重新读取</button>
    </div>{/if}
  {#if records.length}<p class="runtime-results-link">
      <button class="text-button" onclick={() => onshowresults()}
        >查看运行进度与结果<ArrowUpRight size={14} /></button
      >
    </p>{/if}
  {#if error}<div class="error-banner" role="alert" bind:this={errorPanel} tabindex="-1">
      <span
        >{failedSubmission
          ? `${submittingMode === 'FUZZ' ? '模糊测试' : '验证'}提交未确认：`
          : ''}{error}</span
      >
      {#if failedSubmission}<button
          class="button secondary small"
          disabled={busy}
          onclick={() => start(lastSubmissionFinding)}>重试提交</button
        >{/if}<button
        class="text-button"
        onclick={() => {
          error = '';
        }}>关闭</button
      >
    </div>{/if}
  {#if visiblePlans.length}
    <div class="runtime-plans">
      {#each visiblePlans as task}
        {@const plan = parseJson<VerificationPlan>(task.resultJson, {
          status: '',
          rationale: '',
          limitations: [],
          config: null,
        })}
        {@const ready = plan.status === 'READY' && Boolean(plan.config)}
        {@const action = plan.config?.mode === 'FUZZ' ? '模糊测试' : '验证'}
        {@const previous = plan.config ? matchingRuntime(records, task.itemKey, plan.config) : undefined}
        {@const pending = previous && runtimePending(previous.status)}
        <article class="runtime-plan" class:ready>
          <header class="runtime-plan-heading">
            <span class="plan-label">{action}方案</span>
            <h3>{audit?.findings.find((f) => f.id === task.itemKey)?.title || '待验证发现'}</h3>
          </header>
          <div class="runtime-plan-status" class:ready class:unavailable={plan.status === 'UNSUPPORTED'}>
            {#if ready}<CheckCircle2 size={24} />{:else}<Info size={24} />{/if}
            <div>
              <strong
                >{previous
                  ? `已有${action} · ${runtimeLabel(previous.status)}`
                  : ready
                    ? '方案就绪'
                    : runtimeLabel(plan.status) || '方案待完善'}</strong
              >
              <p>
                {previous
                  ? pending
                    ? `${action}正在处理，可在“覆盖与产物”查看进度。`
                    : '已有执行结果，可在“覆盖与产物”查看复现结论与证据。'
                  : ready
                    ? '运行配置已生成，尚未执行。'
                    : plan.status === 'UNSUPPORTED'
                      ? '此方案暂不能在当前执行环境中运行。'
                      : '请先核对验证思路，补齐入口或输入等运行条件。'}
              </p>
            </div>
            {#if ready && !previous && plan.config?.mode === 'FUZZ'}<button
                class="button primary"
                disabled={busy}
                onclick={() => loadPlan(task)}><FlaskConical size={15} />核对 Fuzz 配置</button
              >
            {:else if ready && !previous}<button
                class="button primary"
                disabled={busy}
                aria-busy={submittingFinding === task.itemKey}
                onclick={() => start(task.itemKey)}
                >{#if submittingFinding === task.itemKey}<LoaderCircle
                    size={15}
                    class="spin"
                  />正在提交验证…{:else}<Play size={15} />按方案运行{/if}</button
              >
            {:else if previous}
              {#if pending}<button class="button secondary" disabled
                  ><LoaderCircle size={15} class="spin" />{runtimeLabel(previous.status)}</button
                >{/if}
              <button class="button primary" onclick={() => onshowresults(previous.id)}
                >{pending ? `查看${action}进度` : `查看${action}结果`}<ArrowUpRight size={15} /></button
              >
            {/if}
          </div>
          {#if submittingFinding === task.itemKey}<p class="runtime-submitting" role="status">
              正在创建验证任务，提交成功后将自动切换到“覆盖与产物”。
            </p>{/if}
          <div class="runtime-plan-body">
            <div class="plan-rationale">
              <h4>验证思路</h4>
              <p>{plan.rationale}</p>
            </div>
            {#if plan.config}
              <dl class="plan-facts">
                <div>
                  <dt>测试方式</dt>
                  <dd>{runtimeLabel(String(plan.config.mode || '')) || '未提供'}</dd>
                </div>
                <div>
                  <dt>执行方式</dt>
                  <dd>{runtimeLabel(String(plan.config.adapter || '')) || '未提供'}</dd>
                </div>
                <div>
                  <dt>测试入口</dt>
                  <dd>
                    <code>{String(plan.config.path || '未提供')}</code>
                    {#if plan.config.function}<code>{String(plan.config.function)}()</code>{/if}
                  </dd>
                </div>
                {#if typeof plan.config.repeats === 'number' && plan.config.mode === 'VERIFY'}
                  <div>
                    <dt>异常输入复测</dt>
                    <dd>{plan.config.repeats} 次<small>另执行 1 次正常输入作对照</small></dd>
                  </div>
                {/if}
              </dl>
            {/if}
            {#if plan.limitations.length}<div class="plan-limitations">
                <h4><Info size={15} />执行条件与限制</h4>
                <ul>
                  {#each plan.limitations as limitation}<li>{limitation}</li>{/each}
                </ul>
              </div>{/if}
            {#if plan.config}<div class="runtime-actions">
                <button class="button secondary" disabled={busy} onclick={() => loadPlan(task)}
                  >查看并调整配置</button
                >
              </div>{/if}
          </div>
        </article>
      {/each}
    </div>
  {/if}
  <details class="runtime-config" bind:this={configPanel} bind:open={configOpen}>
    <summary>{mode === 'FUZZ' ? '配置 Fuzz 任务' : '配置本地测试'}</summary>
    {#if mode === 'FUZZ'}<p class="fuzz-boundary">
        目标必须是预构建的 libFuzzer EXE；普通 EXE 不会自动转换或插桩。测试在 Windows 宿主机执行，非沙箱隔离。
      </p>{:else}<p class="muted">
        填写快照内的入口文件及输入。Python 支持函数级测试，C/C++ 支持单入口本地构建，原始二进制支持 PE
        x86/x64，预构建 libFuzzer 支持动态测试。
      </p>{/if}
    {#if !runtimeAdapterSupported}<div class="error-banner" role="alert">
        {mode === 'FUZZ'
          ? '当前 Fuzz 仅支持 PE x86/x64 的预构建 libFuzzer EXE。'
          : '运行适配器与当前目标不匹配；ELF 目标只能进行静态分析。'}
      </div>{/if}
    <form
      onsubmit={(event) => {
        event.preventDefault();
        void start();
      }}
    >
      <div class="runtime-config-row">
        {#if mode === 'VERIFY'}
          <label class="field"
            >配置模板<select
              value={adapter}
              disabled={busy}
              onchange={(event) => {
                adapter = event.currentTarget.value;
                template();
              }}
              >{#each adapterOptions as option}<option value={option.value}>{option.label}</option
                >{/each}</select
            ></label
          >{/if}
        <fieldset class="runtime-modes" disabled={busy}>
          <legend>测试方式</legend>
          <div role="group" aria-label="测试方式">
            <button type="button" aria-pressed={mode === 'VERIFY'} onclick={() => (mode = 'VERIFY')}
              ><Play size={14} />运行验证</button
            >
            <button
              type="button"
              aria-pressed={mode === 'FUZZ'}
              disabled={!fuzzSupported}
              onclick={() => (mode = 'FUZZ')}
              title="预构建 libFuzzer 的覆盖引导模糊测试"><FlaskConical size={14} />Fuzz</button
            >
          </div>
        </fieldset>
        <div class="runtime-template-actions">
          <button type="button" class="button secondary" disabled={busy} onclick={template}
            ><RefreshCw size={14} />填入模板</button
          >
          <button
            type="button"
            class="button secondary"
            disabled={busy || !reusableFinding}
            aria-busy={suggesting}
            title="根据 PE 二进制的 MEMORY_BOUNDS 发现生成 Fuzz 配置"
            onclick={() => void reuse()}
            >{#if suggesting}<LoaderCircle size={14} class="spin" />正在生成配置…{:else}<Sparkles
                size={14}
              />智能复用{/if}</button
          >
        </div>
      </div>
      {#if audit?.findings.length}<label class="field"
          >关联发现<select bind:value={selectedFinding} disabled={busy}
            ><option value="">独立测试</option>{#each audit.findings as finding}<option value={finding.id}
                >{finding.title}</option
              >{/each}</select
          ></label
        >{/if}
      {#if suggestion}<div class="plan-limitations" role="status">
          <p>{suggestion.rationale}</p>
          {#if suggestion.limitations.length}<ul>
              {#each suggestion.limitations as limitation}<li>{limitation}</li>{/each}
            </ul>{/if}
        </div>{/if}
      {#if mode === 'FUZZ'}
        <FuzzConfig {configJson} disabled={busy || !fuzzSupported} onchange={applyConfig} />
        <details class="fuzz-json">
          <summary>高级运行配置 JSON</summary>
          <label class="field"
            >运行配置 JSON<textarea
              class="runtime-config-editor"
              bind:this={configEditor}
              value={configJson}
              oninput={(event) => applyConfig(event.currentTarget.value)}
              spellcheck="false"
              disabled={busy}
            ></textarea></label
          >
        </details>
        {#if fuzzError}<p class="inline-error" role="alert">{fuzzError}</p>{/if}
        <label class="fuzz-consent"
          ><input type="checkbox" bind:checked={fuzzConfirmed} required disabled={busy} />已确认目标支持
          libFuzzer，并获授权在本机执行</label
        >
      {:else}<label class="field"
          >运行配置 JSON<textarea
            class="runtime-config-editor"
            bind:this={configEditor}
            value={configJson}
            oninput={(event) => applyConfig(event.currentTarget.value)}
            disabled={busy}
            spellcheck="false"
            required
          ></textarea></label
        >{/if}
      {#if configuredRecord && runtimePending(configuredRecord.status)}<p role="status">
          此配置已在{runtimeLabel(configuredRecord.status)}。<button
            type="button"
            class="text-button"
            onclick={() => onshowresults(configuredRecord.id)}
            >查看{mode === 'FUZZ' ? '模糊测试' : '验证'}进度<ArrowUpRight size={14} /></button
          >
        </p>{/if}
      <button
        class="button primary"
        disabled={busy ||
          !configJson.trim() ||
          !runtimeAdapterSupported ||
          (mode === 'FUZZ' && (Boolean(fuzzError) || !fuzzConfirmed)) ||
          Boolean(configuredRecord && runtimePending(configuredRecord.status))}
        >{#if submittingFinding === ''}<LoaderCircle size={15} class="spin" />正在提交{submittingMode ===
          'FUZZ'
            ? '模糊测试'
            : '验证'}…{:else}<Play size={15} />{mode === 'FUZZ'
            ? configuredRecord
              ? runtimePending(configuredRecord.status)
                ? '模糊测试处理中'
                : '再次运行模糊测试'
              : '开始模糊测试'
            : configuredRecord
              ? runtimePending(configuredRecord.status)
                ? '验证处理中'
                : '再次运行本地测试'
              : '开始本地测试'}{/if}</button
      >
    </form>
  </details>
</section>

<style>
  .runtime-panel {
    min-width: 0;
    border: 0;
    border-radius: 0;
  }
  .runtime-config {
    border: 0;
    border-top: 1px solid var(--line);
    border-radius: 0;
    padding: 18px 0 0;
    margin-bottom: 0;
  }
  .runtime-modes {
    border: 0;
    padding: 0;
    margin: 0;
    min-width: 0;
  }
  .runtime-modes legend {
    font-size: var(--text-sm);
    color: var(--text-secondary);
    margin-bottom: 6px;
  }
  .runtime-modes > div {
    display: flex;
    border: 1px solid var(--line);
    border-radius: var(--radius-sm);
    overflow: hidden;
  }
  .runtime-modes button {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    min-height: 38px;
    padding: 6px 12px;
    color: var(--text-secondary);
  }
  .runtime-modes button[aria-pressed='true'] {
    color: var(--accent);
    background: var(--accent-soft);
  }
  .fuzz-boundary {
    border-left: 3px solid var(--warning-line);
    padding-left: 12px;
    margin-top: 14px;
    color: var(--text-secondary);
    line-height: 1.7;
  }
  .fuzz-json .field {
    margin-top: 12px;
  }
  .fuzz-consent {
    display: flex;
    align-items: start;
    gap: 8px;
    font-size: var(--text-sm);
    color: var(--text-secondary);
    line-height: 1.7;
  }
  .fuzz-consent input {
    flex: none;
    margin-top: 5px;
  }
  .runtime-results-link {
    margin: 0 0 16px;
  }
  .runtime-submitting {
    margin: 12px 20px 0;
    color: var(--accent);
  }
  .runtime-panel > .panel-title {
    align-items: start;
    gap: 14px;
    flex-wrap: wrap;
  }
  .refresh-runtime {
    flex: none;
  }
  .runtime-plan {
    padding: 0;
    overflow: hidden;
  }
  .runtime-plan.ready {
    border-color: var(--success-line);
  }
  .runtime-plan-heading {
    display: grid;
    gap: 5px;
    padding: 20px 20px 16px;
  }
  .plan-label {
    font-size: var(--text-xs);
    font-weight: 600;
    color: var(--muted);
  }
  .runtime-plan-heading h3 {
    font-size: var(--text-lg);
    color: var(--ink);
    overflow-wrap: anywhere;
  }
  .runtime-plan-status {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 12px;
    margin: 0 20px;
    padding: 16px;
    border: 1px solid var(--warning-line);
    border-radius: var(--radius-md);
    background: var(--warning-soft);
    color: var(--warning);
  }
  .runtime-plan-status.ready {
    border-color: var(--success-line);
    background: var(--success-soft);
    color: var(--success);
  }
  .runtime-plan-status.unavailable {
    border-color: var(--line);
    background: var(--surface-subtle);
    color: var(--text-secondary);
  }
  .runtime-plan-status > div {
    flex: 1;
    min-width: 150px;
  }
  .runtime-plan-status strong {
    display: block;
    font-size: 18px;
    line-height: 1.5;
  }
  .runtime-plan-status p {
    margin-top: 4px;
    font-size: var(--text-sm);
    color: var(--text-secondary);
  }
  .runtime-plan-status .button {
    flex: none;
  }
  .runtime-plan-body {
    display: grid;
    gap: 18px;
    padding: 20px;
  }
  .runtime-plan-body h4 {
    display: flex;
    align-items: center;
    gap: 6px;
    margin: 0 0 8px;
    font-size: var(--text-base);
    color: var(--ink);
  }
  .plan-rationale p,
  .plan-limitations li {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    line-height: 1.8;
    color: var(--text-secondary);
  }
  .plan-facts {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 16px 24px;
    margin: 0;
    padding: 16px;
    background: var(--surface-subtle);
    border: 1px solid var(--line);
    border-radius: var(--radius-sm);
  }
  .plan-facts dt {
    margin-bottom: 4px;
    color: var(--muted);
    font-size: var(--text-xs);
  }
  .plan-facts dd {
    display: grid;
    gap: 3px;
    margin: 0;
    color: var(--text-secondary);
    font-weight: 500;
    overflow-wrap: anywhere;
  }
  .plan-facts small {
    font-weight: 400;
    color: var(--muted);
  }
  .plan-limitations {
    padding-left: 14px;
    border-left: 3px solid var(--warning-line);
  }
  .plan-limitations h4 {
    color: var(--warning);
  }
  .plan-limitations ul {
    display: grid;
    gap: 6px;
    padding-left: 18px;
    margin: 0;
  }
  .runtime-plan-body .runtime-actions {
    margin: 0;
  }
  .runtime-template-actions {
    display: flex;
    gap: 8px;
    align-items: center;
  }
  @media (max-width: 600px) {
    .runtime-panel {
      padding: var(--space-4);
    }
    .runtime-plan-heading,
    .runtime-plan-body {
      padding: var(--space-4);
    }
    .runtime-plan-status {
      margin: 0 var(--space-4);
      padding: 12px;
    }
    .runtime-plan-status .button {
      width: 100%;
    }
    .plan-facts {
      grid-template-columns: minmax(0, 1fr);
      padding: 12px;
    }
    .runtime-template-actions {
      flex-wrap: wrap;
    }
  }
</style>
