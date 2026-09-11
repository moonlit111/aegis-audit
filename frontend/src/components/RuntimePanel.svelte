<script lang="ts">
  import { onMount } from 'svelte';
  import { Play, RefreshCw, Square, Download, ArrowUpRight } from '@lucide/svelte';
  import type {
    AuditRun,
    ProgramUnit,
    RuntimeRecord,
    GetAuditResponse,
    AgentTask,
    Snapshot,
  } from '../gen/audit/v1/audit_pb';
  import { TargetKind } from '../gen/audit/v1/audit_pb';
  import { artifactUrl, errorMessage, findingsApi, requestId, runsApi, runtimeApi } from '../lib/api';
  import { dateTime, isTerminal, parseJson } from '../lib/format';
  import {
    runtimeLabel,
    runtimePending,
    runtimeTemplate,
    type RuntimeResult,
    type VerificationPlan,
  } from '../lib/runtime';

  let {
    run,
    snapshot,
    unit,
    findingId = '',
    active = true,
    onchanged,
    notify,
  }: {
    run: AuditRun;
    snapshot?: Snapshot;
    unit?: ProgramUnit;
    findingId?: string;
    active?: boolean;
    onchanged: () => Promise<void>;
    notify: (message: string) => void;
  } = $props();
  let records = $state<RuntimeRecord[]>([]);
  let audit = $state<GetAuditResponse>();
  let configJson = $state('');
  let adapter = $state('NATIVE_SOURCE');
  let mode = $state('VERIFY');
  let selectedFinding = $state('');
  let error = $state('');
  let busy = $state(false);
  let loading: Promise<void> | undefined;
  let loaded = false;
  let alive = true;
  const controller = new AbortController();
  const snapshotMetadata = $derived(
    parseJson<{ architecture?: string; format?: string }>(snapshot?.metadataJson || '', {}),
  );
  const adapterOptions = $derived.by(() => {
    if (mode === 'FUZZ') {
      return snapshot?.kind === TargetKind.BINARY && snapshotMetadata.format === 'PE'
        ? [{ value: 'WINDOWS_LIBFUZZER_PREBUILT', label: '预构建 libFuzzer' }]
        : [];
    }
    if (snapshot?.kind === TargetKind.BINARY) {
      return snapshotMetadata.format === 'PE'
        ? [
            { value: 'WINDOWS_ORIGINAL_PE32', label: '原始 PE32' },
            { value: 'WINDOWS_ORIGINAL_PE64', label: '原始 PE64' },
          ]
        : [];
    }
    return [
      { value: 'WINDOWS_PYTHON_CALL', label: 'Python 函数' },
      { value: 'WINDOWS_NATIVE_SOURCE', label: 'C / C++' },
    ];
  });
  const runtimeAdapterSupported = $derived(adapterOptions.length > 0);
  const fuzzSupported = $derived(snapshot?.kind === TargetKind.BINARY && snapshotMetadata.format === 'PE');
  $effect(() => {
    if (adapterOptions.length && !adapterOptions.some((option) => option.value === adapter)) {
      adapter = adapterOptions[0].value;
      configJson = runtimeTemplate(adapter, mode, unit);
    }
  });
  $effect(() => {
    selectedFinding = findingId;
  });
  const isRuntimeRun = $derived(['RUNTIME_VERIFICATION', 'DYNAMIC_TESTING'].includes(run.scope));
  const plans = $derived(
    (audit?.tasks || []).filter((t) => t.role === 'VERIFIER' && t.status === 'SUCCEEDED'),
  );

  function template() {
    configJson = runtimeTemplate(adapter, mode, unit);
  }
  function refresh() {
    if (loading) return loading;
    loading = (async () => {
      try {
        const response = await runtimeApi.listRuntime({ runId: run.id }, { signal: controller.signal });
        if (alive) {
          records = response.records;
          error = '';
        }
        if (run.scope === 'SECURITY_AUDIT') {
          const response = await findingsApi.getAudit({ runId: run.id }, { signal: controller.signal });
          if (alive) audit = response;
        }
      } catch (failure) {
        if (alive) error = errorMessage(failure);
      }
    })().finally(() => {
      loading = undefined;
    });
    return loading;
  }
  function loadPlan(task: AgentTask) {
    const plan = parseJson<VerificationPlan>(task.resultJson, {
      status: '',
      rationale: '',
      limitations: [],
      config: null,
    });
    if (!plan.config) return;
    selectedFinding = task.itemKey;
    configJson = JSON.stringify(plan.config, null, 2);
  }
  async function start(savedFinding = '') {
    if (busy) return;
    busy = true;
    error = '';
    try {
      if (!savedFinding) JSON.parse(configJson);
      await runtimeApi.createRuntime({
        requestId: requestId(),
        sourceRunId: run.id,
        findingId: savedFinding || selectedFinding,
        configJson: savedFinding ? '' : configJson,
      });
      await refresh();
      await onchanged();
      notify('运行任务已创建，结果会保存在当前分析中。');
    } catch (failure) {
      error = errorMessage(failure);
    } finally {
      busy = false;
    }
  }

  async function reuse() {
    if (busy || !selectedFinding) return;
    busy = true;
    error = '';
    try {
      const response = await runtimeApi.suggestRuntime({
        requestId: requestId(),
        sourceRunId: run.id,
        findingId: selectedFinding,
      });
      configJson = response.configJson;
      notify(response.rationale || '已生成可复用的动态测试配置。');
    } catch (failure) {
      error = errorMessage(failure);
    } finally {
      busy = false;
    }
  }
  async function cancel(record: RuntimeRecord) {
    try {
      await runsApi.cancelRun({ runId: record.runId });
      await refresh();
      notify('取消请求已记录，正在等待宿主机运行进程回收。');
    } catch (failure) {
      error = errorMessage(failure);
    }
  }
  onMount(() => {
    adapter =
      unit?.language === 'python'
        ? 'WINDOWS_PYTHON_CALL'
        : unit?.language === 'binary'
          ? snapshotMetadata.architecture === 'x86'
            ? 'WINDOWS_ORIGINAL_PE32'
            : 'WINDOWS_ORIGINAL_PE64'
          : 'WINDOWS_NATIVE_SOURCE';
    template();
    const timer = setInterval(() => {
      if (active && (!isTerminal(run.state) || records.some((r) => runtimePending(r.status)))) void refresh();
    }, 1800);
    return () => {
      alive = false;
      controller.abort();
      clearInterval(timer);
    };
  });
  $effect(() => {
    if (active && !loaded) {
      loaded = true;
      void refresh();
    }
  });
</script>

<section class="runtime-panel">
  <div class="panel-title">
    <div>
      <h2>运行验证与动态测试</h2>
      <p class="subtle">每次运行保存正常输入、执行输出、复测记录和测试范围。</p>
    </div>
    <button class="text-button" onclick={() => refresh()} aria-label="刷新运行结果"
      ><RefreshCw size={16} /></button
    >
  </div>
  {#if error}<div class="error-banner" role="alert">
      <span>{error}</span><button
        class="text-button"
        onclick={() => {
          error = '';
        }}>关闭</button
      >
    </div>{/if}
  {#if !isRuntimeRun}
    {#if plans.length}
      <div class="runtime-plans">
        {#each plans as task}
          {@const plan = parseJson<VerificationPlan>(task.resultJson, {
            status: '',
            rationale: '',
            limitations: [],
            config: null,
          })}
          <article class="runtime-plan">
            <div>
              <strong>{audit?.findings.find((f) => f.id === task.itemKey)?.title || '验证方案'}</strong><span
                class="badge neutral">{runtimeLabel(plan.status)}</span
              >
            </div>
            <p>{plan.rationale}</p>
            {#if plan.limitations.length}<ul class="muted">
                {#each plan.limitations as limitation}<li>{limitation}</li>{/each}
              </ul>{/if}
            {#if plan.config}<div class="runtime-actions">
                <button class="button secondary" onclick={() => loadPlan(task)}>查看并调整配置</button><button
                  class="button primary"
                  disabled={busy}
                  onclick={() => start(task.itemKey)}><Play size={14} />按方案运行</button
                >
              </div>{/if}
          </article>
        {/each}
      </div>
    {/if}
    <details class="runtime-config" open={!plans.length}>
      <summary>配置本地测试</summary>
      <p class="muted">
        填写快照内的入口文件及输入。Python 支持函数级测试，C/C++ 支持单入口本地构建，原始二进制支持 PE
        x86/x64，预构建 libFuzzer 支持动态测试。
      </p>
      {#if !runtimeAdapterSupported}<div class="error-banner" role="alert">
          当前运行器仅支持 PE x86/x64；ELF 目标只能进行静态分析。
        </div>{/if}
      <form
        onsubmit={(event) => {
          event.preventDefault();
          void start();
        }}
      >
        <div class="runtime-config-row">
          <label class="field"
            >配置模板<select bind:value={adapter}
              >{#each adapterOptions as option}<option value={option.value}>{option.label}</option
                >{/each}</select
            ></label
          >
          <label class="field"
            >测试方式<select bind:value={mode}
              ><option value="VERIFY">正常输入与重复验证</option><option
                value="FUZZ"
                disabled={!fuzzSupported}>动态测试（libFuzzer）</option
              ></select
            ></label
          >
          <div class="runtime-template-actions">
            <button type="button" class="button secondary" onclick={template}>填入模板</button>
            <button
              type="button"
              class="button secondary"
              disabled={busy || !selectedFinding}
              onclick={() => void reuse()}>智能复用</button
            >
          </div>
        </div>
        {#if audit?.findings.length}<label class="field"
            >关联发现<select bind:value={selectedFinding}
              ><option value="">独立测试</option>{#each audit.findings as finding}<option value={finding.id}
                  >{finding.title}</option
                >{/each}</select
            ></label
          >{/if}
        <label class="field"
          >运行配置 JSON<textarea
            class="runtime-config-editor"
            bind:value={configJson}
            spellcheck="false"
            required
          ></textarea></label
        >
        <button class="button primary" disabled={busy || !configJson.trim() || !runtimeAdapterSupported}
          ><Play size={15} />{busy ? '创建中…' : '开始本地测试'}</button
        >
      </form>
    </details>
  {/if}
  <div class="runtime-records">
    {#each records as record}
      {@const config = parseJson<{ mode: string; path: string }>(record.configJson, { mode: '', path: '' })}
      {@const result = parseJson<RuntimeResult | null>(record.resultJson, null)}
      <article class="runtime-record" data-status={record.status}>
        <div class="panel-title">
          <h3>{runtimeLabel(config.mode)} · {config.path}</h3>
          <span
            class={`badge ${['ERROR', 'FAILED'].includes(record.status) ? 'danger' : runtimePending(record.status) ? 'neutral' : 'warning'}`}
            >{runtimeLabel(record.status)}</span
          >
        </div>
        <p class="subtle">
          {dateTime(record.createdAt)}{#if result}
            · {runtimeLabel(result.target_scope)}{/if}
        </p>
        <div class="runtime-actions">
          <a class="text-button" href={`#/runs/${record.runId}`}>任务与事件<ArrowUpRight size={13} /></a>
          {#if isRuntimeRun}<a class="text-button" href={`#/runs/${record.sourceRunId}`}
              >原始分析<ArrowUpRight size={13} /></a
            >{/if}
          {#if runtimePending(record.status)}<button
              class="text-button"
              disabled={record.status === 'CANCELLING'}
              onclick={() => cancel(record)}><Square size={13} />取消运行</button
            >{/if}
          {#if result}<a class="text-button" href={artifactUrl(result.recipe_artifact_id)}
              >测试配置与脚本<Download size={13} /></a
            ><a class="text-button" href={artifactUrl(result.observation_artifact_id)}
              >原始观察<Download size={13} /></a
            >{#each result.tools as tool}<a class="text-button" href={artifactUrl(tool.log_artifact_id)}
                >{tool.name} 日志<Download size={13} /></a
              >{/each}{/if}
        </div>
        {#if result}
          {#if result.observation.error}<p class="inline-error">{result.observation.error}</p>{/if}
          {#if result.observation.trials.length}<div class="table-scroll">
              <table>
                <thead><tr><th>输入</th><th>退出码</th><th>观察结果</th><th>状态</th></tr></thead><tbody
                  >{#each result.observation.trials as trial, index}<tr
                      ><td>{trial.label === 'baseline' ? '正常输入' : `复测 ${index}`}</td><td
                        >{trial.exit_code ?? '—'}</td
                      ><td>{trial.observed ? '观察到指定现象' : '未观察到'}</td><td
                        >{trial.timed_out ? '超时' : trial.exception || '执行结束'}{trial.truncated
                          ? ' · 日志已截断'
                          : ''}</td
                      ></tr
                    >{/each}</tbody
                >
              </table>
            </div>{/if}
          {#if config.mode === 'FUZZ'}<p>
              {runtimeLabel(result.observation.fuzz.engine || '')} · {result.observation.fuzz.executions ?? 0}
              次执行 · {result.observation.fuzz.timeouts ?? 0} 次超时
            </p>
            <p class="muted">
              {result.observation.fuzz.coverage_feedback
                ? `覆盖反馈：${result.observation.fuzz.bitmap_cvg || '见原始统计'}`
                : '按输入变异执行，未使用覆盖反馈。'}
            </p>
            {#each result.observation.crashes as crash}<div class="runtime-crash">
                <strong>{crash.signature}</strong>
                <p>
                  {crash.reproduced ? '已重复复现' : '尚未稳定复现'} · {crash.minimized
                    ? '已缩减输入'
                    : '保留原始输入'}
                </p>
                <code>SHA-256 {crash.input_sha256}</code>
              </div>{/each}{/if}
          <details>
            <summary>执行输出与构建信息</summary>
            <pre>{JSON.stringify(result.observation, null, 2)}</pre>
          </details>
          <p class="runtime-hash">
            <span>目标 SHA-256</span><code>{result.target_sha256}</code><span>配置 SHA-256</span><code
              >{result.config_hash}</code
            ><span>执行环境</span><code>{result.image_id}</code>
          </p>
        {/if}
        <details>
          <summary>本次冻结的配置</summary>
          <pre>{JSON.stringify(JSON.parse(record.configJson), null, 2)}</pre>
        </details>
      </article>
    {/each}
    {#if !records.length}<p class="empty-panel compact">
        尚无运行记录。创建测试后可在这里查看进度和证据。
      </p>{/if}
  </div>
  <p class="field-help">
    组件内验证、插桩构建和原始程序执行分别记录。未复现或未观察到崩溃，仅说明本次输入和预算下的结果。
  </p>
</section>

<style>
  .runtime-template-actions {
    display: flex;
    gap: 8px;
    align-items: center;
  }
</style>
