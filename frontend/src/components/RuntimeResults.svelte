<script lang="ts">
  import { onMount, tick, untrack } from 'svelte';
  import {
    ArrowUpRight,
    CheckCircle2,
    Download,
    Info,
    LoaderCircle,
    RefreshCw,
    Square,
  } from '@lucide/svelte';
  import { RunState, type AuditRun, type Finding, type RuntimeRecord } from '../gen/audit/v1/audit_pb';
  import { artifactUrl, errorMessage, runsApi } from '../lib/api';
  import { dateTime, parseJson, type Summary } from '../lib/format';
  import { runtimeFeedback, runtimeLabel, runtimePending, type RuntimeResult } from '../lib/runtime';

  let {
    runId,
    records,
    findings = [],
    focusId = '',
    focusVersion = 0,
    refreshing,
    loadError,
    hasPlans,
    onrefresh,
    onconfigure,
    onupdate,
    onevents,
    notify,
  }: {
    runId: string;
    records: RuntimeRecord[];
    findings?: Finding[];
    focusId?: string;
    focusVersion?: number;
    refreshing: boolean;
    loadError: string;
    hasPlans: boolean;
    onrefresh: () => Promise<void>;
    onconfigure?: () => void;
    onupdate: (record: RuntimeRecord) => void;
    onevents: () => void;
    notify: (message: string) => void;
  } = $props();
  let heading = $state<HTMLHeadingElement>();
  let detail = $state<AuditRun>();
  let detailError = $state('');
  let actionError = $state('');
  let cancelling = $state('');
  let detailVersion = $state(0);
  const controller = new AbortController();
  const newest = $derived([...records].reverse());
  const current = $derived(newest.find((record) => record.id === focusId) || newest[0]);
  const history = $derived(newest.filter((record) => record.id !== current?.id));
  const pendingCount = $derived(records.filter((record) => runtimePending(record.status)).length);
  const detailKey = $derived(current ? `${current.runId}:${current.status}` : '');
  const detailSummary = $derived(parseJson<Summary>(detail?.summaryJson || '', {}));
  const evidenceLinks = $derived(
    [
      { id: detailSummary.exploitation_artifact_id, label: '复现证据' },
      { id: detailSummary.exploitation_input_artifact_id, label: '复现输入包' },
      { id: detailSummary.exploitation_runner_artifact_id, label: '复放脚本' },
    ].filter((item): item is { id: string; label: string } => Boolean(item.id)),
  );

  $effect(() => {
    if (!focusVersion) return;
    let active = true;
    void tick().then(() => {
      if (!active) return;
      heading?.scrollIntoView({ block: 'start' });
      heading?.focus({ preventScroll: true });
    });
    return () => {
      active = false;
    };
  });
  $effect(() => {
    const key = detailKey;
    detailVersion;
    const record = untrack(() => current);
    if (!key || !record) return;
    const request = new AbortController();
    detail = undefined;
    detailError = '';
    void runsApi
      .getRun({ runId: record.runId }, { signal: request.signal })
      .then((response) => {
        if (!request.signal.aborted) detail = response.run;
      })
      .catch((failure) => {
        if (!request.signal.aborted) detailError = errorMessage(failure);
      });
    return () => request.abort();
  });

  async function cancel(record: RuntimeRecord) {
    if (cancelling || record.status === 'CANCELLING') return;
    cancelling = record.id;
    actionError = '';
    try {
      const response = await runsApi.cancelRun({ runId: record.runId }, { signal: controller.signal });
      if (controller.signal.aborted) return;
      if (!response.run) throw new Error('未收到取消后的任务状态，请刷新后重试');
      onupdate({ ...record, status: RunState[response.run.state] });
      notify('取消请求已记录，验证状态会自动更新');
      void onrefresh();
    } catch (failure) {
      if (!controller.signal.aborted) actionError = errorMessage(failure);
    } finally {
      cancelling = '';
    }
  }
  onMount(() => () => controller.abort());

  function observedEffect(config: Record<string, unknown>, result: RuntimeResult) {
    const observations = result.observation;
    const hits = observations.trials.filter((trial) => trial.observed);
    if (config.mode === 'FUZZ')
      return observations.crashes.some((crash) => crash.reproduced)
        ? '崩溃输入已重复复现，签名见下方记录。'
        : '本次未形成可重复复现的崩溃证据。';
    if (!hits.length) return '本次未观察到配置指定的现象。';
    if (config.observer === 'FILE_CREATED')
      return `观察到指定文件被创建：${String(config.marker_path || '见运行配置')}。`;
    const signatures = [...new Set(hits.map((trial) => trial.crash_signature).filter(Boolean))];
    if (signatures.length)
      return `观察到异常退出：${signatures.join('、')}。这确认了崩溃现象，未证明任意代码执行。`;
    if (config.observer === 'SANITIZER') return '观察到配置指定的崩溃或内存检测异常，详细输出见执行记录。';
    return '观察到配置指定的现象，详细输出见执行记录。';
  }
</script>

<section class="runtime-results panel" aria-label="验证进度与结果">
  <div class="panel-title">
    <div>
      <h2 tabindex="-1" bind:this={heading}>验证进度与结果</h2>
      <p class="subtle">
        {pendingCount
          ? `${pendingCount} 项验证处理中，状态自动更新。`
          : '查看是否复现、实际观察到的效果和已保存的证据。'}结果保留在本次分析中。
      </p>
    </div>
    <button
      class="button secondary small"
      disabled={refreshing}
      onclick={() => {
        detailVersion += 1;
        void onrefresh();
      }}
      aria-label="刷新验证结果"
    >
      <RefreshCw size={15} class={refreshing ? 'spin' : ''} />{refreshing ? '刷新中…' : '刷新结果'}
    </button>
  </div>
  {#if loadError}<div class="error-banner" role="alert">
      验证记录暂未更新：{loadError}。已显示的记录会保留。
    </div>{/if}
  {#if actionError}<div class="error-banner" role="alert">取消请求未确认：{actionError}</div>{/if}
  {#if current}
    <div class="runtime-records">
      {@render recordCard(current, true)}
    </div>
    {#if history.length}<details
        class="runtime-history"
        open={history.some((record) => runtimePending(record.status))}
      >
        <summary
          >其他验证记录 · {history.length} 次{#if pendingCount > Number(runtimePending(current.status))}
            · 包含正在执行的验证{/if}</summary
        >
        <div class="runtime-records">
          {#each history as record (record.id)}{@render recordCard(record, false)}{/each}
        </div>
      </details>{/if}
  {:else}<div class="runtime-empty" role="status">
      {#if refreshing}<LoaderCircle size={20} class="spin" />
        <p>正在读取验证记录…</p>
      {:else}<Info size={20} />
        <p>
          {hasPlans ? '验证方案已生成，尚未启动运行。查看方案后可开始验证。' : '尚无运行记录，可刷新重试。'}
        </p>{/if}
    </div>{/if}
  {#if onconfigure}<div class="runtime-footer">
      <button class="button secondary" onclick={onconfigure}
        >{hasPlans ? '查看验证方案与配置' : '配置本地测试'}<ArrowUpRight size={14} /></button
      >
    </div>{/if}
</section>

{#snippet recordCard(record: RuntimeRecord, featured: boolean)}
  {@const config = parseJson<Record<string, unknown>>(record.configJson, {})}
  {@const result = parseJson<RuntimeResult | null>(record.resultJson, null)}
  {@const feedback = runtimeFeedback(record, result)}
  {@const pending = runtimePending(record.status)}
  {@const baseline = result?.observation.trials.filter((trial) => trial.label === 'baseline') || []}
  {@const probes = result?.observation.trials.filter((trial) => trial.label !== 'baseline') || []}
  <article class="runtime-record" class:featured data-status={record.status} data-record-id={record.id}>
    <div class="runtime-record-heading">
      <div>
        <span class="runtime-record-label"
          >{featured ? (focusId === record.id ? '本次验证' : '最近验证') : '历史验证'} · {dateTime(
            record.createdAt,
          )}</span
        >
        <h3>
          {findings.find((finding) => finding.id === record.findingId)?.title ||
            String(config.path || '本地测试')}
        </h3>
        <p class="subtle">
          {runtimeLabel(String(config.mode || 'VERIFY'))} ·
          <code>{String(config.path || '')}</code>{#if config.function}
            · <code>{String(config.function)}()</code>{/if}
        </p>
      </div>
      <span class={`badge ${feedback.tone}`}>{runtimeLabel(record.status)}</span>
    </div>
    <div
      class={`runtime-verdict ${feedback.tone}`}
      role="status"
      aria-live={featured ? 'polite' : 'off'}
      aria-atomic="true"
    >
      {#if pending}<LoaderCircle
          size={24}
          class="spin"
        />{:else if ['REPRODUCED', 'VERIFIED_COMPONENT'].includes(record.status)}<CheckCircle2
          size={24}
        />{:else}<Info size={24} />{/if}
      <div>
        <strong>{feedback.title}</strong>
        <p>{feedback.detail}</p>
      </div>
    </div>
    <ol class="runtime-steps" aria-label="验证阶段">
      <li class:done={true}><CheckCircle2 size={15} />任务已创建</li>
      <li class:done={Boolean(result)} class:current={record.status === 'RUNNING'}>
        {record.status === 'RUNNING'
          ? '正在执行验证'
          : result
            ? '验证已执行'
            : ['QUEUED', 'WAITING_EXECUTOR'].includes(record.status)
              ? '等待执行'
              : '执行未完成'}
      </li>
      <li class:done={Boolean(result)}>{result ? '结果已保存' : pending ? '等待结果' : '未形成完整结果'}</li>
    </ol>
    {#if result}
      <div class="runtime-observations">
        <h4>验证效果</h4>
        <dl>
          <div>
            <dt>验证范围</dt>
            <dd>{runtimeLabel(result.target_scope)}</dd>
          </div>
          {#if config.mode === 'FUZZ'}
            <div>
              <dt>测试次数</dt>
              <dd>
                {result.observation.fuzz.executions ?? 0} 次 · {result.observation.fuzz.timeouts ?? 0} 次超时
              </dd>
            </div>
            <div>
              <dt>稳定复现的崩溃</dt>
              <dd>{result.observation.crashes.filter((crash) => crash.reproduced).length} 个</dd>
            </div>
          {:else}
            <div>
              <dt>正常输入</dt>
              <dd>
                {baseline.length
                  ? baseline.some((trial) => trial.timed_out || trial.exception)
                    ? '执行异常，请核对记录'
                    : baseline.some((trial) => trial.observed)
                      ? '也触发了指定现象'
                      : '未触发指定现象'
                  : '无对照记录'}
              </dd>
            </div>
            <div>
              <dt>异常输入</dt>
              <dd>{probes.filter((trial) => trial.observed).length} / {probes.length} 次触发指定现象</dd>
            </div>
          {/if}
        </dl>
        <p class="runtime-observed-effect">{observedEffect(config, result)}</p>
        {#if baseline.some((trial) => trial.observed)}<p class="inline-error">
            正常输入也触发了指定现象，不能仅凭异常输入触发就认定利用成功。
          </p>{/if}
        {#if result.observation.error}<p class="inline-error">{result.observation.error}</p>{/if}
      </div>
      {#if result.observation.trials.length}<div class="table-scroll">
          <table>
            <thead><tr><th>输入</th><th>退出码</th><th>观察结果</th><th>执行情况</th></tr></thead>
            <tbody
              >{#each result.observation.trials as trial, index}<tr>
                  <td>{trial.label === 'baseline' ? '正常输入' : `复测 ${index}`}</td>
                  <td>{trial.exit_code ?? '—'}</td><td>{trial.observed ? '观察到指定现象' : '未观察到'}</td>
                  <td
                    >{trial.timed_out
                      ? '超时'
                      : trial.exception || trial.crash_signature || '执行结束'}{trial.truncated
                      ? ' · 日志已截断'
                      : ''}</td
                  >
                </tr>{/each}</tbody
            >
          </table>
        </div>{/if}
      {#if config.mode === 'FUZZ'}
        <p class="subtle">
          {runtimeLabel(result.observation.fuzz.engine || '')} · {result.observation.fuzz.coverage_feedback
            ? `覆盖反馈：${result.observation.fuzz.bitmap_cvg || '见原始统计'}`
            : '未使用覆盖反馈。'}
        </p>
        {#each result.observation.crashes as crash}<div class="runtime-crash">
            <strong>{crash.signature}</strong>
            <p>
              {crash.reproduced ? '已重复复现' : '尚未稳定复现'} · {crash.minimized
                ? '已缩减输入'
                : '保留原始输入'}
            </p>
            <code>SHA-256 {crash.input_sha256}</code>
          </div>{/each}
      {/if}
    {/if}
    {#if featured && detail?.error}<p class="inline-error">执行原因：{detail.error}</p>{/if}
    <div class="runtime-actions">
      {#if pending}<button
          class="button secondary small"
          disabled={Boolean(cancelling) || record.status === 'CANCELLING'}
          onclick={() => cancel(record)}
          ><Square size={13} />{cancelling === record.id
            ? '正在提交取消…'
            : record.status === 'CANCELLING'
              ? '正在取消…'
              : '取消运行'}</button
        >{/if}
      {#if record.runId === runId}<button class="text-button" onclick={onevents}
          >查看任务事件<ArrowUpRight size={13} /></button
        ><a class="text-button" href={`#/runs/${record.sourceRunId}`}>原始分析<ArrowUpRight size={13} /></a>
      {:else}<a class="text-button" href={`#/runs/${record.runId}`}>打开验证任务<ArrowUpRight size={13} /></a
        >{/if}
      {#if result?.recipe_artifact_id}<a class="text-button" href={artifactUrl(result.recipe_artifact_id)}
          >测试配置与脚本<Download size={13} /></a
        >{/if}
      {#if result?.observation_artifact_id}<a
          class="text-button"
          href={artifactUrl(result.observation_artifact_id)}>原始观察<Download size={13} /></a
        >{/if}
      {#each result?.tools || [] as tool}{#if tool.log_artifact_id}<a
            class="text-button"
            href={artifactUrl(tool.log_artifact_id)}>{tool.name} 日志<Download size={13} /></a
          >{/if}{/each}
      {#if featured}{#each evidenceLinks as item}<a class="text-button" href={artifactUrl(item.id)}
            >{item.label}<Download size={13} /></a
          >{/each}{/if}
    </div>
    {#if featured && detailError}<p class="subtle">任务详情暂未更新：{detailError}。可刷新结果重试。</p>{/if}
    {#if result}
      <details>
        <summary>执行输出与构建信息</summary>
        <pre>{JSON.stringify(result.observation, null, 2)}</pre>
      </details>
      <details>
        <summary>目标、配置与执行环境</summary>
        <dl class="runtime-hash">
          <dt>目标 SHA-256</dt>
          <dd><code>{result.target_sha256}</code></dd>
          <dt>配置 SHA-256</dt>
          <dd><code>{result.config_hash}</code></dd>
          <dt>执行环境</dt>
          <dd><code>{result.image_id}</code></dd>
        </dl>
      </details>
    {/if}
    <details>
      <summary>本次冻结的配置</summary>
      <pre>{JSON.stringify(config, null, 2)}</pre>
    </details>
  </article>
{/snippet}

<style>
  .runtime-results {
    min-width: 0;
    border-color: var(--accent-line, var(--line));
  }
  .runtime-results > .panel-title {
    align-items: start;
    flex-wrap: wrap;
    gap: 12px;
    padding: 20px;
  }
  h2 {
    scroll-margin-top: 90px;
  }
  h2:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 6px;
    border-radius: 2px;
  }
  .panel-title p {
    margin-top: 6px;
    line-height: 1.7;
  }
  .runtime-records {
    padding: 0 20px;
  }
  .runtime-record {
    min-width: 0;
  }
  .runtime-record.featured {
    border-color: var(--accent-line, var(--line));
    background: var(--surface);
  }
  .runtime-record-heading {
    display: flex;
    align-items: start;
    justify-content: space-between;
    gap: 12px;
    flex-wrap: wrap;
  }
  .runtime-record-heading > div {
    min-width: 0;
    flex: 1;
  }
  .runtime-record-label {
    font-size: var(--text-xs);
    color: var(--muted);
  }
  .runtime-record h3 {
    margin: 8px 0;
    font-size: var(--text-lg);
    overflow-wrap: anywhere;
  }
  .runtime-record p,
  .runtime-record code {
    overflow-wrap: anywhere;
  }
  .runtime-verdict {
    display: flex;
    align-items: start;
    gap: 12px;
    margin: 18px 0 12px;
    padding: 16px;
    background: var(--surface-subtle);
    border: 1px solid var(--line);
    border-radius: var(--radius-md);
  }
  .runtime-verdict :global(svg) {
    flex: none;
    margin-top: 2px;
  }
  .runtime-verdict strong {
    display: block;
    font-size: 19px;
    line-height: 1.5;
  }
  .runtime-verdict p {
    margin-top: 5px;
    font-size: var(--text-sm);
    line-height: 1.8;
    color: var(--text-secondary);
  }
  .runtime-verdict.warning {
    background: var(--warning-soft);
    border-color: var(--warning-line);
    color: var(--warning);
  }
  .runtime-verdict.danger {
    background: var(--danger-soft);
    border-color: var(--danger-line);
    color: var(--danger);
  }
  .runtime-steps {
    display: flex;
    flex-wrap: wrap;
    gap: 8px 24px;
    margin: 0 0 20px;
    padding: 0;
    list-style: none;
    color: var(--muted);
    font-size: var(--text-sm);
  }
  .runtime-steps li {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .runtime-steps .done {
    color: var(--text-secondary);
  }
  .runtime-steps .current {
    color: var(--accent);
    font-weight: 600;
  }
  .runtime-observations {
    padding: 16px;
    margin: 16px 0;
    background: var(--surface-subtle);
    border-radius: var(--radius-sm);
  }
  .runtime-observations h4 {
    margin: 0 0 12px;
  }
  .runtime-observations dl {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 12px;
    margin: 0;
  }
  .runtime-observations dt {
    color: var(--muted);
    font-size: var(--text-xs);
    margin-bottom: 6px;
  }
  .runtime-observations dd {
    margin: 0;
    font-weight: 500;
    overflow-wrap: anywhere;
  }
  .runtime-observed-effect {
    margin-top: 16px;
    line-height: 1.8;
  }
  .runtime-record .table-scroll {
    margin: 16px 0;
  }
  .runtime-record table {
    width: 100%;
    font-size: var(--text-sm);
  }
  .runtime-record th,
  .runtime-record td {
    white-space: normal;
    overflow-wrap: anywhere;
    padding: 10px;
  }
  .runtime-hash {
    margin-top: 14px;
  }
  .runtime-hash dd {
    margin: 0;
    min-width: 0;
  }
  .runtime-history {
    margin: 0 20px 20px;
  }
  .runtime-history > summary {
    cursor: pointer;
    font-weight: 500;
    padding-bottom: 12px;
  }
  .runtime-history .runtime-records {
    padding: 0;
  }
  .runtime-footer {
    padding: 0 20px 20px;
  }
  .runtime-empty {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 0 20px 20px;
    color: var(--muted);
  }
  .error-banner {
    margin: 0 20px 18px;
  }
  @media (max-width: 600px) {
    .runtime-results > .panel-title {
      padding: 16px;
    }
    .runtime-records {
      padding: 0 12px;
    }
    .runtime-record {
      padding: 14px;
    }
    .runtime-verdict {
      padding: 12px;
      gap: 8px;
    }
    .runtime-verdict strong {
      font-size: 17px;
    }
    .runtime-observations {
      padding: 12px;
    }
    .runtime-observations dl {
      grid-template-columns: minmax(0, 1fr);
    }
    .runtime-hash {
      grid-template-columns: minmax(0, 1fr);
    }
    .runtime-steps {
      gap: 8px 16px;
      font-size: var(--text-xs);
    }
    .runtime-record th,
    .runtime-record td {
      padding: 8px 5px;
      font-size: var(--text-xs);
    }
    .runtime-history {
      margin: 0 12px 16px;
    }
    .runtime-footer {
      padding: 0 16px 16px;
    }
  }
</style>
