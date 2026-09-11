<script lang="ts">
  import { onMount } from 'svelte';
  import {
    ArrowUpRight,
    ShieldCheck,
    FileSearch,
    RefreshCw,
    Save,
    Code2,
    FlaskConical,
  } from '@lucide/svelte';
  import type {
    AuditRun,
    Finding,
    GetAuditResponse,
    GetFindingResponse,
    ProgramUnit,
    RuntimeRecord,
  } from '../gen/audit/v1/audit_pb';
  import AuditPlan from './AuditPlan.svelte';
  import AnnotationsPanel from './AnnotationsPanel.svelte';
  import { artifactUrl, errorMessage, findingsApi, requestId } from '../lib/api';
  import { dateTime, isTerminal, parseJson, type Summary } from '../lib/format';
  import {
    runtimeLabels,
    runtimePending,
    runtimeFeedback,
    readRuntimeConfig,
    verificationPlans,
    type RuntimeResult,
  } from '../lib/runtime';

  let {
    run,
    active = true,
    onselectunit,
    onverify,
    onfuzz,
    onresults,
    loadAudit,
    runtimeRecords,
    notify,
    knownUnits,
  }: {
    run: AuditRun;
    active?: boolean;
    onselectunit: (id: string) => void;
    onverify: (id: string) => void;
    onfuzz?: (id: string) => void;
    onresults: (id: string) => void;
    loadAudit: () => Promise<GetAuditResponse>;
    runtimeRecords: RuntimeRecord[];
    notify: (message: string) => void;
    knownUnits: ProgramUnit[];
  } = $props();
  let data = $state<GetAuditResponse>();
  let error = $state('');
  let selectedId = $state('');
  let filter = $state('');
  let view = $state<'findings' | 'annotations' | 'agents' | 'reviews'>('findings');
  let verdict = $state('INCONCLUSIVE');
  let rationale = $state('');
  let counterEvidence = $state('');
  let missingInformation = $state('');
  let reviewRevision = $state(0);
  let busy = $state(false);
  let refreshing = $state(false);
  let detail = $state<GetFindingResponse>();
  let findings = $state<Finding[]>([]);
  let findingTotal = $state(0);
  let offset = $state(0);
  let queueGeneration = 0;
  let loading = false;
  let refreshAgain = false;
  let alive = true;
  const controller = new AbortController();
  const summary = $derived(parseJson<Summary>(run.summaryJson, {}));
  const selected = $derived(detail?.finding);
  const selectedPlan = $derived(verificationPlans(data?.tasks).some((task) => task.itemKey === selected?.id));
  const selectedRuntime = $derived(
    [...runtimeRecords].reverse().find((record) => record.findingId === selected?.id),
  );
  const runtimeAction = $derived(
    readRuntimeConfig(selectedRuntime?.configJson || '')?.mode === 'FUZZ' ? '模糊测试' : '验证',
  );
  const reviews = $derived(detail?.reviews || []);
  const reviewCounts = $derived(
    ['UNREVIEWED', 'VALIDATED', 'REJECTED', 'INCONCLUSIVE'].map((status) => ({
      status,
      count: data?.findings.filter((f) => f.reviewStatus === status).length || 0,
    })),
  );
  const pendingHuman = $derived(
    data?.findings.filter((f) => !data?.reviews.some((r) => r.findingId === f.id && r.actor === 'HUMAN'))
      .length || 0,
  );
  const totalTokens = $derived(
    (data?.modelCalls || []).filter((c) => c.usageAvailable).reduce((n, c) => n + c.totalTokens, 0n),
  );
  const unknownUsage = $derived((data?.modelCalls || []).filter((c) => !c.usageAvailable).length);
  const labels: Record<string, string> = {
    ...runtimeLabels,
    UNREVIEWED: '待复核',
    VALIDATED: '静态复核成立',
    REJECTED: '已驳回',
    INCONCLUSIVE: '依据不足',
    NOT_RUN: '未执行',
    AUTHENTICATION: '认证',
    CRYPTOGRAPHY: '加解密',
    REGISTRATION: '注册',
    PLANNER: '编排',
    REVERSE: '导入与逆向',
    AUDITOR: '语义审计',
    REVIEWER: '独立复核',
    REPORTER: '报告',
    VERIFIER: '验证方案',
    RUNNING: '执行中',
    SUCCEEDED: '完成',
    FAILED: '失败',
    INTERRUPTED: '已中断',
    INVALID_RESPONSE: '响应未通过校验',
    CRITICAL: '严重',
    HIGH: '高危',
    MEDIUM: '中危',
    LOW: '低危',
    UNKNOWN: '待定',
  };
  const label = (value: string) => labels[value] || value;
  const severityTone = (value: string) =>
    ['CRITICAL', 'HIGH'].includes(value) ? 'danger' : value === 'MEDIUM' ? 'warning' : 'neutral';
  const runtimeStatus = $derived.by(() => {
    const records = runtimeRecords;
    if (records.some((record) => runtimePending(record.status))) return '执行中';
    const statuses = records
      .filter((record) => !runtimePending(record.status))
      .map((record) => record.status);
    if (!statuses.length) return '未执行';
    if (statuses.includes('REPRODUCED')) return '已复现异常';
    if (statuses.includes('VERIFIED_COMPONENT')) return '组件验证成立';
    if (statuses.includes('INCONCLUSIVE')) return '结果不确定';
    if (statuses.includes('NOT_REPRODUCED')) return '本次未复现';
    if (statuses.includes('NO_CRASH_OBSERVED')) return '未观察到崩溃';
    return label(statuses[statuses.length - 1] || '');
  });
  const exploitationStatus = $derived.by(() => {
    if (summary.exploitation === 'COMPLETED') return '复现证据已保存';
    if (summary.exploitation && summary.exploitation !== 'NOT_RUN') {
      return label(summary.exploitation);
    }
    return '';
  });
  const exploitationArtifacts = $derived.by(() =>
    [
      { id: summary.exploitation_artifact_id, name: '利用证据', hint: '目标哈希、探针与两次运行观察' },
      { id: summary.exploitation_input_artifact_id, name: '复现配方', hint: '测试文件与探针参数' },
      { id: summary.exploitation_runner_artifact_id, name: '复放脚本', hint: '自建目录重放同一输入' },
    ].filter((item): item is { id: string; name: string; hint: string } => !!item.id),
  );
  async function refresh() {
    if (loading) {
      refreshAgain = true;
      return;
    }
    loading = true;
    refreshing = true;
    try {
      const response = await loadAudit();
      if (!alive) return;
      data = response;
      error = '';
      await loadQueue();
      if (selectedId) await loadDetail(selectedId, false);
    } catch (failure) {
      if (alive) error = errorMessage(failure);
    } finally {
      loading = false;
      refreshing = false;
      if (refreshAgain && alive) {
        refreshAgain = false;
        void refresh();
      }
    }
  }
  async function loadQueue(resetSelection = false) {
    const generation = ++queueGeneration;
    try {
      const response = await findingsApi.listFindings(
        { runId: run.id, reviewStatus: filter, offset, limit: 50 },
        { signal: controller.signal },
      );
      if (!alive || generation !== queueGeneration) return;
      findings = response.findings;
      findingTotal = Number(response.total);
      if (!selectedId || (resetSelection && !findings.some((f) => f.id === selectedId))) {
        if (findings.length) await select(findings[0]);
        else {
          selectedId = '';
          detail = undefined;
        }
      }
    } catch (failure) {
      if (alive) error = errorMessage(failure);
    }
  }
  async function loadDetail(id: string, reset: boolean) {
    try {
      const response = await findingsApi.getFinding({ findingId: id }, { signal: controller.signal });
      if (!alive || selectedId !== id) return;
      detail = response;
      if (reset && response.finding) {
        const finding = response.finding;
        reviewRevision = finding.revision;
        verdict = ['VALIDATED', 'REJECTED', 'INCONCLUSIVE'].includes(finding.reviewStatus)
          ? finding.reviewStatus
          : 'INCONCLUSIVE';
        rationale = '';
        counterEvidence = '';
        missingInformation = '';
      }
    } catch (failure) {
      if (alive) error = errorMessage(failure);
    }
  }
  async function select(finding: Finding) {
    selectedId = finding.id;
    detail = undefined;
    await loadDetail(finding.id, true);
  }
  async function review(event: SubmitEvent) {
    event.preventDefault();
    if (!selected || !rationale.trim() || busy) return;
    busy = true;
    error = '';
    try {
      const response = await findingsApi.submitReview({
        requestId: requestId(),
        findingId: selected.id,
        expectedRevision: reviewRevision,
        verdict,
        rationale: rationale.trim(),
        counterEvidence: counterEvidence.trim(),
        missingInformation: missingInformation.trim(),
      });
      reviewRevision = response.finding?.revision || reviewRevision;
      await refresh();
      rationale = '';
      counterEvidence = '';
      missingInformation = '';
      notify('人工复核已保存，原始模型复核与执行证据继续保留');
    } catch (failure) {
      error = errorMessage(failure);
    } finally {
      busy = false;
    }
  }
  onMount(() => {
    if (active) void refresh();
    const timer = setInterval(() => {
      if (active && (!isTerminal(run.state) || runtimeRecords.some((r) => runtimePending(r.status))))
        void refresh();
    }, 1800);
    return () => {
      alive = false;
      controller.abort();
      clearInterval(timer);
    };
  });
  $effect(() => {
    if (active && isTerminal(run.state)) void refresh();
  });
</script>

<section class="audit-workspace" aria-label="漏洞审计">
  <div class="audit-heading">
    <div>
      <h2>漏洞审计</h2>
      <p class="subtle">查看候选发现、代码证据与独立复核结论。</p>
    </div>
    <button
      class="button secondary small"
      disabled={refreshing}
      onclick={() => refresh()}
      aria-label="刷新审计结果"
    >
      <RefreshCw size={15} class={refreshing ? 'spin' : ''} />{refreshing ? '刷新中…' : '刷新结果'}
    </button>
  </div>
  <AuditPlan task={data?.tasks.find((t) => t.role === 'PLANNER')} units={knownUnits} {onselectunit} />
  <div class="audit-metrics">
    <div>
      <span>语义审计覆盖</span><strong
        >{summary.audited_unit_count || 0} / {summary.eligible_unit_count ?? Number(run.unitCount)}</strong
      >
    </div>
    <div><span>候选发现</span><strong>{data?.findings.length || 0}</strong></div>
    <div>
      <span>实际模型用量</span><strong
        >{totalTokens.toString()}
        <small>token{unknownUsage ? ` · ${unknownUsage} 次用量未知` : ''}</small></strong
      >
    </div>
    <div>
      <span>动态与利用验证</span><strong
        >{runtimeStatus}{exploitationStatus ? ` / ${exploitationStatus}` : ''}</strong
      >
    </div>
  </div>
  {#if summary.audit_config}<details class="audit-budget">
      <summary>审计预算与模型设置</summary>
      <dl class="audit-budget-summary">
        <div>
          <dt>模型调用</dt>
          <dd>{data?.modelCalls.length || 0} / {summary.audit_config.max_model_calls}</dd>
        </div>
        <div>
          <dt>工具轮数 / 子任务</dt>
          <dd>{summary.audit_config.max_tool_rounds}</dd>
        </div>
        <div>
          <dt>单元上限</dt>
          <dd>{summary.audit_config.max_units}</dd>
        </div>
        <div>
          <dt>任务时限</dt>
          <dd>{summary.audit_config.timeout_seconds} s</dd>
        </div>
        {#if summary.audit_config.max_output_tokens}<div>
            <dt>单次输出（含思考）</dt>
            <dd>{summary.audit_config.max_output_tokens} token</dd>
          </div>{/if}
        {#if summary.audit_config.reasoning_effort}<div>
            <dt>思考强度</dt>
            <dd>{summary.audit_config.reasoning_effort}</dd>
          </div>{/if}
        {#if summary.audit_config.model_timeout_seconds}<div>
            <dt>单次时限</dt>
            <dd>{summary.audit_config.model_timeout_seconds} s</dd>
          </div>{/if}
      </dl>
    </details>{/if}
  {#if summary.audit_coverage_gap}<div class="audit-gap">
      <strong>审计覆盖缺口</strong>
      <p>{summary.audit_coverage_gap}</p>
    </div>{/if}
  {#if error}<div class="error-banner" role="alert">
      <span>{error}</span><button
        class="text-button"
        onclick={() => {
          error = '';
        }}>关闭</button
      ><button
        class="text-button"
        onclick={() => {
          error = '';
          void refresh();
        }}>刷新</button
      >
    </div>{/if}
  <div class="code-tabs" role="tablist" aria-label="审计内容">
    <button
      role="tab"
      aria-selected={view === 'reviews'}
      class:active={view === 'reviews'}
      onclick={() => (view = 'reviews')}><ShieldCheck size={15} />复核总览</button
    >
    <button
      role="tab"
      aria-selected={view === 'findings'}
      class:active={view === 'findings'}
      onclick={() => (view = 'findings')}><ShieldCheck size={15} />发现与复核</button
    >
    <button
      role="tab"
      aria-selected={view === 'annotations'}
      class:active={view === 'annotations'}
      onclick={() => (view = 'annotations')}
      ><Code2 size={15} />关键逻辑 <span>{data?.annotations.length || 0}</span></button
    >
    <button
      role="tab"
      aria-selected={view === 'agents'}
      class:active={view === 'agents'}
      onclick={() => (view = 'agents')}><FileSearch size={15} />智能体记录</button
    >
    {#if exploitationArtifacts.length}<span class="poc-links">
        <span class="poc-links-title">漏洞复用 PoC</span>
        {#each exploitationArtifacts as item (item.name)}<a
            class="text-button"
            href={artifactUrl(item.id)}
            download
            title={`${item.name}：${item.hint}`}>{item.name}</a
          >{/each}
      </span>{/if}
  </div>
  {#if view === 'findings'}
    <div class="finding-layout">
      <aside class="finding-list">
        <div class="finding-list-heading">
          <h3>候选发现</h3>
          <span class="badge neutral">{findingTotal} 项</span>
        </div>
        <label class="field"
          >复核状态<select
            bind:value={filter}
            onchange={() => {
              offset = 0;
              void loadQueue(true);
            }}
            ><option value="">全部候选</option><option value="UNREVIEWED">待复核</option><option
              value="VALIDATED">静态复核成立</option
            ><option value="REJECTED">已驳回</option><option value="INCONCLUSIVE">依据不足</option></select
          ></label
        >
        {#each findings as finding}<button
            class:selected={selectedId === finding.id}
            class="finding-row"
            onclick={() => select(finding)}
            ><strong>{finding.title}</strong><span class="finding-row-meta"
              ><span class={`badge ${severityTone(finding.severity)}`}>{label(finding.severity)}</span><code
                >{finding.cwe}</code
              ></span
            ><small class="review-status" data-status={finding.reviewStatus}
              >{label(finding.reviewStatus)}</small
            ></button
          >{/each}
        {#if findingTotal > 50}<div class="queue-pagination">
            <button
              class="text-button"
              disabled={offset === 0}
              onclick={() => {
                offset -= 50;
                void loadQueue(true);
              }}>上一页</button
            >
            <span>{offset + 1}–{Math.min(offset + 50, findingTotal)} / {findingTotal}</span>
            <button
              class="text-button"
              disabled={offset + 50 >= findingTotal}
              onclick={() => {
                offset += 50;
                void loadQueue(true);
              }}>下一页</button
            >
          </div>{/if}
        {#if !findings.length}<p class="muted">
            {isTerminal(run.state)
              ? '当前筛选下没有候选发现。已审计范围与覆盖缺口见上方。'
              : '智能体正在分析；形成有效候选后会显示在这里。'}
          </p>{/if}
      </aside>
      <div class="finding-detail">
        {#if selected}
          <div class="panel-title">
            <h2>{selected.title}</h2>
            <span class="badge review-status" data-status={selected.reviewStatus}
              >{label(selected.reviewStatus)}</span
            >
          </div>
          <div class="finding-meta">
            <span class={`badge ${severityTone(selected.severity)}`}>{label(selected.severity)}</span>
            <code>{selected.cwe}</code>
            {#if selected.staticScope === 'COMPONENT'}<span>组件级静态审计</span>{/if}
            <span>修订 v{selected.revision}</span>
          </div>
          {#if selectedPlan || selectedRuntime || (onfuzz && selected.category === 'MEMORY_BOUNDS')}<div
              class="finding-next"
            >
              <div>
                {#if selectedRuntime}
                  {@const feedback = runtimeFeedback(
                    selectedRuntime,
                    parseJson<RuntimeResult | null>(selectedRuntime.resultJson, null),
                  )}
                  <span>{runtimeAction}：<strong>{feedback.title}</strong></span>
                  <p class="subtle verification-hint">{feedback.detail}</p>
                {:else if selectedPlan}<span>运行验证：<strong>方案已生成，尚未执行</strong></span>
                  <p class="subtle verification-hint">启动运行后才能判断是否复现。</p>
                {:else}<span>动态模糊测试：<strong>尚未执行</strong></span>{/if}
              </div>
              {#if selectedRuntime}<button
                  class="button secondary small"
                  onclick={() => onresults(selected.id)}
                  >{runtimePending(selectedRuntime.status)
                    ? `查看${runtimeAction}进度`
                    : `查看${runtimeAction}结果`}<ArrowUpRight size={14} /></button
                >{/if}
              {#if selectedPlan}<button class="button secondary small" onclick={() => onverify(selected.id)}
                  >查看验证方案<ArrowUpRight size={14} /></button
                >{/if}
              {#if onfuzz && selected.category === 'MEMORY_BOUNDS'}<button
                  class="button secondary small"
                  onclick={() => onfuzz?.(selected.id)}><FlaskConical size={14} />配置模糊测试</button
                >{/if}
            </div>{/if}
          <section class="finding-key-points" aria-label="漏洞核心问题">
            <h3>核心问题</h3>
            <dl class="finding-facts">
              <div>
                <dt>防护缺口</dt>
                <dd>{selected.missingGuard || '未记录'}</dd>
              </div>
              <div>
                <dt>预期影响</dt>
                <dd>{selected.impact || '未记录'}</dd>
              </div>
              <div class="finding-recommendation">
                <dt>修复建议</dt>
                <dd>{selected.recommendation || '未记录'}</dd>
              </div>
            </dl>
          </section>
          <section class="finding-context" aria-label="漏洞触发路径与前提">
            <h3>触发路径与前提</h3>
            <dl class="finding-facts">
              <div>
                <dt>输入来源</dt>
                <dd>{selected.inputSource || '未记录'}</dd>
              </div>
              <div>
                <dt>危险操作</dt>
                <dd>{selected.sink || '未记录'}</dd>
              </div>
              <div>
                <dt>触发前提</dt>
                <dd>{selected.preconditions || '未记录'}</dd>
              </div>
              <div>
                <dt>严重度依据</dt>
                <dd>{selected.severityReason || '未记录'}</dd>
              </div>
            </dl>
          </section>
          <h3 class="finding-section-heading">
            代码证据<span class="badge neutral">{selected.evidence.length} 处</span>
          </h3>
          {#each selected.evidence as reference}<div class="evidence-card">
              <button class="text-button" onclick={() => onselectunit(reference.unitId)}
                >{reference.path} · L{reference.startLine}–{reference.endLine}{reference.address
                  ? ` · 函数入口 ${reference.address}`
                  : ''}<ArrowUpRight size={13} /></button
              >
              <pre>{reference.quote}</pre>
              <a class="subtle" href={artifactUrl(reference.artifactId)}>原始分析产物</a>
            </div>{/each}
          <h3>独立复核与修订历史</h3>
          {#each reviews as item}<article class="review-card">
              <div class="review-heading">
                <strong class="review-status" data-status={item.verdict}>{label(item.verdict)}</strong><span
                  >{item.actor === 'HUMAN' ? '人工' : '独立复核智能体'} · v{item.revision}</span
                >
              </div>
              <p>{item.rationale}</p>
              <p class="subtle">反证与防护：{item.counterEvidence || '未记录'}</p>
              <p class="subtle">待补信息：{item.missingInformation || '无补充记录'}</p>
              {#each parseJson<{ check: string; status: string; rationale: string }[]>(item.assessmentsJson, []) as assessment}
                <p class="subtle">
                  {(
                    {
                      INPUT_CONTROL: '输入控制',
                      REACHABILITY: '操作可达性',
                      DEFENSE_GAP: '防护缺口',
                      EXTRA_PRECONDITION: '额外攻击前提',
                    } as Record<string, string>
                  )[assessment.check] || assessment.check} · {(
                    { SUPPORTED: '有证据支持', REFUTED: '有反证', UNKNOWN: '尚未证实' } as Record<
                      string,
                      string
                    >
                  )[assessment.status] || assessment.status}：{assessment.rationale}
                </p>
              {/each}
            </article>{/each}
          {#if !reviews.length}<p class="muted">尚无复核记录。</p>{/if}
          <details class="review-editor">
            <summary>提交人工复核</summary>
            {#if selected.revision !== reviewRevision}<p class="audit-gap">
                此发现已更新，当前草稿仍基于 v{reviewRevision}。<button
                  class="text-button"
                  onclick={() => loadDetail(selectedId, true)}>载入最新版本并重填</button
                >
              </p>{/if}
            <form onsubmit={review}>
              <label class="field"
                >结论<select bind:value={verdict}
                  ><option value="INCONCLUSIVE">依据不足</option><option value="VALIDATED"
                    >静态复核成立</option
                  ><option value="REJECTED">驳回候选</option></select
                ></label
              ><label class="field"
                >复核说明<textarea
                  bind:value={rationale}
                  required
                  maxlength="4000"
                  rows="4"
                  placeholder="说明你核对的输入、防护条件、反证或缺少的信息"
                ></textarea></label
              ><label class="field"
                >反证与防护<textarea
                  bind:value={counterEvidence}
                  maxlength="2000"
                  rows="3"
                  placeholder="记录已发现的防护、反例或可能推翻结论的证据"
                ></textarea></label
              >
              <label class="field"
                >待补信息<textarea
                  bind:value={missingInformation}
                  maxlength="2000"
                  rows="3"
                  placeholder="记录尚需确认的调用入口、配置或运行条件"
                ></textarea></label
              >
              <button class="button secondary" disabled={busy || !rationale.trim()}
                ><Save size={14} />保存修订</button
              >
            </form>
          </details>
        {:else}<div class="empty-panel">
            <ShieldCheck size={28} />
            <p>选择候选查看输入、代码证据与独立复核。</p>
          </div>{/if}
      </div>
    </div>
  {:else if view === 'annotations'}
    <AnnotationsPanel {run} {notify} {onselectunit} onchanged={() => void refresh()} />
  {:else if view === 'reviews'}
    <section class="review-overview" aria-label="复核总览">
      <h3>跨发现复核队列</h3>
      <p class="muted">尚无人工复核记录：{pendingHuman} 项。静态复核与动态验证结果分别保留。</p>
      <div class="review-counts">
        {#each reviewCounts as count}<button
            class="button secondary"
            onclick={() => {
              filter = count.status;
              offset = 0;
              view = 'findings';
              void loadQueue(true);
            }}>{label(count.status)} · {count.count}</button
          >{/each}
      </div>
      <div class="table-scroll">
        <table>
          <thead
            ><tr><th>候选发现</th><th>当前结论</th><th>最近复核</th><th>待补信息</th><th>操作</th></tr></thead
          >
          <tbody
            >{#each data?.findings || [] as finding}
              {@const latest = data?.reviews
                .filter((r) => r.findingId === finding.id)
                .sort((a, b) => b.revision - a.revision)[0]}
              <tr
                ><td>{finding.title}<small>{finding.cwe} · {label(finding.severity)}</small></td>
                <td>{label(finding.reviewStatus)}</td>
                <td
                  >{latest
                    ? `${latest.actor === 'HUMAN' ? '人工' : '模型'} · v${latest.revision}`
                    : '未复核'}<small>{latest ? dateTime(latest.createdAt) : ''}</small></td
                >
                <td>{latest?.missingInformation || '未记录'}</td>
                <td
                  ><button
                    class="text-button"
                    onclick={() => {
                      filter = '';
                      view = 'findings';
                      void select(finding);
                    }}>查看并复核</button
                  ></td
                >
              </tr>
            {/each}</tbody
          >
        </table>
      </div>
      {#if !data?.findings.length}<p class="muted">尚无候选发现。</p>{/if}
    </section>
  {:else}
    <div class="agent-records">
      <h3>角色与任务</h3>
      <div class="table-scroll">
        <table>
          <thead><tr><th>角色</th><th>状态</th><th>结果</th></tr></thead><tbody
            >{#each data?.tasks || [] as task}<tr
                ><td>{label(task.role)}</td><td>{label(task.status)}</td><td
                  >{task.error}{#if task.resultArtifactId}<a href={artifactUrl(task.resultArtifactId)}
                      >结构化结果</a
                    >{/if}</td
                ></tr
              >{/each}</tbody
          >
        </table>
      </div>
      <h3>模型请求、响应与用量</h3>
      <p class="muted">角色使用独立上下文。原始响应保留校验失败和中断记录；无法取得用量的调用显示为未知。</p>
      <div class="table-scroll">
        <table>
          <thead><tr><th>时间 / 角色</th><th>状态</th><th>模型</th><th>用量</th><th>原始记录</th></tr></thead
          ><tbody
            >{#each data?.modelCalls || [] as call}<tr
                ><td>{dateTime(call.createdAt)}<br />{label(call.role)}</td><td
                  >{label(call.status)}{#if call.error}<small class="inline-error">{call.error}</small
                    >{/if}</td
                ><td>{call.model}</td><td
                  >{call.usageAvailable
                    ? `${call.inputTokens} + ${call.outputTokens} = ${call.totalTokens}`
                    : '未知'}</td
                ><td
                  >{#if call.requestArtifactId}<a href={artifactUrl(call.requestArtifactId)}>请求</a>{/if}
                  {#if call.artifactId}<a href={artifactUrl(call.artifactId)}>响应</a>{/if}</td
                ></tr
              >{/each}</tbody
          >
        </table>
      </div>
    </div>
  {/if}
</section>

<style>
  .verification-hint {
    margin-top: 6px;
    line-height: 1.7;
  }
  .audit-heading {
    display: flex;
    align-items: start;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 14px;
    padding: var(--space-6);
  }
  .audit-heading .subtle {
    margin-top: 5px;
  }
  .audit-metrics {
    gap: 12px;
    padding: 0 var(--space-6) var(--space-5);
  }
  .audit-metrics > div {
    padding: 16px;
    min-width: 0;
    background: var(--surface-subtle);
    border: 1px solid var(--line);
    border-radius: var(--radius-md);
  }
  .audit-metrics span {
    font-size: var(--text-sm);
    color: var(--muted);
  }
  .audit-metrics strong {
    display: block;
    line-height: 1.6;
    overflow-wrap: anywhere;
  }
  .audit-metrics strong small {
    display: block;
    color: var(--muted);
  }
  .audit-metrics > div:last-child strong {
    font-size: var(--text-lg);
  }
  .audit-budget {
    margin: 0 var(--space-6) var(--space-4);
    padding: 12px 16px;
    border: 1px solid var(--line);
    border-radius: var(--radius-sm);
  }
  .audit-budget summary {
    cursor: pointer;
    color: var(--text-secondary);
    font-size: var(--text-sm);
    font-weight: 500;
  }
  .audit-budget .audit-budget-summary {
    padding: 16px 0 0;
  }
  .audit-gap {
    border: 1px solid var(--warning-line);
    line-height: 1.8;
  }
  .audit-gap > p {
    margin-top: 5px;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
  .finding-list {
    background: var(--surface-subtle);
  }
  .finding-list-heading {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 16px;
    gap: 8px;
  }
  .finding-list-heading h3 {
    font-size: var(--text-lg);
  }
  .finding-row {
    margin: 12px 0;
    gap: 10px;
  }
  .finding-row strong {
    line-height: 1.7;
    overflow-wrap: anywhere;
  }
  .finding-row .badge {
    font-size: var(--text-xs);
  }
  .finding-row-meta {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
  }
  .finding-row-meta code {
    font-size: var(--text-xs);
  }
  .review-status[data-status='VALIDATED'] {
    color: var(--accent-hover);
  }
  .badge.review-status[data-status='VALIDATED'] {
    background: var(--accent-soft);
    border-color: var(--accent-line);
  }
  .review-status[data-status='INCONCLUSIVE'],
  .review-status[data-status='UNREVIEWED'] {
    color: var(--warning);
  }
  .badge.review-status[data-status='INCONCLUSIVE'],
  .badge.review-status[data-status='UNREVIEWED'] {
    background: var(--warning-soft);
    border-color: var(--warning-line);
  }
  .review-status[data-status='REJECTED'] {
    color: var(--muted);
  }
  .finding-detail > .panel-title {
    padding: 0;
    align-items: start;
    gap: 12px;
    flex-wrap: wrap;
  }
  .finding-detail > .panel-title h2 {
    min-width: 0;
    flex: 1 1 240px;
    overflow-wrap: anywhere;
  }
  .finding-meta {
    display: flex;
    gap: 8px 14px;
    align-items: center;
    flex-wrap: wrap;
    margin-top: 12px;
    font-size: var(--text-sm);
    color: var(--muted);
  }
  .finding-next {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 12px;
    padding: 14px 0;
    margin-bottom: 6px;
    font-size: var(--text-sm);
    color: var(--text-secondary);
  }
  .finding-key-points {
    padding: 18px;
    border: 1px solid var(--accent-line);
    border-left: 4px solid var(--accent);
    border-radius: var(--radius-md);
    background: var(--accent-soft);
  }
  .finding-detail .finding-key-points h3 {
    margin: 0;
    color: var(--accent-hover);
  }
  .finding-facts {
    grid-template-columns: minmax(0, 1fr);
    gap: 14px;
    margin: 14px 0 0;
  }
  .finding-facts > div {
    display: grid;
    grid-template-columns: 85px minmax(0, 1fr);
    gap: 8px 14px;
  }
  .finding-facts dt {
    font-size: var(--text-sm);
    color: var(--muted);
  }
  .finding-facts dd {
    white-space: pre-wrap;
    line-height: 1.8;
  }
  .finding-recommendation {
    padding-top: 14px;
    border-top: 1px solid var(--accent-line);
  }
  .finding-recommendation dt {
    color: var(--accent-hover);
    font-weight: 600;
  }
  .finding-section-heading {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .evidence-card .text-button {
    text-align: left;
    white-space: normal;
    overflow-wrap: anywhere;
    line-height: 1.7;
  }
  .evidence-card pre {
    line-height: 1.8;
    border-radius: var(--radius-sm);
  }
  .review-card {
    background: var(--surface-subtle);
    padding: 16px;
  }
  .review-heading {
    display: flex;
    gap: 8px 14px;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    margin-bottom: 10px;
  }
  .review-heading > span {
    font-size: var(--text-xs);
    color: var(--muted);
  }
  .review-card p {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
  .review-card .subtle {
    margin-top: 8px;
  }
  .review-editor {
    border: 1px solid var(--line);
    padding: 16px;
    border-radius: var(--radius-md);
  }
  .review-editor summary {
    font-weight: 600;
    cursor: pointer;
  }
  .review-editor form {
    display: grid;
    gap: 14px;
  }
  .review-counts,
  .queue-pagination {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-2);
    margin: var(--space-3) 0;
    align-items: center;
  }
  .review-overview {
    padding: var(--space-5) var(--space-6);
  }
  .review-overview h3 {
    margin-bottom: var(--space-2);
    font-size: var(--text-base);
  }
  .review-overview td {
    white-space: normal;
    overflow-wrap: anywhere;
    max-width: 320px;
  }
  .review-overview td small {
    display: block;
    color: var(--muted);
    margin-top: var(--space-1);
  }
  .poc-links {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: var(--space-2) var(--space-3);
    margin-left: auto;
    padding-left: var(--space-3);
    font-size: var(--text-sm);
    white-space: nowrap;
  }
  .poc-links-title {
    color: var(--muted);
  }
  .audit-budget-summary {
    display: flex;
    flex-wrap: wrap;
    gap: var(--space-3) var(--space-6);
    padding: 0 var(--space-6) var(--space-4);
    margin: 0;
    font-size: var(--text-sm);
  }
  .audit-budget-summary div {
    min-width: 0;
  }
  .audit-budget-summary dt {
    color: var(--muted);
    margin-bottom: 3px;
  }
  .audit-budget-summary dd {
    margin: 0;
    overflow-wrap: anywhere;
    font-variant-numeric: tabular-nums;
  }
  @media (max-width: 600px) {
    .audit-heading {
      padding: var(--space-4);
    }
    .audit-metrics {
      padding-inline: var(--space-4);
      gap: 10px;
    }
    .audit-metrics > div {
      padding: 12px;
    }
    .audit-budget {
      margin-inline: var(--space-4);
    }
    .finding-list,
    .finding-detail {
      padding: var(--space-4);
    }
    .finding-key-points {
      padding: 14px;
    }
    .finding-facts > div {
      grid-template-columns: minmax(0, 1fr);
      gap: 4px;
    }
    .finding-next .button {
      white-space: normal;
      text-align: left;
    }
    .code-tabs {
      flex-wrap: wrap;
      row-gap: var(--space-1);
    }
    .code-tabs button {
      flex-shrink: 0;
      white-space: nowrap;
    }
    .review-overview {
      padding: var(--space-4);
    }
    .audit-budget-summary {
      padding-inline: var(--space-4);
    }
  }
</style>
