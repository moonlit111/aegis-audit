<script lang="ts">
  import { onMount } from 'svelte';
  import { ArrowUpRight, ShieldCheck, FileSearch, RefreshCw, Save, Code2 } from '@lucide/svelte';
  import type {
    AuditRun,
    Finding,
    GetAuditResponse,
    GetFindingResponse,
    ProgramUnit,
  } from '../gen/audit/v1/audit_pb';
  import AuditPlan from './AuditPlan.svelte';
  import AnnotationsPanel from './AnnotationsPanel.svelte';
  import { artifactUrl, errorMessage, findingsApi, requestId } from '../lib/api';
  import { dateTime, isTerminal, parseJson, type Summary } from '../lib/format';
  import { runtimeLabels, runtimePending } from '../lib/runtime';

  let {
    run,
    onselectunit,
    onverify,
    notify,
    knownUnits,
  }: {
    run: AuditRun;
    onselectunit: (id: string) => void;
    onverify: (id: string) => void;
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
  const runtimeStatus = $derived.by(() => {
    const records = data?.runtime || [];
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
    if (summary.exploitation === 'COMPLETED') return '利用证据已完成';
    if (summary.exploitation && summary.exploitation !== 'NOT_RUN') {
      return label(summary.exploitation);
    }
    return '';
  });
  async function refresh() {
    if (loading) {
      refreshAgain = true;
      return;
    }
    loading = true;
    try {
      const response = await findingsApi.getAudit({ runId: run.id }, { signal: controller.signal });
      if (!alive) return;
      data = response;
      await loadQueue();
      if (selectedId) await loadDetail(selectedId, false);
    } catch (failure) {
      if (alive) error = errorMessage(failure);
    } finally {
      loading = false;
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
      notify('人工复核已保存，原始模型复核与执行证据继续保留。');
    } catch (failure) {
      error = errorMessage(failure);
    } finally {
      busy = false;
    }
  }
  onMount(() => {
    void refresh();
    const timer = setInterval(() => {
      if (!isTerminal(run.state) || data?.runtime.some((r) => runtimePending(r.status))) void refresh();
    }, 1800);
    return () => {
      alive = false;
      controller.abort();
      clearInterval(timer);
    };
  });
  $effect(() => {
    if (isTerminal(run.state)) void refresh();
  });
</script>

<section class="audit-workspace">
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
  {#if summary.audit_config}<dl class="audit-budget-summary">
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
    </dl>{/if}
  {#if summary.audit_coverage_gap}<p class="audit-gap">{summary.audit_coverage_gap}</p>{/if}
  {#if error}<div class="error-banner" role="alert">
      {error}<button
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
    <button class="text-button" onclick={() => refresh()} aria-label="刷新审计结果"
      ><RefreshCw size={14} /></button
    >
  </div>
  {#if view === 'findings'}
    <div class="finding-layout">
      <aside class="finding-list">
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
            ><strong>{finding.title}</strong><span>{finding.cwe} · {label(finding.severity)}</span><small
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
            <span class={`badge ${selected.reviewStatus === 'VALIDATED' ? 'warning' : 'neutral'}`}
              >{label(selected.reviewStatus)}</span
            >
          </div>
          <p class="subtle">
            {selected.cwe} · {selected.staticScope === 'COMPONENT' ? '组件级静态审计 · ' : ''}{label(
              selected.severity,
            )} · 修订 {selected.revision} · {label(selected.verificationStatus)}
          </p>
          <button class="button secondary" onclick={() => onverify(selected.id)}
            >查看验证方案与运行结果<ArrowUpRight size={14} /></button
          >
          <dl class="finding-facts">
            <dt>输入来源</dt>
            <dd>{selected.inputSource}</dd>
            <dt>危险操作</dt>
            <dd>{selected.sink}</dd>
            <dt>防护缺口</dt>
            <dd>{selected.missingGuard}</dd>
            <dt>触发前提</dt>
            <dd>{selected.preconditions}</dd>
            <dt>预期影响</dt>
            <dd>{selected.impact}</dd>
            <dt>严重度依据</dt>
            <dd>{selected.severityReason}</dd>
            <dt>修复建议</dt>
            <dd>{selected.recommendation}</dd>
          </dl>
          <h3>代码证据</h3>
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
              <strong
                >{label(item.verdict)} · {item.actor === 'HUMAN' ? '人工' : '独立复核智能体'} · v{item.revision}</strong
              >
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
