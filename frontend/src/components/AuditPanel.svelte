<script lang="ts">
  import { onMount } from 'svelte';
  import { ArrowUpRight, ShieldCheck, FileSearch, RefreshCw, Save, Code2 } from '@lucide/svelte';
  import type { AuditRun, Finding, GetAuditResponse, LogicAnnotation } from '../gen/audit/v1/audit_pb';
  import { artifactUrl, errorMessage, findingsApi, programsApi, requestId } from '../lib/api';
  import { dateTime, isTerminal, parseJson, type Summary } from '../lib/format';
  import { runtimeLabels, runtimePending } from '../lib/runtime';

  let {
    run,
    onselectunit,
    onverify,
    notify,
  }: {
    run: AuditRun;
    onselectunit: (id: string) => void;
    onverify: (id: string) => void;
    notify: (message: string) => void;
  } = $props();
  let data = $state<GetAuditResponse>();
  let error = $state('');
  let selectedId = $state('');
  let filter = $state('');
  let view = $state<'findings' | 'annotations' | 'agents'>('findings');
  let verdict = $state('INCONCLUSIVE');
  let rationale = $state('');
  let busy = $state(false);
  let editing = $state('');
  let annotationTag = $state('');
  let annotationText = $state('');
  let loading = false;
  let alive = true;
  const controller = new AbortController();
  const summary = $derived(parseJson<Summary>(run.summaryJson, {}));
  const findings = $derived((data?.findings || []).filter((f) => !filter || f.reviewStatus === filter));
  const selected = $derived(data?.findings.find((f) => f.id === selectedId));
  const reviews = $derived((data?.reviews || []).filter((r) => r.findingId === selectedId));
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
    if (loading) return;
    loading = true;
    try {
      const response = await findingsApi.getAudit({ runId: run.id }, { signal: controller.signal });
      if (!alive) return;
      data = response;
      if (!selectedId && response.findings.length) select(response.findings[0]);
    } catch (failure) {
      if (alive) error = errorMessage(failure);
    } finally {
      loading = false;
    }
  }
  function select(finding: Finding) {
    selectedId = finding.id;
    verdict = ['VALIDATED', 'REJECTED', 'INCONCLUSIVE'].includes(finding.reviewStatus)
      ? finding.reviewStatus
      : 'INCONCLUSIVE';
    rationale = '';
  }
  async function review(event: SubmitEvent) {
    event.preventDefault();
    if (!selected || !rationale.trim() || busy) return;
    busy = true;
    error = '';
    try {
      await findingsApi.submitReview({
        requestId: requestId(),
        findingId: selected.id,
        expectedRevision: selected.revision,
        verdict,
        rationale: rationale.trim(),
        counterEvidence: '人工修订：见复核说明',
        missingInformation: '',
      });
      await refresh();
      rationale = '';
      notify('人工复核已保存，原始模型复核与执行证据继续保留。');
    } catch (failure) {
      error = errorMessage(failure);
    } finally {
      busy = false;
    }
  }
  function edit(annotation: LogicAnnotation) {
    editing = annotation.id;
    annotationTag = annotation.tag;
    annotationText = annotation.rationale;
  }
  async function saveAnnotation(annotation: LogicAnnotation, event: SubmitEvent) {
    event.preventDefault();
    busy = true;
    error = '';
    try {
      await programsApi.updateAnnotation({
        requestId: requestId(),
        annotationId: annotation.id,
        expectedRevision: annotation.revision,
        tag: annotationTag,
        rationale: annotationText,
      });
      editing = '';
      await refresh();
      notify('关键逻辑修订已保存。');
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
          >复核状态<select bind:value={filter}
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
              ><button class="button secondary" disabled={busy || !rationale.trim()}
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
    <div class="annotation-list">
      {#each data?.annotations || [] as annotation}<article class="panel">
          <div class="panel-title">
            <h3>{label(annotation.tag)}</h3>
            <span class="subtle"
              >{annotation.actor === 'HUMAN' ? '人工修订' : '自动标注'} · v{annotation.revision}</span
            >
          </div>
          {#each annotation.evidence as reference}<button
              class="text-button"
              onclick={() => onselectunit(reference.unitId)}
              >{reference.path} · L{reference.startLine}<ArrowUpRight size={13} /></button
            >{/each}
          <p>{annotation.rationale}</p>
          {#if editing === annotation.id}<form onsubmit={(event) => saveAnnotation(annotation, event)}>
              <label class="field"
                >逻辑类型<select bind:value={annotationTag}
                  ><option value="AUTHENTICATION">认证</option><option value="CRYPTOGRAPHY">加解密</option
                  ><option value="REGISTRATION">注册</option></select
                ></label
              ><label class="field"
                >标注依据<textarea bind:value={annotationText} required rows="3" maxlength="4000"
                ></textarea></label
              ><button class="button secondary" disabled={busy}>保存标注</button>
            </form>{:else}<button class="text-button" onclick={() => edit(annotation)}>修订标注</button>{/if}
        </article>{/each}
      {#if !data?.annotations.length}<div class="empty-panel">尚未标定认证、加解密或注册逻辑。</div>{/if}
    </div>
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
  .audit-budget-summary {
    display: flex;
    flex-wrap: wrap;
    gap: 12px 24px;
    margin: 12px 0;
    font-size: 12px;
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
</style>
