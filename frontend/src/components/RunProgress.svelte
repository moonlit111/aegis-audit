<script lang="ts">
  import { ArrowUpRight, Check } from '@lucide/svelte';
  import type { RunPhase } from '../gen/audit/v1/audit_pb';
  import { RunState } from '../gen/audit/v1/audit_pb';
  import { runLabel, tone } from '../lib/format';

  let {
    phases,
    runState,
    statusMessage = '',
    showEnvironmentLink = false,
    onselect,
    canSelect = () => true,
  }: {
    phases: RunPhase[];
    runState: RunState;
    statusMessage?: string;
    showEnvironmentLink?: boolean;
    onselect: (phase: RunPhase) => void;
    canSelect?: (phase: RunPhase) => boolean;
  } = $props();
  const labels: Record<string, string> = {
    PENDING: '未开始',
    WAITING: '等待执行',
    RUNNING: '执行中',
    COMPLETED: '完成',
    PARTIAL: '部分完成',
    SKIPPED: '未执行',
    FAILED: '失败',
    CANCELLED: '已取消',
    CANCELLING: '取消中',
  };
  const current = $derived(phases.find((p) => ['RUNNING', 'WAITING', 'CANCELLING'].includes(p.status)));
  const resolvedCount = $derived(
    phases.filter((phase) =>
      ['COMPLETED', 'PARTIAL', 'SKIPPED', 'FAILED', 'CANCELLED'].includes(phase.status),
    ).length,
  );
  const completedCount = $derived(phases.filter((phase) => phase.status === 'COMPLETED').length);
  const percent = $derived(phases.length ? Math.round((resolvedCount / phases.length) * 100) : 0);
  const headline = $derived(current ? `当前阶段：${current.title}` : `任务${runLabel(runState)}`);
  const note = $derived(current?.detail || statusMessage || '阶段记录已归档，可点击阶段查看对应内容。');

  function statusClass(status: string) {
    if (['COMPLETED'].includes(status)) return 'success';
    if (['PARTIAL', 'CANCELLING'].includes(status)) return 'warning';
    if (['FAILED', 'CANCELLED'].includes(status)) return 'danger';
    if (['RUNNING', 'WAITING'].includes(status)) return 'active';
    return 'neutral';
  }
</script>

{#if phases.length}
  <section class="workflow-progress" aria-label="任务阶段">
    <div class="progress-heading">
      <div class="progress-heading-main">
        <span class="progress-eyebrow">EXECUTION PROGRESS</span>
        <h2>{headline}</h2>
        <p>
          <span>{note}</span>
          {#if showEnvironmentLink}<a href="#/environment">执行环境<ArrowUpRight size={13} /></a>{/if}
        </p>
      </div>
      <div class="progress-heading-meta">
        <span class={`phase-status ${tone(runState) === 'danger' ? 'danger' : tone(runState)}`}>
          {runLabel(runState)}
        </span>
        <strong>{resolvedCount} / {phases.length} 阶段已结束</strong>
        <small>{completedCount} 个阶段完成</small>
      </div>
    </div>
    <div
      class="stage-track"
      role="progressbar"
      aria-label="阶段进展"
      aria-valuemin="0"
      aria-valuemax="100"
      aria-valuenow={percent}
    >
      {#each phases as phase}<span class={`stage-segment ${statusClass(phase.status)}`}></span>{/each}
    </div>
    <ol>
      {#each phases as phase}
        <li
          class:current={phase.id === current?.id}
          class:complete={phase.status === 'COMPLETED'}
          data-status={phase.status}
        >
          <button
            disabled={!canSelect(phase)}
            title={canSelect(phase) ? undefined : '该阶段暂无可查看内容'}
            onclick={() => onselect(phase)}
            aria-current={phase.id === current?.id ? 'step' : undefined}
          >
            <span class="step-number">
              {#if phase.status === 'COMPLETED'}<Check size={14} />{:else}{phase.order}{/if}
            </span>
            <span class="step-body">
              <strong>{phase.title}</strong>
              <span class={`phase-status ${statusClass(phase.status)}`}>
                {phase.id === current?.id ? '当前 · ' : ''}{labels[phase.status] || phase.status}
              </span>
              {#if phase.total > 0n}
                <progress
                  aria-label={`${phase.title}已记录进度`}
                  max={Number(phase.total)}
                  value={Number(phase.current)}
                ></progress>
                <small
                  >{phase.current.toString()} / {phase.total.toString()}{phase.id === 'AUDIT_REVIEW'
                    ? ' 个计划单元'
                    : ' 项'}</small
                >
              {/if}
              {#if current?.detail && phase.id === current?.id}<small>{current.detail}</small>{/if}
            </span>
          </button>
        </li>
      {/each}
    </ol>
  </section>
{/if}

<style>
  .workflow-progress {
    padding: var(--space-4);
    border: 1px solid var(--line);
    border-radius: var(--radius-lg);
    background: var(--surface);
    margin-bottom: var(--space-5);
  }
  .progress-heading {
    display: flex;
    gap: var(--space-3);
    justify-content: space-between;
    align-items: start;
    margin-bottom: var(--space-4);
  }
  .progress-heading-main {
    display: grid;
    gap: 4px;
    min-width: 0;
  }
  .progress-eyebrow {
    font: 600 var(--text-xs) / 1.5 var(--font-ui);
    letter-spacing: 0.08em;
    color: var(--muted);
  }
  h2 {
    margin: 0;
    font-size: var(--text-lg);
    color: var(--ink);
  }
  .progress-heading-main p {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px 12px;
    margin: 2px 0 0;
    color: var(--muted);
    font-size: var(--text-base);
    line-height: 1.7;
  }
  .progress-heading-main a {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    color: var(--accent);
    font-size: 13px;
    white-space: nowrap;
  }
  .progress-heading-meta {
    display: grid;
    justify-items: end;
    gap: 5px;
    flex: none;
  }
  .progress-heading-meta strong {
    color: var(--ink);
    font-size: 15px;
    font-variant-numeric: tabular-nums;
  }
  .progress-heading-meta small {
    color: var(--muted);
    font-size: 13px;
  }
  .phase-status {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-height: 23px;
    padding: 3px var(--space-2);
    border: 1px solid var(--line);
    border-radius: var(--radius-sm);
    background: var(--surface-subtle);
    color: var(--muted);
    font-size: 13px;
    font-weight: 500;
    white-space: nowrap;
  }
  .phase-status.success {
    border-color: var(--success-line);
    background: var(--success-soft);
    color: var(--success);
  }
  .phase-status.warning {
    border-color: var(--warning-line);
    background: var(--warning-soft);
    color: var(--warning);
  }
  .phase-status.danger {
    border-color: var(--danger-line);
    background: var(--danger-soft);
    color: var(--danger);
  }
  .phase-status.active {
    border-color: var(--accent-line);
    background: var(--accent-soft);
    color: var(--accent-hover);
  }
  .stage-track {
    display: flex;
    gap: 4px;
    height: 6px;
    margin-bottom: var(--space-3);
  }
  .stage-segment {
    flex: 1;
    min-width: 6px;
    border-radius: 999px;
    background: var(--line);
  }
  .stage-segment.success {
    background: var(--success);
  }
  .stage-segment.warning {
    background: var(--warning);
  }
  .stage-segment.danger {
    background: var(--danger);
  }
  .stage-segment.active {
    background: var(--accent);
  }
  ol {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(175px, 1fr));
    gap: var(--space-2);
    list-style: none;
    margin: 0;
    padding: 0;
  }
  li {
    border: 1px solid var(--line);
    border-radius: var(--radius-md);
    background: var(--surface-subtle);
  }
  li.current {
    border-color: var(--accent);
    background: var(--accent-soft);
    box-shadow: 0 0 0 1px var(--accent) inset;
  }
  li[data-status='PARTIAL'],
  li[data-status='FAILED'],
  li[data-status='CANCELLED'] {
    border-color: var(--warning-line);
  }
  li[data-status='FAILED'],
  li[data-status='CANCELLED'] {
    border-color: var(--danger-line);
  }
  button {
    display: flex;
    align-items: flex-start;
    gap: var(--space-2);
    padding: var(--space-3);
    width: 100%;
    text-align: left;
    color: var(--ink);
    border: 0;
    background: transparent;
  }
  .step-number {
    display: grid;
    place-items: center;
    border: 1px solid var(--line);
    border-radius: 50%;
    width: 24px;
    height: 24px;
    flex: none;
    font-size: var(--text-sm);
  }
  .current .step-number {
    background: var(--accent);
    color: white;
    border-color: var(--accent);
  }
  .complete .step-number {
    display: grid;
    place-items: center;
    border-color: var(--success-line);
    color: var(--success);
    background: var(--success-soft);
  }
  .step-body {
    display: grid;
    gap: 4px;
    min-width: 0;
    flex: 1;
  }
  strong {
    font-size: 15px;
  }
  small {
    color: var(--text-secondary);
    font-size: 13px;
  }
  .step-body > .phase-status {
    justify-self: start;
  }
  progress {
    width: 100%;
    height: 5px;
    accent-color: var(--accent);
  }
  p {
    margin: var(--space-3) 0 0;
  }
  @media (max-width: 600px) {
    .progress-heading {
      display: grid;
    }
    .progress-heading-meta {
      justify-items: start;
    }
    ol {
      grid-template-columns: 1fr;
    }
  }
</style>
