<script lang="ts">
  import type { RunPhase } from '../gen/audit/v1/audit_pb';
  let { phases, onselect }: { phases: RunPhase[]; onselect: (phase: RunPhase) => void } = $props();
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
</script>

{#if phases.length}
  <section class="workflow-progress" aria-label="任务阶段">
    <div class="progress-heading">
      <strong
        >{current
          ? `当前第 ${current.order} / ${phases.length} 阶段 · ${current.title}`
          : '任务阶段记录'}</strong
      >
      <span>按实际执行记录恢复</span>
    </div>
    <ol>
      {#each phases as phase}
        <li class:current={phase.id === current?.id} class:complete={phase.status === 'COMPLETED'}>
          <button
            onclick={() => onselect(phase)}
            aria-current={phase.id === current?.id ? 'step' : undefined}
          >
            <span class="step-number">{phase.order}</span>
            <span class="step-body">
              <strong>{phase.title}</strong><small>{labels[phase.status] || phase.status}</small>
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
            </span>
          </button>
        </li>
      {/each}
    </ol>
    {#if current?.detail}<p>
        {current.detail}{current.unitId ? ' · 点击当前阶段可定位正在处理的代码' : ''}
      </p>{/if}
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
    align-items: baseline;
    margin-bottom: var(--space-3);
  }
  .progress-heading span,
  p {
    color: var(--muted);
    font-size: var(--text-sm);
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
    color: var(--success);
  }
  .step-body {
    display: grid;
    gap: 4px;
    min-width: 0;
    flex: 1;
  }
  strong {
    font-size: var(--text-base);
  }
  small {
    color: var(--text-secondary);
    font-size: var(--text-sm);
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
      display: block;
    }
    ol {
      grid-template-columns: 1fr;
    }
  }
</style>
