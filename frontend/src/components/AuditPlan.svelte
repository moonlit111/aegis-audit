<script lang="ts">
  import type { AgentTask, ProgramUnit } from '../gen/audit/v1/audit_pb';
  import { artifactUrl } from '../lib/api';
  let {
    task,
    units,
    onselectunit,
  }: { task?: AgentTask; units: ProgramUnit[]; onselectunit: (id: string) => void } = $props();
  const plan = $derived(task?.plan);
</script>

<section class="panel plan-panel" aria-label="顶层审计规划">
  <div class="panel-title">
    <h2>审计策略与优先级</h2>
    {#if task?.resultArtifactId}<a href={artifactUrl(task.resultArtifactId)}>原始规划 JSON</a>{/if}
  </div>
  <div class="plan-body">
    {#if plan}
      <p class="approach">{plan.approach}</p>
      {#if plan.priorities.length}
        <ol>
          {#each plan.priorities as priority}
            <li>
              <button class="text-button" onclick={() => onselectunit(priority.unitId)}>
                {units.find((u) => u.id === priority.unitId)?.name || '查看优先审计单元'}
              </button>
              <p>{priority.reason}</p>
              {#if units.find((u) => u.id === priority.unitId)}
                {@const unit = units.find((u) => u.id === priority.unitId)!}
                <small>{unit.path} · {unit.address || `L${unit.startLine}–L${unit.endLine}`}</small>
              {/if}
            </li>
          {/each}
        </ol>
      {:else}<p class="muted">规划未指定优先单元，按程序索引顺序审计，并受本次单元上限约束。</p>{/if}
      {#if plan.limitations.length}<h3>规划限制</h3>
        <ul>
          {#each plan.limitations as limitation}<li>{limitation}</li>{/each}
        </ul>{/if}
      <p class="muted">优先项决定审计先后，完整覆盖范围以已审计单元和覆盖缺口为准。</p>
    {:else}<p class="muted">
        {task?.status === 'FAILED'
          ? task.error || '规划未成功生成。'
          : '规划完成并通过校验后，将在这里显示策略、顺序与选择理由。'}
      </p>{/if}
  </div>
</section>

<style>
  .plan-panel {
    margin-bottom: var(--space-4);
  }
  .plan-body {
    display: grid;
    gap: var(--space-3);
    padding: var(--space-5) var(--space-6);
  }
  .plan-body h3 {
    font-size: var(--text-base);
  }
  .plan-body ol,
  .plan-body ul {
    margin: 0;
  }
  .approach,
  li p {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    line-height: 1.65;
  }
  ol {
    padding-left: 24px;
  }
  ol li {
    padding: var(--space-2);
    border-bottom: 1px solid var(--line);
  }
  li p {
    margin: 6px 0;
  }
  small {
    color: var(--text-secondary);
    font-size: var(--text-sm);
    overflow-wrap: anywhere;
  }
  @media (max-width: 600px) {
    .plan-body {
      padding: var(--space-4);
    }
  }
</style>
