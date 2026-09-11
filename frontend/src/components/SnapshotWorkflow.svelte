<script lang="ts">
  import { ArrowRight, ArrowUpRight } from '@lucide/svelte';
  import type { AuditRun, Snapshot } from '../gen/audit/v1/audit_pb';
  import { RunState, SnapshotState, TargetKind } from '../gen/audit/v1/audit_pb';
  import { artifactUrl } from '../lib/api';
  import { isTerminal, runLabel, scopeLabel } from '../lib/format';

  let {
    snapshot,
    runs,
    connected,
    tools,
    modelConfigured,
    busy,
    onanalyze,
    onaudit,
  }: {
    snapshot: Snapshot;
    runs: AuditRun[];
    connected: boolean;
    tools: string[];
    modelConfigured: boolean;
    busy: boolean;
    onanalyze: () => void;
    onaudit: () => void;
  } = $props();
  const binary = $derived(snapshot.kind === TargetKind.BINARY);
  const analyses = $derived(
    runs.filter((run) => ['STRUCTURE_ANALYSIS', 'SECURITY_AUDIT'].includes(run.scope)),
  );
  const active = $derived(analyses.find((run) => !isTerminal(run.state)));
  const latest = $derived(analyses[0]);
  const ready = $derived(
    connected && !busy && [SnapshotState.READY, SnapshotState.PARTIAL].includes(snapshot.state),
  );
  const canAnalyze = $derived(ready && !active && tools.includes(binary ? 'ghidra' : 'tree-sitter'));
  const canAudit = $derived(
    ready && !active && modelConfigured && tools.includes(binary ? 'import' : 'tree-sitter'),
  );
  const reusable = $derived(
    binary &&
      latest?.scope === 'STRUCTURE_ANALYSIS' &&
      latest.state === RunState.COMPLETED &&
      latest.unitCount > 0n,
  );
</script>

<div class="snapshot-workflow">
  <p class="workflow-hint">
    {#if active}
      {scopeLabel(active.scope)} · {runLabel(active.state)}。打开进度可继续查看或取消。
    {:else if latest?.scope === 'SECURITY_AUDIT'}
      本轮审计{runLabel(latest.state).replace(/^分析/, '')}。结果和执行记录已保留。
    {:else if reusable}
      反编译结果已就绪。继续审计时会检查并复用兼容结果，按需补充逆向恢复。
    {:else if binary}
      漏洞审计包含逆向、反编译与独立复核，无需先单独反编译。
    {:else}
      漏洞审计包含结构解析与独立复核，无需先单独解析。
    {/if}
  </p>
  <div class="snapshot-actions">
    {#if active}
      <a class="button primary small" href={`#/runs/${active.id}`}>查看进度<ArrowRight size={14} /></a>
    {:else if latest?.scope === 'SECURITY_AUDIT'}
      <a class="button primary small" href={`#/runs/${latest.id}`}>
        {latest.state === RunState.FAILED ? '查看失败原因' : '查看审计结果'}<ArrowRight size={14} />
      </a>
    {:else}
      <button class="button primary small" disabled={!canAudit} onclick={onaudit}>
        {reusable ? '继续漏洞审计' : '开始漏洞审计'}<ArrowRight size={14} />
      </button>
      {#if latest}
        <a class="button secondary small" href={`#/runs/${latest.id}`}>
          {binary ? '查看反编译结果' : '查看结构结果'}<ArrowRight size={14} />
        </a>
      {:else}
        <button class="button secondary small" disabled={!canAnalyze} onclick={onanalyze}>
          {busy ? '正在创建…' : binary ? '仅反编译' : '仅结构分析'}<ArrowRight size={14} />
        </button>
      {/if}
    {/if}
    {#if !active && latest}
      <details class="rerun-options">
        <summary>重新运行</summary>
        <p>新建一轮分析，保留已有结果和历史记录。</p>
        <div class="rerun-buttons">
          <button class="button secondary small" disabled={!canAudit} onclick={onaudit}>重新审计</button>
          <button class="button secondary small" disabled={!canAnalyze} onclick={onanalyze}>
            {busy ? '正在创建…' : binary ? '重新反编译' : '重新结构分析'}
          </button>
        </div>
      </details>
    {/if}
  </div>
  <div class="workflow-links">
    {#if !active && !modelConfigured}<a class="text-button" href="#/environment">配置模型后可进行漏洞审计</a>
    {:else if !active && !tools.includes(binary ? 'import' : 'tree-sitter')}
      <a class="text-button" href="#/environment">查看所需执行环境</a>
    {/if}
    {#if snapshot.manifestArtifactId}<a class="text-button" href={artifactUrl(snapshot.manifestArtifactId)}>
        快照清单<ArrowUpRight size={13} />
      </a>{/if}
  </div>
</div>

<style>
  .snapshot-workflow {
    display: grid;
    gap: 10px;
  }
  .workflow-hint,
  .rerun-options p {
    margin: 0;
    font-size: var(--text-sm);
    color: var(--muted);
    line-height: 1.6;
  }
  .snapshot-actions,
  .rerun-buttons,
  .workflow-links {
    display: flex;
    flex-wrap: wrap;
    gap: 8px 12px;
    align-items: center;
  }
  .rerun-options {
    width: 100%;
  }
  .rerun-options summary {
    width: fit-content;
    cursor: pointer;
    color: var(--muted);
    font-size: var(--text-sm);
  }
  .rerun-options[open] {
    border-top: 1px solid var(--line);
    padding-top: 10px;
  }
  .rerun-options p {
    margin: 8px 0;
  }
  .workflow-links {
    justify-content: space-between;
  }
</style>
