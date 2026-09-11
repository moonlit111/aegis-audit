<script lang="ts">
  import { Download, FileJson, ScanLine, ListChecks, Info } from '@lucide/svelte';
  import { artifactUrl } from '../lib/api';
  import type { RecoverySummary } from '../lib/format';

  let { recovery }: { recovery: RecoverySummary } = $props();
  const toolNames: Record<string, string> = {
    upx: 'UPX 去壳',
    floss: 'FLOSS 字符串恢复',
    ghidra: 'Ghidra 反编译',
    ida_d810: 'IDA / D-810 代码解混淆',
    builtin_strings: '编码字符串候选',
  };
  const states: Record<string, string> = {
    PLANNED: '已规划',
    RUNNING: '执行中',
    PLAN_COMPLETED: '计划步骤已完成',
    PARTIAL: '存在未完成项',
    NO_TRANSFORMATIONS: '未执行转换',
    PROCESSED: '已生成解包文件',
    RECOVERED: '已恢复字符串',
    CANDIDATES: '待复核候选',
    COMPLETED: '工具已完成',
    NOT_FOUND: '未发现可恢复内容',
    UNAVAILABLE: '工具不可用',
    INPUT_UNAVAILABLE: '所需输入未生成',
    UNSUPPORTED: '超出支持范围',
    FAILED: '执行失败',
  };
  const limitations = $derived([
    ...new Set([...(recovery.plan?.limitations || []), ...(recovery.conclusion?.limitations || [])]),
  ]);

  function statusTone(status = '') {
    if (['PLAN_COMPLETED', 'PROCESSED', 'RECOVERED', 'COMPLETED'].includes(status)) return 'success';
    if (status === 'FAILED') return 'danger';
    if (['PARTIAL', 'UNAVAILABLE', 'INPUT_UNAVAILABLE', 'UNSUPPORTED', 'CANDIDATES'].includes(status))
      return 'warning';
    return 'neutral';
  }
</script>

<section class="recovery-panel" aria-label="逆向与解混淆">
  <div class="panel-heading">
    <div>
      <h2>逆向与解混淆</h2>
      <p class="subtle">分析判断、工具步骤与实际执行结果</p>
    </div>
    {#if recovery.status}<span class={`badge ${statusTone(recovery.status)}`}
        >{states[recovery.status] || recovery.status}</span
      >{/if}
  </div>
  {#if recovery.plan}
    <section class="recovery-assessment" aria-label="逆向方案判断">
      <h3><ScanLine size={18} />方案判断</h3>
      <p class="assessment-text">{recovery.plan.assessment}</p>
      {#if recovery.plan.evidence.length}<details class="recovery-evidence">
          <summary>识别依据 · {recovery.plan.evidence.length} 条</summary>
          <ul>
            {#each recovery.plan.evidence as evidence}<li>{evidence}</li>{/each}
          </ul>
        </details>{/if}
    </section>
    <section class="recovery-steps" aria-label="工具执行步骤">
      <div class="section-heading">
        <h3><ListChecks size={18} />工具执行步骤</h3>
        <span class="subtle">共 {recovery.plan.steps.length} 步 · 按顺序执行</span>
      </div>
      <ol>
        {#each recovery.plan.steps as step, index}
          <li>
            <span class="step-number" aria-hidden="true">{index + 1}</span>
            <div class="step-body">
              <h4>{toolNames[step.tool] || step.tool}</h4>
              <div class="step-meta">
                <span>输入：{step.input === 'unpacked' ? '解包文件' : '原始文件'}</span>
                {#if step.profile}<span>配置：{step.profile}</span>{/if}
              </div>
              <div class="step-reason">
                <span>选择理由</span>
                <p>{step.reason}</p>
              </div>
            </div>
          </li>
        {/each}
      </ol>
      {#if !recovery.plan.steps.length}<p class="muted">
          本次计划未安排工具转换，具体依据和限制见方案判断。
        </p>{/if}
    </section>
  {/if}
  {#if recovery.history?.length}
    <section class="recovery-history" aria-label="逆向实际执行记录">
      <div class="section-heading">
        <h3>实际执行记录</h3>
        <span class="subtle">{recovery.history.length} 条记录</span>
      </div>
      {#each recovery.history as item, index}
        <article>
          <div class="panel-heading">
            <h4>{index + 1}. {toolNames[item.tool] || item.tool}</h4>
            <span class={`badge ${statusTone(item.status)}`}>{states[item.status] || item.status}</span>
          </div>
          {#if item.reason}<p>{item.reason}</p>{/if}
          <div class="artifact-links">
            {#if item.readable_artifact_id}<a href={artifactUrl(item.readable_artifact_id)} download
                ><Download size={15} />下载可读结果</a
              >{/if}
            {#if item.output_artifact_id}<a href={artifactUrl(item.output_artifact_id)} download
                ><Download size={15} />下载解包文件</a
              >{/if}
            {#if item.result_artifact_id}<a href={artifactUrl(item.result_artifact_id)} download
                ><FileJson size={15} />步骤证据</a
              >{/if}
          </div>
          {#if item.input_sha256 || item.output_sha256}
            <details class="recovery-fingerprints">
              <summary>文件校验信息</summary>
              <dl>
                {#if item.input_sha256}<div>
                    <dt>输入 SHA-256</dt>
                    <dd><code>{item.input_sha256}</code></dd>
                  </div>{/if}
                {#if item.output_sha256}<div>
                    <dt>输出 SHA-256</dt>
                    <dd><code>{item.output_sha256}</code></dd>
                  </div>{/if}
              </dl>
            </details>
          {/if}
          {#each item.warnings || [] as warning}<p class="recovery-warning">
              <Info size={15} />{warning}
            </p>{/each}
        </article>
      {/each}
    </section>
  {/if}
  {#if recovery.conclusion}<section class="recovery-conclusion" aria-label="逆向结果说明">
      <h3>结果说明</h3>
      <p>{recovery.conclusion.summary}</p>
    </section>{/if}
  {#if limitations.length}<section class="recovery-limitations" aria-label="逆向范围与限制">
      <h3><Info size={18} />范围与限制</h3>
      <ul>
        {#each limitations as limitation}<li>{limitation}</li>{/each}
      </ul>
    </section>{/if}
</section>

<style>
  .recovery-panel {
    display: grid;
    gap: var(--space-6);
    padding: var(--space-6);
    min-width: 0;
    border: 1px solid var(--line);
    border-radius: var(--radius-md);
    background: var(--surface);
  }
  .panel-heading,
  .section-heading,
  .artifact-links {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    flex-wrap: wrap;
  }
  .section-heading {
    margin-bottom: var(--space-3);
  }
  h3 {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: var(--text-lg);
  }
  h4 {
    margin: 0;
    color: var(--ink);
    font-size: var(--text-lg);
    line-height: 1.5;
  }
  p,
  li,
  code {
    overflow-wrap: anywhere;
  }
  p,
  li {
    line-height: 1.8;
    white-space: pre-wrap;
  }
  .recovery-assessment,
  .recovery-conclusion,
  .recovery-limitations {
    padding: var(--space-5);
    border: 1px solid var(--line);
    border-radius: var(--radius-md);
  }
  .recovery-assessment {
    background: var(--accent-soft);
    border-color: var(--accent-line);
    border-left: 4px solid var(--accent);
  }
  .recovery-assessment h3 {
    color: var(--accent-hover);
  }
  .assessment-text {
    margin-top: var(--space-3);
    font-size: var(--text-lg);
    font-weight: 500;
    color: var(--ink);
  }
  .recovery-evidence {
    margin-top: var(--space-4);
    padding-top: var(--space-3);
    border-top: 1px solid var(--accent-line);
  }
  summary {
    cursor: pointer;
    color: var(--text-secondary);
    font-size: var(--text-sm);
    font-weight: 600;
  }
  ul {
    display: grid;
    gap: 8px;
    margin: 12px 0 0;
    padding-left: 20px;
  }
  ol {
    display: grid;
    gap: var(--space-3);
    margin: 0;
    padding: 0;
    list-style: none;
  }
  ol li {
    display: grid;
    grid-template-columns: 32px minmax(0, 1fr);
    align-items: start;
    gap: var(--space-3);
    padding: var(--space-4);
    background: var(--surface-subtle);
    border: 1px solid var(--line);
    border-radius: var(--radius-md);
    white-space: normal;
  }
  .step-number {
    display: grid;
    place-items: center;
    width: 30px;
    height: 30px;
    border: 1px solid var(--accent-line);
    border-radius: 50%;
    background: var(--accent-soft);
    color: var(--accent-hover);
    font-weight: 600;
  }
  .step-body {
    min-width: 0;
  }
  .step-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 6px 16px;
    margin: 5px 0 12px;
    color: var(--muted);
    font-size: var(--text-sm);
  }
  .step-reason > span {
    display: block;
    margin-bottom: 3px;
    font-size: var(--text-xs);
    color: var(--muted);
  }
  .step-reason p {
    color: var(--text-secondary);
  }
  article {
    display: grid;
    gap: var(--space-3);
    padding: 18px 0;
    border-top: 1px solid var(--line);
  }
  article:last-child {
    padding-bottom: 0;
  }
  .artifact-links {
    justify-content: flex-start;
  }
  .artifact-links:empty {
    display: none;
  }
  .artifact-links a {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: var(--accent);
    font-size: var(--text-sm);
  }
  dl {
    display: grid;
    gap: 8px;
    margin-bottom: 0;
    font-size: var(--text-xs);
    color: var(--muted);
  }
  dd {
    margin: 4px 0 0;
  }
  .recovery-warning {
    display: flex;
    align-items: start;
    gap: 8px;
    color: var(--warning);
  }
  .recovery-conclusion {
    background: var(--surface-subtle);
  }
  .recovery-conclusion p {
    margin-top: 10px;
  }
  .recovery-limitations {
    background: var(--warning-soft);
    border-color: var(--warning-line);
  }
  .recovery-limitations h3 {
    color: var(--warning);
  }
  @media (max-width: 600px) {
    .recovery-panel,
    .recovery-assessment,
    .recovery-conclusion,
    .recovery-limitations {
      padding: var(--space-4);
    }
    .recovery-panel {
      gap: var(--space-5);
    }
    .section-heading {
      gap: 6px;
    }
    ol li {
      grid-template-columns: 26px minmax(0, 1fr);
      padding: 12px;
      gap: 10px;
    }
    .step-number {
      width: 26px;
      height: 26px;
    }
  }
</style>
