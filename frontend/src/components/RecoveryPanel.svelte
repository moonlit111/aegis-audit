<script lang="ts">
  import { Download, FileJson } from '@lucide/svelte';
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
</script>

<section class="recovery-panel">
  <div class="panel-heading">
    <h2>逆向与解混淆</h2>
    <span class="badge neutral">{states[recovery.status || ''] || recovery.status}</span>
  </div>
  {#if recovery.plan}
    <p>{recovery.plan.assessment}</p>
    <details>
      <summary>识别依据</summary>
      <ul>
        {#each recovery.plan.evidence as evidence}<li>{evidence}</li>{/each}
      </ul>
    </details>
    <h3>智能体规划的步骤</h3>
    <ol>
      {#each recovery.plan.steps as step}<li>
          <strong>{toolNames[step.tool] || step.tool}</strong> · {step.input === 'unpacked'
            ? '解包文件'
            : '原始文件'}{step.profile ? ` · ${step.profile}` : ''}
          <p>{step.reason}</p>
        </li>{/each}
    </ol>
    {#if !recovery.plan.steps.length}<p class="muted">
        本次计划未安排工具转换，具体依据和限制见智能体说明。
      </p>{/if}
  {/if}
  {#if recovery.history?.length}
    <h3>实际执行记录</h3>
    {#each recovery.history as item, index}
      <article>
        <div class="panel-heading">
          <strong>{index + 1}. {toolNames[item.tool] || item.tool}</strong><span class="badge neutral"
            >{states[item.status] || item.status}</span
          >
        </div>
        {#if item.reason}<p>{item.reason}</p>{/if}
        {#if item.input_sha256}<p class="muted">输入 SHA-256：<code>{item.input_sha256}</code></p>{/if}
        {#if item.output_sha256}<p class="muted">输出 SHA-256：<code>{item.output_sha256}</code></p>{/if}
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
        {#each item.warnings || [] as warning}<p class="muted">{warning}</p>{/each}
      </article>
    {/each}
  {/if}
  {#if recovery.conclusion}<h3>结果说明</h3>
    <p>{recovery.conclusion.summary}</p>{/if}
  {#each recovery.conclusion?.limitations || recovery.plan?.limitations || [] as limitation}<p class="muted">
      {limitation}
    </p>{/each}
</section>

<style>
  .recovery-panel {
    padding: 24px;
    max-width: 1120px;
  }
  .panel-heading,
  .artifact-links {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    flex-wrap: wrap;
  }
  .artifact-links {
    justify-content: flex-start;
  }
  .artifact-links a {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
  article {
    padding: 20px 0;
    border-top: 1px solid var(--border, #dce7e3);
  }
  li {
    margin: 12px 0;
  }
  code {
    overflow-wrap: anywhere;
  }
</style>
