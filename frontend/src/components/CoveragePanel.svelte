<script lang="ts">
  import type { Snippet } from 'svelte';
  import { AlertCircle, Download, FileJson, FolderOpen } from '@lucide/svelte';
  import type { Artifact } from '../gen/audit/v1/audit_pb';
  import { artifactUrl } from '../lib/api';
  import { bytes, dateTime, type Summary } from '../lib/format';

  let {
    summary,
    artifacts,
    verification,
  }: { summary: Summary; artifacts: Artifact[]; verification?: Snippet } = $props();
  let onlyGaps = $state(false);
  const files = $derived(summary.files || []);
  const parsedCount = $derived(files.filter((file) => file.status === 'PARSED').length);
  const gaps = $derived(files.filter((file) => !['PARSED', 'NOT_SOURCE'].includes(file.status)));
  const visibleFiles = $derived(onlyGaps ? gaps : files);
  const statusLabels: Record<string, string> = {
    PARSED: '已解析',
    PARTIAL: '部分解析',
    FAILED: '失败',
    UNSUPPORTED: '不支持',
    NOT_SOURCE: '资源文件',
  };
</script>

<section class="coverage-workspace" aria-label="覆盖与产物">
  {@render verification?.()}
  <div class="coverage-overview">
    <div><span>已解析文件</span><strong>{parsedCount}<small>/ {files.length} 个文件记录</small></strong></div>
    <div class:has-gaps={gaps.length > 0}>
      <span>需关注文件</span><strong>{gaps.length}<small>部分解析、失败或不支持</small></strong>
    </div>
    <div><span>归档产物</span><strong>{artifacts.length}<small>分析结果与执行证据</small></strong></div>
  </div>

  <section class="panel coverage-panel" aria-label="文件覆盖">
    <div class="panel-title">
      <div>
        <h2>文件覆盖</h2>
        <p class="subtle">查看各文件的解析状态、程序单元与未覆盖原因。</p>
      </div>
      <label class="coverage-filter"><input type="checkbox" bind:checked={onlyGaps} />仅看需关注文件</label>
    </div>
    {#if summary.warnings?.length}<div class="warning-list">
        {#each summary.warnings as warning}<p><AlertCircle size={16} />{warning}</p>{/each}
      </div>{/if}
    <div class="table-scroll">
      <table>
        <thead><tr><th>文件</th><th>状态</th><th>单元</th><th>说明</th></tr></thead>
        <tbody>
          {#each visibleFiles.slice(0, 500) as file}<tr
              class:coverage-gap={!['PARSED', 'NOT_SOURCE'].includes(file.status)}
            >
              <td class="file-cell">{file.path}<small>{file.language}</small></td>
              <td data-label="状态"
                ><span
                  class={`badge ${file.status === 'PARSED' ? 'success' : file.status === 'NOT_SOURCE' ? 'neutral' : file.status === 'FAILED' ? 'danger' : 'warning'}`}
                  >{statusLabels[file.status] || file.status}</span
                ></td
              >
              <td data-label="程序单元">{file.unit_count}</td><td data-label="说明">{file.reason || '—'}</td>
            </tr>{/each}
        </tbody>
      </table>
    </div>
    {#if !visibleFiles.length}<div class="empty-panel compact">
        {onlyGaps && files.length ? '当前没有需关注的文件。' : '暂无文件覆盖记录。'}
      </div>{/if}
    {#if visibleFiles.length > 500}<p class="field-help">
        当前筛选显示前 500 个文件，完整记录见分析产物与 JSON 报告。
      </p>{/if}
  </section>

  <section class="panel artifacts-panel" aria-label="归档产物">
    <div class="panel-title">
      <div>
        <h2>归档产物</h2>
        <p class="subtle">下载分析结果、工具日志与证据文件。</p>
      </div>
      <span class="badge neutral">{artifacts.length} 个文件</span>
    </div>
    <div class="artifact-list">
      {#each artifacts as artifact}<a href={artifactUrl(artifact.id)} class="artifact-row">
          <span class="file-icon"><FileJson size={22} /></span>
          <span class="artifact-info"
            ><strong>{artifact.name}</strong><small
              >{bytes(artifact.size)}<i>·</i><code title={`SHA-256 ${artifact.sha256}`}
                >SHA256 {artifact.sha256.slice(0, 12)}…</code
              ></small
            ></span
          >
          <span class="artifact-download"><Download size={15} />下载</span>
        </a>{/each}
    </div>
    {#if !artifacts.length}<div class="empty-panel compact">暂无归档产物，生成后会显示在这里。</div>{/if}
  </section>

  <section class="panel tool-panel" aria-label="工具记录">
    <div class="panel-title">
      <div>
        <h2>工具记录</h2>
        <p class="subtle">执行版本、退出状态和原始日志</p>
      </div>
      <span class="badge neutral">{summary.tools?.length || 0} 条</span>
    </div>
    <div class="tool-records">
      {#each summary.tools || [] as tool}<div class="tool-record">
          <div>
            <strong>{tool.name}</strong><span
              class={`badge ${tool.exit_code === null ? 'neutral' : tool.exit_code === 0 ? 'success' : 'danger'}`}
              >{tool.exit_code === null ? '进程内解析' : `退出码 ${tool.exit_code}`}</span
            >
          </div>
          <p>{tool.version}</p>
          <small>{dateTime(tool.started_at)} → {dateTime(tool.finished_at)}</small>
          {#if tool.log_artifact_id}<a href={artifactUrl(tool.log_artifact_id)} class="text-button"
              >工具日志<Download size={13} /></a
            >{/if}
        </div>{/each}
    </div>
    {#if !summary.tools?.length}<p class="empty-panel compact">
        尚无工具结果。失败过程可在产物和任务事件中查看。
      </p>{/if}
  </section>

  {#if summary.exclusions?.length}<section class="panel exclusions-panel">
      <details>
        <summary><FolderOpen size={16} />导入时排除的文件或目录 · {summary.exclusions.length} 项</summary>
        <div class="table-scroll">
          <table>
            <thead><tr><th>文件或目录</th><th>排除原因</th></tr></thead>
            <tbody
              >{#each summary.exclusions.slice(0, 100) as exclusion}<tr
                  ><td>{exclusion.path}</td><td>{exclusion.reason}</td></tr
                >{/each}</tbody
            >
          </table>
        </div>
        {#if summary.exclusions.length > 100}<p>这里列出前 100 项，完整列表在快照清单中。</p>{/if}
      </details>
    </section>{/if}
</section>

<style>
  .coverage-workspace {
    display: grid;
    gap: var(--space-5);
    min-width: 0;
  }
  .coverage-overview {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 14px;
  }
  .coverage-overview > div {
    padding: 18px 20px;
    border: 1px solid var(--line);
    border-radius: var(--radius-md);
    background: var(--surface-subtle);
  }
  .coverage-overview span {
    color: var(--muted);
    font-size: var(--text-sm);
  }
  .coverage-overview strong {
    display: block;
    margin-top: 8px;
    font-size: 26px;
    font-weight: 600;
    line-height: 1.4;
  }
  .coverage-overview small {
    display: block;
    margin-top: 5px;
    font-size: var(--text-xs);
    font-weight: 400;
    color: var(--muted);
  }
  .coverage-overview .has-gaps {
    border-color: var(--warning-line);
    background: var(--warning-soft);
  }
  .has-gaps strong {
    color: var(--warning);
  }
  .panel-title {
    align-items: center;
    flex-wrap: wrap;
    gap: 12px;
    padding: 18px 20px;
  }
  .panel-title .subtle {
    margin-top: 5px;
  }
  .coverage-filter {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: var(--text-sm);
    color: var(--text-secondary);
    cursor: pointer;
  }
  .coverage-filter input {
    accent-color: var(--accent);
    width: 16px;
    height: 16px;
  }
  .coverage-panel table {
    width: 100%;
  }
  .coverage-panel td {
    vertical-align: top;
  }
  .coverage-panel td:last-child {
    font-size: var(--text-sm);
    line-height: 1.7;
    color: var(--text-secondary);
  }
  .file-cell {
    font-weight: 500;
    line-height: 1.7;
  }
  .file-cell small {
    font-weight: 400;
  }
  .coverage-gap td:first-child {
    box-shadow: inset 3px 0 var(--warning-line);
  }
  .warning-list p {
    align-items: start;
    line-height: 1.7;
  }
  .artifacts-panel,
  .exclusions-panel {
    margin-top: 0;
  }
  .artifact-list {
    padding: 14px;
    gap: 12px;
  }
  .artifact-row,
  .artifact-row:nth-child(odd) {
    padding: 16px;
    border: 1px solid var(--line);
    border-radius: var(--radius-md);
    align-items: start;
  }
  .artifact-row strong {
    font-weight: 600;
    white-space: normal;
    overflow-wrap: anywhere;
    line-height: 1.6;
  }
  .artifact-row small {
    white-space: normal;
    overflow-wrap: anywhere;
  }
  .artifact-download {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    color: var(--accent);
    flex: none;
    font-size: var(--text-sm);
  }
  .tool-records {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 14px;
    padding: 14px;
  }
  .tool-record {
    min-width: 0;
    display: grid;
    gap: 8px;
    padding: 16px;
    border: 1px solid var(--line);
    border-radius: var(--radius-md);
  }
  .tool-record > div {
    flex-wrap: wrap;
  }
  .tool-record p {
    overflow-wrap: anywhere;
    line-height: 1.7;
  }
  .tool-record .text-button {
    justify-self: start;
  }
  .exclusions-panel td {
    white-space: normal;
    overflow-wrap: anywhere;
    max-width: 400px;
  }
  @media (max-width: 760px) {
    .coverage-panel table,
    .coverage-panel tbody {
      display: block;
      width: 100%;
    }
    .coverage-panel thead {
      position: absolute;
      width: 1px;
      height: 1px;
      overflow: hidden;
      clip-path: inset(50%);
      white-space: nowrap;
    }
    .coverage-panel tbody tr {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px 16px;
      padding: 16px;
      border-bottom: 1px solid var(--line);
    }
    .coverage-panel tbody tr:last-child {
      border-bottom: 0;
    }
    .coverage-panel td,
    .coverage-panel td:last-child {
      min-width: 0;
      max-width: none;
      padding: 0;
      border: 0;
      white-space: normal;
    }
    .coverage-panel td:first-child,
    .coverage-panel td:last-child {
      grid-column: 1 / -1;
    }
    .coverage-panel td[data-label]::before {
      content: attr(data-label);
      display: block;
      margin-bottom: 4px;
      color: var(--muted);
      font-size: var(--text-xs);
    }
    .coverage-panel .coverage-gap {
      border-left: 3px solid var(--warning-line);
      padding-left: 13px;
    }
    .coverage-gap td:first-child {
      box-shadow: none;
    }
    .coverage-overview {
      grid-template-columns: minmax(0, 1fr);
      gap: 10px;
    }
    .coverage-overview > div {
      padding: 14px 16px;
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      align-items: center;
      gap: 12px;
    }
    .coverage-overview strong {
      margin: 0;
      text-align: right;
      font-size: 22px;
    }
    .coverage-overview small {
      font-size: var(--text-xs);
    }
    .artifact-list,
    .tool-records {
      grid-template-columns: minmax(0, 1fr);
      padding: 12px;
    }
    .panel-title {
      padding: 16px;
    }
    .artifact-row,
    .artifact-row:nth-child(odd) {
      padding: 12px;
      gap: 8px;
    }
    .artifact-row .file-icon {
      display: none;
    }
    .exclusions-panel {
      padding: 16px;
    }
  }
</style>
