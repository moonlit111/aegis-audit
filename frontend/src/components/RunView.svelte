<script lang="ts">
  import { onMount } from 'svelte';
  import { Code, ConnectError } from '@connectrpc/connect';
  import {
    ArrowLeft,
    ArrowRight,
    Download,
    Square,
    FileCode2,
    Code2,
    Search,
    Network,
    Layers,
    ListChecks,
    ScrollText,
    ArrowUpRight,
    ChevronRight,
    RefreshCw,
    AlertCircle,
    FolderOpen,
    Hash,
    FileJson,
  } from '@lucide/svelte';
  import type {
    AuditRun,
    Snapshot,
    ProgramUnit,
    ProgramEdge,
    Artifact,
    RunEvent,
    RunPhase,
  } from '../gen/audit/v1/audit_pb';
  import { RunState } from '../gen/audit/v1/audit_pb';
  import {
    runsApi,
    projectsApi,
    programsApi,
    reportsApi,
    artifactUrl,
    errorMessage,
    requestId,
  } from '../lib/api';
  import {
    isTerminal,
    runLabel,
    scopeLabel,
    tone,
    parseJson,
    dateTime,
    bytes,
    type Summary,
    type UnitMetadata,
  } from '../lib/format';
  import CodeViewer from './CodeViewer.svelte';
  import CallGraph from './CallGraph.svelte';
  import AuditPanel from './AuditPanel.svelte';
  import RuntimePanel from './RuntimePanel.svelte';
  import RecoveryPanel from './RecoveryPanel.svelte';
  import RunProgress from './RunProgress.svelte';
  import AnnotationsPanel from './AnnotationsPanel.svelte';
  import ReportHistory from './ReportHistory.svelte';

  let {
    runId,
    onchanged,
    notify,
    projectName = '',
  }: {
    runId: string;
    onchanged: () => Promise<void>;
    notify: (message: string) => void;
    projectName?: string;
  } = $props();
  let run = $state<AuditRun>();
  let snapshot = $state<Snapshot>();
  let artifacts = $state<Artifact[]>([]);
  let units = $state<ProgramUnit[]>([]);
  let unit = $state<ProgramUnit>();
  let graph = $state<{ units: ProgramUnit[]; edges: ProgramEdge[] }>({ units: [], edges: [] });
  let total = $state(0);
  let query = $state('');
  let language = $state('');
  let tab = $state('program');
  let runtimeFinding = $state('');
  let viewer = $state('code');
  let events = $state<RunEvent[]>([]);
  let phases = $state<RunPhase[]>([]);
  let streamStatus = $state('连接中');
  let error = $state('');
  let notFound = $state(false);
  let loadingUnits = $state(false);
  let selectedId = $state('');
  let reportFormat = $state('html');
  let reportBusy = $state(false);
  let reportVersion = $state(0);
  let cancelBusy = $state(false);
  let cursor = $state(0n);
  let alive = true;
  let loadingRun: Promise<void> | undefined;
  let unitQueryGeneration = 0;
  let searchTimer: ReturnType<typeof setTimeout>;
  const controller = new AbortController();
  const summary = $derived(parseJson<Summary>(run?.summaryJson || '', {}));
  const metadata = $derived(parseJson<UnitMetadata>(unit?.metadataJson || '', {}));
  const files = $derived(summary.files || []);
  const parsedCount = $derived(files.filter((file) => file.status === 'PARSED').length);
  const gaps = $derived(files.filter((file) => !['PARSED', 'NOT_SOURCE'].includes(file.status)));
  const capabilityLabels: Record<string, string> = {
    import: '导入与逆向',
    'tree-sitter': '源码解析',
    ghidra: 'Ghidra 反编译',
  };
  const statusMessage = $derived.by(() => {
    if (!run || isTerminal(run.state)) return '';
    if (run.state === RunState.WAITING_EXECUTOR) {
      const capability =
        capabilityLabels[summary.required_capability || ''] || summary.required_capability || '所需工具';
      return `等待具备${capability}能力的执行器，连接后将自动继续。`;
    }
    if (run.state === RunState.CANCELLING) return '取消已登记；只有确认工具进程回收后，任务才会结束。';
    return '分析在执行器中进行，关闭或刷新页面不会取消任务。';
  });

  function loadRun() {
    if (loadingRun) return loadingRun;
    loadingRun = (async () => {
      try {
        const response = await runsApi.getRun({ runId }, { signal: controller.signal });
        if (!alive) return;
        const previousCount = run?.unitCount;
        const previousResult = parseJson<Summary>(run?.summaryJson || '', {}).result_artifact_id;
        run = response.run;
        phases = response.phases;
        notFound = false;
        error = '';
        artifacts = response.artifacts;
        if (!snapshot && run)
          snapshot = (
            await projectsApi.getSnapshot({ snapshotId: run.snapshotId }, { signal: controller.signal })
          ).snapshot;
        if (
          run?.unitCount !== previousCount ||
          parseJson<Summary>(run?.summaryJson || '', {}).result_artifact_id !== previousResult
        )
          await loadUnits();
      } catch (failure) {
        if (!alive || controller.signal.aborted) return;
        if (failure instanceof ConnectError && failure.code === Code.NotFound) {
          notFound = true;
          run = undefined;
          snapshot = undefined;
          error = '';
          return;
        }
        error = errorMessage(failure);
      }
    })().finally(() => {
      loadingRun = undefined;
    });
    return loadingRun;
  }
  async function loadUnits(append = false) {
    const generation = ++unitQueryGeneration;
    loadingUnits = true;
    try {
      const response = await programsApi.listUnits(
        { runId, query, language, offset: append ? units.length : 0, limit: 80 },
        { signal: controller.signal },
      );
      if (!alive || generation !== unitQueryGeneration) return;
      units = append ? [...units, ...response.units] : response.units;
      total = Number(response.total);
      if (!units.some((item) => item.id === selectedId)) {
        if (units.length)
          await selectUnit(
            units.find((item) => parseJson<UnitMetadata>(item.metadataJson, {}).kind === 'function')?.id ||
              units[0].id,
          );
        else {
          selectedId = '';
          unit = undefined;
          graph = { units: [], edges: [] };
        }
      }
    } catch (failure) {
      if (alive) error = errorMessage(failure);
    } finally {
      if (generation === unitQueryGeneration) loadingUnits = false;
    }
  }
  function search() {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      void loadUnits();
    }, 250);
  }
  async function selectUnit(id: string) {
    selectedId = id;
    try {
      const [detail, relation] = await Promise.all([
        programsApi.getUnit({ unitId: id }, { signal: controller.signal }),
        programsApi.getGraph({ unitId: id }, { signal: controller.signal }),
      ]);
      if (alive && id === selectedId) {
        unit = detail.unit;
        graph = relation;
      }
    } catch (failure) {
      if (alive) error = errorMessage(failure);
    }
  }
  async function watch() {
    while (alive) {
      try {
        streamStatus = cursor > 0n ? '游标重连中' : '连接中';
        for await (const message of runsApi.watchRun(
          { runId, afterSeq: cursor },
          { signal: controller.signal },
        )) {
          if (!alive) return;
          streamStatus = '实时连接';
          if (message.event && message.event.seq > cursor) {
            cursor = message.event.seq;
            events = [...events, message.event].slice(-500);
            if (
              ['RUN_COMPLETED', 'RUN_FINISHED', 'LEASE_EXPIRED', 'CANCEL_REQUESTED'].includes(
                message.event.kind,
              )
            ) {
              void loadRun();
              void onchanged();
            }
          }
        }
        await loadRun();
        if (notFound) return;
        if (run && isTerminal(run.state)) {
          streamStatus = '事件已归档';
          return;
        }
      } catch {
        if (!alive) return;
        streamStatus = '连接中断，正在重连';
      }
      await new Promise<void>((resolve) => {
        const finish = () => {
          clearTimeout(timer);
          controller.signal.removeEventListener('abort', finish);
          resolve();
        };
        const timer = setTimeout(finish, 1200);
        controller.signal.addEventListener('abort', finish, { once: true });
      });
    }
  }
  async function cancel() {
    if (cancelBusy) return;
    cancelBusy = true;
    try {
      run = (await runsApi.cancelRun({ runId })).run;
      notify('取消请求已记录，正在确认工具进程回收');
      await onchanged();
    } catch (failure) {
      error = errorMessage(failure);
    } finally {
      cancelBusy = false;
    }
  }
  async function exportReport() {
    reportBusy = true;
    try {
      const response = await reportsApi.createReport({ requestId: requestId(), runId, format: reportFormat });
      const link = document.createElement('a');
      link.href = artifactUrl(response.report!.artifactId);
      link.download = '';
      link.dataset.aegisDownloadNotice = response.report?.interim
        ? '阶段报告已生成，保留导出时的进度与证据'
        : '报告已生成，可在报告历史中再次下载';
      document.body.appendChild(link);
      link.click();
      link.remove();
      reportVersion += 1;
      await loadRun();
    } catch (failure) {
      error = errorMessage(failure);
    } finally {
      reportBusy = false;
    }
  }
  onMount(() => {
    void loadRun();
    void watch();
    const poll = setInterval(() => {
      if (!notFound && (!run || !isTerminal(run.state))) void loadRun();
    }, 1800);
    return () => {
      alive = false;
      controller.abort();
      clearInterval(poll);
      clearTimeout(searchTimer);
    };
  });
  $effect(() => {
    if (tab === 'recovery' && !summary.recovery) tab = 'events';
  });
</script>

{#if notFound}
  <section class="empty-panel">
    <AlertCircle size={32} strokeWidth={1.2} />
    <h2>分析任务不存在或已被删除</h2>
    <p>地址中的任务 ID 没有对应的持久化记录，请从任务列表重新选择。</p>
    <div class="empty-actions">
      <a class="button secondary" href="#/runs">查看全部分析任务</a><a
        class="button primary"
        href="#/projects">选择分析目标</a
      >
    </div>
  </section>
{:else}
  <a href="#/runs" class="back-link"><ArrowLeft size={14} />全部分析任务</a>
  <div class="run-heading">
    <div>
      <div class="eyebrow">{scopeLabel(run?.scope || '')}</div>
      <h1 title={snapshot?.name}>{snapshot?.name || '程序结构分析'}</h1>
      <p>
        <code>{runId.slice(0, 8)}</code><span>·</span>{dateTime(run?.createdAt || '')}<span>·</span
        >{projectName || '固定快照分析'}
      </p>
    </div>
    <div class="run-actions">
      {#if run && !isTerminal(run.state)}<button
          class="button secondary"
          disabled={cancelBusy || run.state === RunState.CANCELLING}
          onclick={cancel}
          ><Square size={13} />{run.state === RunState.CANCELLING ? '等待进程回收' : '取消任务'}</button
        >{/if}
      <div class="report-action">
        <select aria-label="报告格式" bind:value={reportFormat}
          ><option value="html">HTML</option><option value="pdf">PDF</option><option value="json">JSON</option
          ><option value="markdown">Markdown</option></select
        ><button class="button primary" disabled={reportBusy || !run} onclick={exportReport}
          ><Download size={15} />{reportBusy
            ? '生成中…'
            : run && !isTerminal(run.state)
              ? '导出阶段报告'
              : '导出报告'}</button
        >
      </div>
    </div>
  </div>
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
          void loadRun();
        }}>重试</button
      >
    </div>{/if}
  {#if run}
    <div class="run-summary">
      <div>
        <span>任务状态</span><strong class={`run-status ${tone(run.state)}`}
          ><i class="dot"></i>{runLabel(run.state)}</strong
        >
      </div>
      <div><span>程序单元</span><strong>{run.unitCount.toString()}<small>模块 / 函数</small></strong></div>
      <div><span>函数索引</span><strong>{summary.function_count ?? '—'}</strong></div>
      <div>
        <span>调用线索</span><strong
          >{summary.edge_count ?? '—'}<small>{summary.unresolved_calls ?? 0} 条未解析</small></strong
        >
      </div>
      <div class="audit-not-run">
        <span>漏洞审计</span><strong
          >{run.scope === 'SECURITY_AUDIT'
            ? {
                COMPLETED: '完成',
                PARTIAL: '部分完成',
                RUNNING: '分析中',
                QUEUED: '待分析',
                CANCELLED: '已取消',
              }[summary.vulnerability_audit || ''] || '准备中'
            : '未执行'}</strong
        >
      </div>
    </div>
    {#if run.error}<div class="error-banner"><AlertCircle size={18} /><span>{run.error}</span></div>{/if}
    <RunProgress
      {phases}
      runState={run.state}
      {statusMessage}
      showEnvironmentLink={!isTerminal(run.state)}
      canSelect={(phase) => phase.id !== 'RECOVERY' || Boolean(summary.recovery)}
      onselect={(phase) => {
        if (phase.unitId) {
          tab = 'program';
          void selectUnit(phase.unitId);
        } else if (phase.id === 'RECOVERY') tab = 'recovery';
        else if (phase.id === 'RUNTIME') tab = 'runtime';
        else if (phase.id === 'STRUCTURE') tab = 'program';
        else tab = 'audit';
      }}
    />
    <div class="view-tabs" role="tablist" aria-label="分析内容">
      <button
        role="tab"
        aria-selected={tab === 'program'}
        class:active={tab === 'program'}
        onclick={() => {
          tab = 'program';
        }}><Code2 size={16} />程序视图</button
      >
      <button
        role="tab"
        aria-selected={tab === 'reports'}
        class:active={tab === 'reports'}
        onclick={() => (tab = 'reports')}><Download size={16} />报告历史</button
      >
      <button
        role="tab"
        aria-selected={tab === 'annotations'}
        class:active={tab === 'annotations'}
        onclick={() => (tab = 'annotations')}><Code2 size={16} />关键逻辑</button
      >
      {#if summary.recovery}<button
          role="tab"
          aria-selected={tab === 'recovery'}
          class:active={tab === 'recovery'}
          onclick={() => (tab = 'recovery')}><Code2 size={16} />逆向与解混淆</button
        >{/if}
      <button
        role="tab"
        aria-selected={tab === 'runtime'}
        class:active={tab === 'runtime'}
        onclick={() => {
          runtimeFinding = '';
          tab = 'runtime';
        }}><ListChecks size={16} />运行验证</button
      >
      {#if run.scope === 'SECURITY_AUDIT'}<button
          role="tab"
          aria-selected={tab === 'audit'}
          class:active={tab === 'audit'}
          onclick={() => (tab = 'audit')}
          ><ListChecks size={16} />漏洞审计<span class="tab-count">{summary.finding_count || 0}</span></button
        >{/if}
      <button
        role="tab"
        aria-selected={tab === 'coverage'}
        class:active={tab === 'coverage'}
        onclick={() => {
          tab = 'coverage';
        }}
        ><ListChecks size={16} />覆盖与产物{#if gaps.length}<span class="tab-count">{gaps.length}</span
          >{/if}</button
      ><button
        role="tab"
        aria-selected={tab === 'events'}
        class:active={tab === 'events'}
        onclick={() => {
          tab = 'events';
        }}><ScrollText size={16} />任务事件<span class="tab-count">{cursor.toString()}</span></button
      ><span class="tabs-extra"
        ><i class="dot" class:green={streamStatus === '实时连接' || streamStatus === '事件已归档'}
        ></i>{streamStatus}</span
      >
    </div>
    {#if tab === 'reports'}
      <ReportHistory {runId} version={reportVersion} />
    {:else if tab === 'annotations'}
      <AnnotationsPanel
        {run}
        {notify}
        onselectunit={(id) => {
          tab = 'program';
          void selectUnit(id);
        }}
      />
    {:else if tab === 'recovery' && summary.recovery}
      <RecoveryPanel recovery={summary.recovery} />
    {/if}
    <div class:hidden-panel={tab !== 'runtime'}>
      <RuntimePanel
        {run}
        {snapshot}
        {unit}
        {notify}
        {onchanged}
        findingId={runtimeFinding}
        active={tab === 'runtime'}
      />
    </div>
    {#if run.scope === 'SECURITY_AUDIT'}<div class:hidden-panel={tab !== 'audit'}>
        <AuditPanel
          {run}
          {notify}
          knownUnits={units}
          active={tab === 'audit'}
          onverify={(id) => {
            runtimeFinding = id;
            tab = 'runtime';
          }}
          onselectunit={(id) => {
            tab = 'program';
            void selectUnit(id);
          }}
        />
      </div>{/if}
    {#if tab === 'program'}
      <div class="program-layout">
        <aside class="unit-explorer">
          <div class="explorer-title"><strong>程序索引</strong><span>{total}</span></div>
          <label class="search-input"
            ><Search size={15} /><input
              placeholder="搜索函数或文件…"
              aria-label="搜索函数或文件"
              bind:value={query}
              oninput={search}
            /></label
          ><select
            class="language-filter"
            bind:value={language}
            onchange={() => loadUnits()}
            aria-label="语言筛选"
            ><option value="">全部语言</option><option value="python">Python</option><option value="go"
              >Go</option
            ><option value="c">C</option><option value="cpp">C++</option><option value="binary">二进制</option
            ></select
          >
          <div class="unit-list">
            {#each units as item}<button
                class="unit-row"
                class:selected={selectedId === item.id}
                onclick={() => selectUnit(item.id)}
                title={`${item.path} · ${item.name}`}
                ><span class="unit-symbol"
                  >{#if parseJson<UnitMetadata>(item.metadataJson, {}).kind === 'module'}<FileCode2
                      size={15}
                    />{:else}<Code2 size={15} />{/if}</span
                ><span><strong>{item.name}</strong><small>{item.path}</small></span><span
                  class="unit-location">{item.address || `L${item.startLine}–L${item.endLine}`}</span
                ></button
              >{/each}{#if !units.length}<div class="explorer-empty">
                {loadingUnits
                  ? '正在读取索引…'
                  : query || language
                    ? '没有匹配的程序单元'
                    : '尚无程序索引，请查看任务状态与覆盖情况。'}
              </div>{/if}
          </div>
          {#if units.length < total}<button
              class="text-button load-more"
              onclick={() => loadUnits(true)}
              disabled={loadingUnits}>加载更多 · {units.length} / {total}</button
            >{/if}
          <div class="explorer-footer">
            <Hash size={12} /><code title={snapshot?.targetSha256}
              >{snapshot?.targetSha256.slice(0, 16) || '等待快照'}…</code
            >
          </div>
        </aside>
        <section class="program-content">
          {#if unit}<div class="unit-header">
              <div class="unit-path">
                <FileCode2 size={15} /><span title={unit.path}>{unit.path}</span><ChevronRight
                  size={13}
                /><strong>{unit.name}</strong>
              </div>
              <span class={`badge ${unit.quality === 'PARSED' ? 'neutral' : 'warning'}`}
                >{unit.language === 'binary'
                  ? metadata.analysis_engine === 'IDA_HEXRAYS_D810'
                    ? 'IDA / D-810 伪代码'
                    : 'Ghidra 伪代码'
                  : unit.language.toUpperCase()}</span
              >
            </div>
            <div class="unit-meta">
              <span
                >{unit.address
                  ? `${metadata.address_space === 'UNPACKED_IMAGE' ? '解包映像入口' : '入口'} ${unit.address}`
                  : `原文件 L${unit.startLine}–L${unit.endLine}`}</span
              >{#if unit.address}<span>RVA {metadata.rva || '—'}</span>{:else}<span
                  >UTF-8 字节 [{unit.startByte.toString()}, {unit.endByte.toString()})</span
                >{/if}<a href={artifactUrl(unit.artifactId)} title="下载分析原始产物"
                >原始依据<ArrowUpRight size={12} /></a
              >
            </div>
            <div class="code-tabs" role="tablist" aria-label="程序视图模式">
              <button
                role="tab"
                aria-selected={viewer === 'code'}
                class:active={viewer === 'code'}
                onclick={() => {
                  viewer = 'code';
                }}><Code2 size={14} />{unit.language === 'binary' ? '伪代码' : '源代码'}</button
              ><button
                role="tab"
                aria-selected={viewer === 'graph'}
                class:active={viewer === 'graph'}
                onclick={() => {
                  viewer = 'graph';
                }}><Network size={14} />调用图</button
              ><button
                role="tab"
                aria-selected={viewer === 'details'}
                class:active={viewer === 'details'}
                onclick={() => {
                  viewer = 'details';
                }}><Layers size={14} />结构细节</button
              >
            </div>
            {#if viewer === 'code'}{#if unit.code}<CodeViewer {unit} />{:else}<div class="empty-panel">
                  <AlertCircle size={27} />
                  <h3>未生成可展示的代码</h3>
                  <p>{metadata.decompile_error || '请查看工具日志与覆盖缺口。'}</p>
                </div>{/if}
              <div class="code-note">
                {unit.language === 'binary'
                  ? '伪代码只映射到函数入口；行号不代表精确指令位置。调用点与 P-code 保留实际地址。'
                  : '显示原始源码片段。调用关系按同文件唯一名称推断；条件分支来自语法树。'}
              </div>
            {:else if viewer === 'graph'}<CallGraph
                units={graph.units}
                edges={graph.edges}
                focus={unit.id}
                focusUnit={unit}
                onselect={selectUnit}
              />
              <div class="relation-list">
                {#each graph.edges.slice(0, 30) as edge}<div>
                    <code>{graph.units.find((item) => item.id === edge.sourceId)?.name || unit.name}</code
                    ><ArrowRight size={13} />{#if edge.targetId}<button
                        class="text-button"
                        onclick={() => selectUnit(edge.targetId)}>{edge.targetName}</button
                      >{:else}<span>{edge.targetName}</span>{/if}<small
                      >{edge.certainty === 'INFERRED'
                        ? '推断'
                        : edge.certainty === 'UNKNOWN'
                          ? '未解析'
                          : '工具报告'} · {edge.address || `L${edge.line}`}</small
                    >
                  </div>{/each}{#if !graph.edges.length}<p class="muted">
                    当前单元未记录到调用边。模块内的函数调用请从函数索引查看。
                  </p>{/if}{#if graph.edges.length > 30}<p class="muted">
                    下方列出前 30 条关系，画布最多显示 200 条。
                  </p>{/if}
              </div>
            {:else}<div class="structure-details">
                {#if unit.language === 'binary'}<h3>基本块与后继关系</h3>
                  <p class="muted">由 Ghidra 报告的静态控制流，保留跳转目标地址。</p>
                  <div class="table-scroll">
                    <table>
                      <thead><tr><th>起始地址</th><th>结束地址</th><th>后继</th></tr></thead><tbody
                        >{#each metadata.basic_blocks || [] as block}<tr
                            ><td><code>{block.start}</code></td><td><code>{block.end}</code></td><td
                              >{#each block.successors as successor}<span class="block-successor"
                                  ><code>{successor.address}</code> {successor.flow_type}</span
                                >{/each}</td
                            ></tr
                          >{/each}</tbody
                      >
                    </table>
                  </div>
                  <details>
                    <summary>P-code 操作 · {metadata.pcode?.length || 0} 条</summary>
                    <div class="pcode-list">
                      {#each metadata.pcode || [] as operation}<span
                          ><code>{operation.address}</code><strong>{operation.opcode}</strong></span
                        >{/each}
                    </div>
                  </details>
                  <details>
                    <summary>字符串引用 · {metadata.referenced_strings?.length || 0} 条</summary
                    >{#each metadata.referenced_strings || [] as string}<p>
                        <code>{string.address}</code>
                        {string.value}
                      </p>{/each}
                  </details>{:else}<h3>语法分支</h3>
                  <p class="muted">这里只展示语法树中的条件与循环，不代表完整语义控制流。</p>
                  {#if metadata.branches?.length}<table>
                      <thead><tr><th>位置</th><th>节点类型</th><th>条件片段</th></tr></thead><tbody
                        >{#each metadata.branches as branch}<tr
                            ><td>L{branch.line}</td><td><code>{branch.kind}</code></td><td
                              ><code>{branch.condition || '—'}</code></td
                            ></tr
                          >{/each}</tbody
                      >
                    </table>{:else}<div class="empty-panel compact">
                      当前单元未记录语法分支。选择函数可查看其内部结构。
                    </div>{/if}{/if}
              </div>{/if}
          {:else}<div class="empty-program">
              <div class="welcome-symbol"><Code2 size={32} strokeWidth={1.2} /></div>
              <h2>
                {isTerminal(run.state)
                  ? '当前没有可显示的代码'
                  : run.state === RunState.QUEUED || run.state === RunState.WAITING_EXECUTOR
                    ? '任务尚未开始解析'
                    : '正在建立程序索引'}
              </h2>
              <p>
                {isTerminal(run.state)
                  ? '检查覆盖与产物，了解支持范围、解析错误与原始日志。'
                  : run.state === RunState.QUEUED || run.state === RunState.WAITING_EXECUTOR
                    ? '任务仍在队列或等待执行器；被领取后才会建立程序索引。'
                    : '解析完成后，函数、代码与位置将出现在这里。'}
              </p>
              <button
                class="text-button"
                onclick={() => {
                  tab = isTerminal(run!.state) ? 'coverage' : 'events';
                }}>查看{isTerminal(run.state) ? '覆盖情况' : '任务事件'}<ArrowRight size={14} /></button
              >
            </div>{/if}
        </section>
      </div>
    {:else if tab === 'coverage'}
      <div class="coverage-grid">
        <section class="panel coverage-panel">
          <div class="panel-title">
            <h2>文件覆盖</h2>
            <span>{parsedCount} 已解析 / {files.length} 个文件</span>
          </div>
          {#if summary.warnings?.length}<div class="warning-list">
              {#each summary.warnings as warning}<p><AlertCircle size={15} />{warning}</p>{/each}
            </div>{/if}
          <div class="table-scroll">
            <table>
              <thead><tr><th>文件</th><th>状态</th><th>单元</th><th>说明</th></tr></thead><tbody
                >{#each files.slice(0, 500) as file}<tr
                    ><td class="file-cell">{file.path}<small>{file.language}</small></td><td
                      ><span
                        class={`badge ${file.status === 'PARSED' ? 'success' : file.status === 'NOT_SOURCE' ? 'neutral' : 'warning'}`}
                        >{(
                          {
                            PARSED: '已解析',
                            PARTIAL: '部分解析',
                            FAILED: '失败',
                            UNSUPPORTED: '不支持',
                            NOT_SOURCE: '资源文件',
                          } as Record<string, string>
                        )[file.status] || file.status}</span
                      ></td
                    ><td>{file.unit_count}</td><td>{file.reason || '—'}</td></tr
                  >{/each}</tbody
              >
            </table>
          </div>
          {#if !files.length}<div class="empty-panel compact">
              尚无覆盖记录。
            </div>{/if}{#if files.length > 500}<p class="field-help">
              显示前 500 个文件。完整记录见分析产物与 JSON 报告。
            </p>{/if}
        </section>
        <section class="panel tool-panel">
          <div class="panel-title">
            <h2>工具记录</h2>
            <span>{summary.tools?.length || 0}</span>
          </div>
          {#each summary.tools || [] as tool}<div class="tool-record">
              <div>
                <strong>{tool.name}</strong><span class="badge neutral"
                  >{tool.exit_code === null ? '进程内解析' : `退出码 ${tool.exit_code}`}</span
                >
              </div>
              <p>{tool.version}</p>
              <small>{dateTime(tool.started_at)} → {dateTime(tool.finished_at)}</small
              >{#if tool.log_artifact_id}<a href={artifactUrl(tool.log_artifact_id)} class="text-button"
                  >工具日志<Download size={13} /></a
                >{/if}
            </div>{/each}{#if !summary.tools?.length}<p class="muted inset">
              尚无工具结果。失败过程可在产物和任务事件中查看。
            </p>{/if}
        </section>
      </div>
      <section class="panel artifacts-panel">
        <div class="panel-title">
          <h2>归档产物</h2>
          <span>下载后可按 SHA-256 核对</span>
        </div>
        <div class="artifact-list">
          {#each artifacts as artifact}<a href={artifactUrl(artifact.id)} class="artifact-row"
              ><span class="file-icon"><FileJson size={20} /></span><span
                ><strong>{artifact.name}</strong><small
                  >{bytes(artifact.size)}<i>·</i><code title={artifact.sha256}
                    >SHA256 {artifact.sha256.slice(0, 24)}…</code
                  ></small
                ></span
              ><Download size={16} /></a
            >{/each}
        </div>
      </section>
      {#if summary.exclusions?.length}<section class="panel exclusions-panel">
          <details>
            <summary><FolderOpen size={16} />导入时排除的文件或目录 · {summary.exclusions.length} 项</summary>
            <table>
              <tbody
                >{#each summary.exclusions.slice(0, 100) as exclusion}<tr
                    ><td>{exclusion.path}</td><td>{exclusion.reason}</td></tr
                  >{/each}</tbody
              >
            </table>
            {#if summary.exclusions.length > 100}<p>这里列出前 100 项，完整列表在快照清单中。</p>{/if}
          </details>
        </section>{/if}
    {:else}<section class="panel events-panel">
        <div class="panel-title">
          <div>
            <h2>持久化任务事件</h2>
            <span class="subtle">按序号恢复 · 断线后自动补读 · 页面保留最近 500 条</span>
          </div>
          <span class="badge neutral">游标 {cursor.toString()}</span>
        </div>
        <div class="event-list">
          {#each events as event}<div class="event-row">
              <span class="event-seq">{event.seq.toString().padStart(3, '0')}</span><time
                >{dateTime(event.createdAt)}</time
              >
              <div>
                <span class="event-kind">{event.kind}</span>
                {#if event.phaseId}<span class="subtle">
                    · 阶段 {event.phaseOrder}/{event.phaseCount}
                    {phases.find((p) => p.id === event.phaseId)?.title || event.phaseId}</span
                  >{/if}
                <pre>{event.message}</pre>
                {#if event.total > 0n && event.kind === 'TOOL_PROGRESS'}<div class="event-progress">
                    <progress max={Number(event.total)} value={Number(event.current)}></progress><span
                      >{event.current.toString()} / {event.total.toString()}</span
                    >
                  </div>{/if}
              </div>
            </div>{/each}{#if !events.length}<div class="empty-panel">正在读取事件…</div>{/if}
        </div>
      </section>{/if}
  {:else if !error}<div class="empty-panel">
      <RefreshCw class="spin" size={24} />
      <p>正在读取分析任务…</p>
    </div>{/if}
{/if}
