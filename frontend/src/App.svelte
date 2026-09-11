<script lang="ts">
  import { onMount } from 'svelte';
  import {
    Shield,
    FolderKanban,
    Activity,
    Server,
    Plus,
    ArrowUpRight,
    ArrowRight,
    ChevronRight,
    GitBranch,
    FileCode2,
    Binary,
    Layers,
    CircleHelp,
    RefreshCw,
    Cpu,
    Check,
    ExternalLink,
    X,
  } from '@lucide/svelte';
  import type { Project, Snapshot, AuditRun, GetCapabilitiesResponse } from './gen/audit/v1/audit_pb';
  import { TargetKind, SnapshotState } from './gen/audit/v1/audit_pb';
  import {
    establishSession,
    projectsApi,
    runsApi,
    systemApi,
    requestId,
    errorMessage,
    artifactUrl,
  } from './lib/api';
  import {
    dateTime,
    bytes,
    kindLabel,
    snapshotLabel,
    runLabel,
    scopeLabel,
    tone,
    isTerminal,
  } from './lib/format';
  import ImportDialog from './components/ImportDialog.svelte';
  import AuditDialog from './components/AuditDialog.svelte';
  import RunView from './components/RunView.svelte';
  import ModelConnectionPanel from './components/ModelConnectionPanel.svelte';

  let projects = $state<Project[]>([]);
  let runs = $state<AuditRun[]>([]);
  let snapshots = $state<Snapshot[]>([]);
  let capabilities = $state<GetCapabilitiesResponse>();
  let projectId = $state(localStorage.getItem('aegis.project') || '');
  let page = $state('projects');
  let runId = $state('');
  let loading = $state(true);
  let connected = $state(false);
  let connectionError = $state('');
  let actionError = $state('');
  let toast = $state('');
  let showImport = $state(false);
  let auditSnapshot = $state<Snapshot>();
  let importProject = $state('');
  let creatingIds = $state<Record<string, boolean>>({});
  let refreshing: Promise<void> | undefined;
  let toastTimer: ReturnType<typeof setTimeout>;
  const project = $derived(projects.find((item) => item.id === projectId));
  const projectRuns = $derived(runs.filter((run) => run.projectId === projectId));
  const activeRuns = $derived(runs.filter((run) => !isTerminal(run.state)).length);
  const currentRun = $derived(runs.find((run) => run.id === runId));
  const currentRunProject = $derived(projects.find((project) => project.id === currentRun?.projectId));
  const availableTools = $derived([
    ...new Set(
      capabilities?.executors.flatMap((executor) =>
        executor.capabilities.filter((cap) => cap.available).map((cap) => cap.name),
      ) || [],
    ),
  ]);

  function route() {
    const parts = location.hash.replace(/^#\/?/, '').split('/');
    const nextPage = ['projects', 'runs', 'environment'].includes(parts[0]) ? parts[0] : 'projects';
    const nextRunId = nextPage === 'runs' ? parts[1] || '' : '';
    if (nextPage !== parts[0] || parts.length > 2) {
      history.replaceState(null, '', '#/projects');
      page = 'projects';
      runId = '';
    } else {
      page = nextPage;
      runId = nextRunId;
    }
    window.scrollTo({ top: 0 });
  }
  function notify(message: string) {
    toast = message;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      toast = '';
    }, 5000);
  }
  async function loadProject(id = projectId) {
    if (!id) {
      snapshots = [];
      return;
    }
    const response = await projectsApi.getProject({ projectId: id });
    if (id === projectId) snapshots = response.snapshots;
  }
  function refresh() {
    if (refreshing) return refreshing;
    refreshing = (async () => {
      try {
        const requestedProjectId = projectId;
        const [p, r, c] = await Promise.all([
          projectsApi.listProjects({}),
          runsApi.listRuns({}),
          systemApi.getCapabilities({}),
        ]);
        projects = p.projects;
        runs = r.runs;
        capabilities = c;
        connected = true;
        connectionError = '';
        if (!requestedProjectId && projects.length) {
          projectId = projects[0].id;
          localStorage.setItem('aegis.project', projectId);
          await loadProject(projectId);
        } else if (requestedProjectId && !projects.some((item) => item.id === requestedProjectId)) {
          snapshots = [];
        } else {
          await loadProject(requestedProjectId);
        }
      } catch (failure) {
        connected = false;
        connectionError = errorMessage(failure);
      } finally {
        loading = false;
      }
    })().finally(() => {
      refreshing = undefined;
    });
    return refreshing;
  }
  async function selectProject(id: string) {
    projectId = id;
    localStorage.setItem('aegis.project', id);
    snapshots = [];
    try {
      await loadProject();
    } catch (failure) {
      actionError = errorMessage(failure);
      notify(errorMessage(failure));
    }
  }
  function importTarget(id = '') {
    importProject = id;
    showImport = true;
  }
  $effect(() => {
    if (currentRun?.projectId && currentRun.projectId !== projectId) void selectProject(currentRun.projectId);
  });
  async function imported(id: string) {
    showImport = false;
    projectId = id;
    localStorage.setItem('aegis.project', id);
    location.hash = '/projects';
    await refresh();
    notify('快照已创建，执行器将检查并归档目标文件。');
  }
  async function analyze(snapshot: Snapshot, scope = 'STRUCTURE_ANALYSIS') {
    if (creatingIds[snapshot.id]) return;
    actionError = '';
    creatingIds = { ...creatingIds, [snapshot.id]: true };
    try {
      const response = await runsApi.createRun({ requestId: requestId(), snapshotId: snapshot.id, scope });
      actionError = '';
      location.hash = `/runs/${response.run!.id}`;
      await refresh();
    } catch (failure) {
      actionError = errorMessage(failure);
    } finally {
      const { [snapshot.id]: _finished, ...remaining } = creatingIds;
      creatingIds = remaining;
    }
  }
  onMount(() => {
    route();
    const start = async () => {
      try {
        await establishSession();
        await refresh();
      } catch (failure) {
        connectionError = errorMessage(failure);
        loading = false;
      }
    };
    void start();
    const poll = setInterval(() => {
      void refresh();
    }, 3000);
    window.addEventListener('hashchange', route);
    return () => {
      clearInterval(poll);
      clearTimeout(toastTimer);
      window.removeEventListener('hashchange', route);
    };
  });
</script>

<div class="app-shell">
  <aside class="sidebar">
    <a class="brand" href="#/projects" aria-label="AegisAudit 首页"
      ><div class="brand-mark"><Shield size={25} strokeWidth={1.5} /><span>A</span></div>
      <div><strong>Aegis<span>Audit</span></strong><small>程序分析工作台</small></div></a
    >
    <div class="workspace-label">
      <span class="dot mint"></span>本地工作区 <span class="single-user">单人</span>
    </div>
    <div class="nav-label">工作台</div>
    <nav aria-label="主导航">
      <a href="#/projects" class:active={page === 'projects'}
        ><FolderKanban size={18} />项目与快照<span class="nav-count">{projects.length}</span></a
      >
      <a href="#/runs" class:active={page === 'runs'}
        ><Activity size={18} />分析任务{#if activeRuns}<span class="nav-count">{activeRuns}</span>{/if}</a
      >
      <a href="#/environment" class:active={page === 'environment'}><Server size={18} />执行环境</a>
    </nav>
    <div class="sidebar-scope">
      <span class="nav-label">当前阶段</span>
      <div><Layers size={17} />程序理解与漏洞审计</div>
      <p>把代码、函数与证据<br />放回同一个上下文。</p>
      <span class="version">MILESTONE 02 <span>/</span> v{capabilities?.version || '0.1.0'}</span>
    </div>
    <div class="sidebar-bottom">
      <a href="https://github.com/moonlit111/aegis-audit" target="_blank" rel="noreferrer"
        ><GitBranch size={16} />项目仓库<ExternalLink size={13} /></a
      >
      <div><i class="dot" class:mint={connected}></i>{connected ? '控制服务已连接' : '等待控制服务'}</div>
    </div>
  </aside>

  <div class="main-shell">
    <header class="topbar">
      <div class="breadcrumb">
        本地工作区<ChevronRight size={14} /><span
          >{page === 'projects' ? '项目与快照' : page === 'runs' ? '分析任务' : '执行环境'}</span
        >
      </div>
      <div class="topbar-right">
        <span class="live-indicator"
          ><i class="dot" class:green={connected}></i>{capabilities?.executors.length || 0} 个执行器在线</span
        ><button class="icon-button" title="刷新数据" aria-label="刷新数据" onclick={refresh}
          ><RefreshCw size={16} /></button
        >
      </div>
    </header>
    <main class:run-page={page === 'runs' && runId}>
      {#if connectionError}<div class="error-banner global-error" role="alert">
          <span>{connectionError}</span><button
            class="text-button"
            onclick={async () => {
              try {
                await establishSession();
                await refresh();
              } catch (failure) {
                connectionError = errorMessage(failure);
              }
            }}>重新连接</button
          >
        </div>{/if}
      {#if actionError}<div class="error-banner global-error" role="alert">
          <span>{actionError}</span><button
            class="text-button"
            onclick={() => {
              actionError = '';
            }}>关闭</button
          >
        </div>{/if}
      {#if page === 'projects'}
        <div class="page-heading">
          <div>
            <div class="eyebrow">PROJECT WORKSPACE</div>
            <h1>让程序结构清晰可见<span class="heading-dot">.</span></h1>
            <p>从一个不可变快照开始，追踪每次分析的代码、位置与原始产物。</p>
          </div>
          <button class="button primary" onclick={() => importTarget()} disabled={!connected}
            ><Plus size={17} />新建项目</button
          >
        </div>
        <div class="metric-grid">
          <div class="metric">
            <span>分析项目<FolderKanban size={17} /></span><strong
              >{projects.length.toString().padStart(2, '0')}</strong
            ><small>本地持久化保存</small>
          </div>
          <div class="metric">
            <span>分析任务<Activity size={17} /></span><strong
              >{runs.length.toString().padStart(2, '0')}</strong
            ><small>{activeRuns} 项正在等待或执行</small>
          </div>
          <div class="metric">
            <span>已索引程序单元<FileCode2 size={17} /></span><strong
              >{runs.reduce((total, run) => total + Number(run.unitCount), 0).toLocaleString()}</strong
            ><small>模块与函数，按任务累计</small>
          </div>
          <div class="metric scope-metric">
            <span>当前能力边界<CircleHelp size={17} /></span><strong>静态审计</strong><small
              >源码 / 反编译 · 独立复核 · 证据</small
            >
          </div>
        </div>
        {#if loading}<div class="empty-panel">正在读取工作区…</div>
        {:else if !projects.length}
          <section class="welcome-panel">
            <div class="welcome-symbol"><FileCode2 size={42} strokeWidth={1} /></div>
            <div class="eyebrow">YOUR FIRST SNAPSHOT</div>
            <h2>带入代码，开始理解程序</h2>
            <p>导入源码、Git 仓库或 PE / ELF 二进制。<br />系统将保留快照并建立可追溯的结构索引。</p>
            <button class="button primary" onclick={() => importTarget()} disabled={!connected}
              >导入第一个目标<ArrowRight size={16} /></button
            >
            <div class="workflow">
              <div><b>01</b><strong>固定目标</strong><span>文件哈希 · 精确版本</span></div>
              <div><b>02</b><strong>解析结构</strong><span>函数 · 代码 · 调用关系</span></div>
              <div><b>03</b><strong>检查依据</strong><span>覆盖范围 · 日志 · 报告</span></div>
            </div>
          </section>
        {:else}
          <div class="workspace-grid">
            <section class="panel project-list">
              <div class="panel-title">
                <h2>项目</h2>
                <span>{projects.length}</span>
              </div>
              {#each projects as item}<button
                  class="project-row"
                  class:selected={item.id === projectId}
                  onclick={() => selectProject(item.id)}
                  ><span class="project-icon"><FolderKanban size={19} /></span><span
                    ><strong>{item.name}</strong><small>{dateTime(item.createdAt)} 创建</small></span
                  ><ChevronRight size={15} /></button
                >{/each}
            </section>
            <section class="panel snapshot-panel">
              <div class="panel-title">
                <div>
                  <h2>{project?.name || '选择项目'}</h2>
                  <span class="subtle">{snapshots.length} 个快照 · {projectRuns.length} 次分析</span>
                </div>
                <button class="button secondary small" onclick={() => importTarget(projectId)}
                  ><Plus size={15} />导入快照</button
                >
              </div>
              {#if !snapshots.length}<div class="empty-panel compact">
                  <Layers size={30} strokeWidth={1.2} />
                  <h3>项目还没有快照</h3>
                  <p>导入一个目标来建立可分析的版本。</p>
                </div>{/if}
              <div class="snapshot-list">
                {#each snapshots as snapshot}<article class="snapshot-card">
                    <div class="snapshot-card-top">
                      <span class="file-icon"
                        >{#if snapshot.kind === TargetKind.BINARY}<Binary
                            size={21}
                          />{:else if snapshot.kind === TargetKind.GIT}<GitBranch
                            size={21}
                          />{:else}<FileCode2 size={21} />{/if}</span
                      >
                      <div class="snapshot-name">
                        <h3 title={snapshot.name}>{snapshot.name}</h3>
                        <span>{kindLabel(snapshot.kind)} <i>·</i> {dateTime(snapshot.createdAt)}</span>
                      </div>
                      <span
                        class="badge"
                        class:success={snapshot.state === SnapshotState.READY}
                        class:danger={snapshot.state === SnapshotState.FAILED}
                        class:neutral={snapshot.state === SnapshotState.IMPORTING}
                        >{snapshotLabel(snapshot.state)}</span
                      >
                    </div>
                    {#if snapshot.error}<p class="inline-error">
                        {snapshot.error}
                      </p>{:else if snapshot.state === SnapshotState.IMPORTING}<div class="snapshot-pending">
                        <span class="pulse-dot"></span>等待执行器完成文件检查与归档…
                      </div>{:else}<div class="snapshot-facts">
                        <span>{Number(snapshot.fileCount)} 个文件</span><span
                          >{bytes(snapshot.totalBytes)}</span
                        ><code title={snapshot.targetSha256}
                          >SHA256 {snapshot.targetSha256.slice(0, 12)}…</code
                        >
                      </div>{/if}
                    {#if snapshot.resolvedRevision}<div class="revision">
                        <GitBranch size={13} />{snapshot.resolvedRevision}
                      </div>{/if}
                    <div class="snapshot-actions">
                      {#if snapshot.manifestArtifactId}<a
                          class="text-button"
                          href={artifactUrl(snapshot.manifestArtifactId)}
                          >快照清单<ArrowUpRight size={13} /></a
                        >{:else}<span></span>{/if}<button
                        class="button secondary small"
                        disabled={creatingIds[snapshot.id] ||
                          !connected ||
                          ![SnapshotState.READY, SnapshotState.PARTIAL].includes(snapshot.state) ||
                          !availableTools.includes(
                            snapshot.kind === TargetKind.BINARY ? 'ghidra' : 'tree-sitter',
                          )}
                        onclick={() => analyze(snapshot)}
                        >{creatingIds[snapshot.id]
                          ? '正在创建…'
                          : snapshot.kind === TargetKind.BINARY
                            ? '开始反编译'
                            : '开始结构分析'}<ArrowRight size={14} /></button
                      >
                      <button
                        class="button primary small"
                        disabled={creatingIds[snapshot.id] ||
                          ![SnapshotState.READY, SnapshotState.PARTIAL].includes(snapshot.state) ||
                          !capabilities?.modelConnection?.configured ||
                          !availableTools.includes(
                            snapshot.kind === TargetKind.BINARY ? 'import' : 'tree-sitter',
                          )}
                        title={capabilities?.modelConnection?.configured
                          ? '解析代码后进行语义审计与独立复核'
                          : '请先在执行环境配置模型连接'}
                        onclick={() => {
                          auditSnapshot = snapshot;
                        }}>开始漏洞审计<ArrowRight size={14} /></button
                      >
                      {#if !capabilities?.modelConnection?.configured}<a
                          class="text-button"
                          href="#/environment">先配置模型连接</a
                        >{:else if !availableTools.includes(snapshot.kind === TargetKind.BINARY ? 'ghidra' : 'tree-sitter') || !availableTools.includes(snapshot.kind === TargetKind.BINARY ? 'import' : 'tree-sitter')}<a
                          class="text-button"
                          href="#/environment">先启动所需执行器</a
                        >{/if}
                    </div>
                  </article>{/each}
              </div>
            </section>
          </div>
        {/if}
        <div class="footnote"><Shield size={14} />解析成功表示已建立程序结构，不能据此判定目标安全。</div>
      {:else if page === 'runs' && runId}
        {#key runId}<RunView
            {runId}
            onchanged={refresh}
            {notify}
            projectName={currentRunProject?.name}
          />{/key}
      {:else if page === 'runs'}
        <div class="page-heading">
          <div>
            <div class="eyebrow">ANALYSIS HISTORY</div>
            <h1>每一次分析，都有据可查<span class="heading-dot">.</span></h1>
            <p>任务独立于浏览器运行；重新打开页面可以继续查看。</p>
          </div>
          <a class="button secondary" href="#/projects">选择分析目标<ArrowRight size={16} /></a>
        </div>
        <section class="panel">
          <div class="panel-title">
            <h2>分析任务</h2>
            <span>{runs.length} 项</span>
          </div>
          {#if !runs.length}<div class="empty-panel">
              <Activity size={32} strokeWidth={1.2} />
              <h3>还没有分析任务</h3>
              <p>从项目快照开始结构分析、反编译或漏洞审计。</p>
            </div>{:else}<div class="table-scroll">
              <table class="task-table">
                <thead
                  ><tr><th>项目 / 任务</th><th>状态</th><th>程序单元</th><th>创建时间</th><th></th></tr
                  ></thead
                ><tbody
                  >{#each runs as run}<tr
                      ><td
                        ><a class="task-name" href={`#/runs/${run.id}`}
                          >{projects.find((item) => item.id === run.projectId)?.name || '分析任务'}<small
                            >{run.id.slice(0, 8)} · {scopeLabel(run.scope)}</small
                          ></a
                        ></td
                      ><td><span class={`badge ${tone(run.state)}`}>{runLabel(run.state)}</span></td><td
                        class="mono">{run.unitCount.toString()}</td
                      ><td>{dateTime(run.createdAt)}</td><td
                        ><a
                          class="icon-button"
                          href={`#/runs/${run.id}`}
                          aria-label={`查看任务 ${run.id.slice(0, 8)}`}><ArrowUpRight size={17} /></a
                        ></td
                      ></tr
                    >{/each}</tbody
                >
              </table>
            </div>{/if}
        </section>
      {:else if page === 'environment'}
        <div class="page-heading">
          <div>
            <div class="eyebrow">EXECUTION ENVIRONMENT</div>
            <h1>工具能力，来自实际环境<span class="heading-dot">.</span></h1>
            <p>执行器启动时检查工具与平台；任务按所需能力进入队列。</p>
          </div>
          <span class="badge neutral"><Cpu size={13} />{availableTools.length} 项可用能力</span>
        </div>
        <ModelConnectionPanel connection={capabilities?.modelConnection} onchanged={refresh} />
        {#each capabilities?.executors || [] as executor}<section class="panel environment-panel">
            <div class="panel-title">
              <div class="executor-title">
                <span class="icon-tile"><Server size={21} /></span>
                <div>
                  <h2>{executor.name}</h2>
                  <span class="subtle"
                    >{executor.platform} / {executor.architecture} · 最后在线 {dateTime(
                      executor.lastSeen,
                    )}</span
                  >
                </div>
              </div>
              <span class="badge success"><i class="dot green"></i>在线</span>
            </div>
            <div class="capability-list">
              {#each executor.capabilities as cap}<div class="capability-row">
                  <div class:available={cap.available} class="capability-icon">
                    {#if cap.available}<Check size={18} />{:else}<CircleHelp size={18} />{/if}
                  </div>
                  <div>
                    <h3>{cap.name}<code>{cap.version || '未检测到'}</code></h3>
                    <p>{cap.detail}</p>
                  </div>
                  <span class={`badge ${cap.available ? 'success' : 'warning'}`}
                    >{cap.available ? '可用' : '不可用'}</span
                  >
                </div>{/each}
            </div>
          </section>{/each}
        {#if !capabilities?.executors.length}<section class="panel empty-panel">
            <Server size={32} strokeWidth={1.2} />
            <h2>还没有在线执行器</h2>
            <p>按运行文档启动执行器，等待中的任务会自动领取。</p>
            <code>py -3 scripts/manage.py start</code>
          </section>{/if}
        <section class="scope-panel">
          <div class="eyebrow">CAPABILITY BOUNDARY</div>
          <h2>能力边界</h2>
          <p>以下能力仍有限制或尚未通过正式验收，报告会保留实际执行状态。</p>
          <div class="pending-features">
            {#each capabilities?.pendingFeatures || [] as feature}<span
                ><span class="dot"></span>{feature}</span
              >{/each}
          </div>
        </section>
      {/if}
    </main>
  </div>
</div>
{#if showImport}<ImportDialog
    {projects}
    initialProjectId={importProject}
    onclose={() => {
      showImport = false;
    }}
    onimported={imported}
  />{/if}
{#if auditSnapshot}<AuditDialog
    snapshot={auditSnapshot}
    onclose={() => {
      auditSnapshot = undefined;
    }}
    oncreated={(id) => {
      auditSnapshot = undefined;
      location.hash = `/runs/${id}`;
      void refresh();
    }}
  />{/if}
{#if toast}<div class="toast" role="status">
    <Check size={17} /><span>{toast}</span><button
      class="icon-button"
      aria-label="关闭提示"
      onclick={() => {
        toast = '';
      }}><X size={15} /></button
    >
  </div>{/if}
