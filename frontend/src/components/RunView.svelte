<script lang="ts">
  import { onMount, tick, untrack } from 'svelte';
  import { Code, ConnectError } from '@connectrpc/connect';
  import {
    ArrowLeft,
    ArrowRight,
    Download,
    CircleStop,
    CheckCircle2,
    LoaderCircle,
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
    Hash,
    FlaskConical,
  } from '@lucide/svelte';
  import type {
    AuditRun,
    Snapshot,
    ProgramUnit,
    ProgramEdge,
    Artifact,
    RunEvent,
    RunPhase,
    GetAuditResponse,
    RuntimeRecord,
  } from '../gen/audit/v1/audit_pb';
  import { RunState } from '../gen/audit/v1/audit_pb';
  import {
    runsApi,
    projectsApi,
    programsApi,
    findingsApi,
    runtimeApi,
    artifactUrl,
    errorMessage,
  } from '../lib/api';
  import {
    mergeRuntimeRecords,
    runtimeFeedback,
    runtimePending,
    verificationPlans,
    supportsFuzz,
    readVerificationPlan,
    type RuntimeMode,
    type RuntimeResult,
  } from '../lib/runtime';
  import {
    isTerminal,
    runLabel,
    scopeLabel,
    tone,
    parseJson,
    dateTime,
    type Summary,
    type UnitMetadata,
  } from '../lib/format';
  import CodeViewer from './CodeViewer.svelte';
  import CallGraph from './CallGraph.svelte';
  import AuditPanel from './AuditPanel.svelte';
  import RuntimePanel from './RuntimePanel.svelte';
  import RuntimeResults from './RuntimeResults.svelte';
  import RecoveryPanel from './RecoveryPanel.svelte';
  import RunProgress from './RunProgress.svelte';
  import RunEvents from './RunEvents.svelte';
  import CoveragePanel from './CoveragePanel.svelte';
  import AnnotationsPanel from './AnnotationsPanel.svelte';
  import ReportHistory from './ReportHistory.svelte';
  import ReportExport from './ReportExport.svelte';
  import CancelRunDialog from './CancelRunDialog.svelte';

  let {
    runId,
    initialView = '',
    onchanged,
    notify,
    projectName = '',
  }: {
    runId: string;
    initialView?: string;
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
  let initialTabSelected = false;
  let runtimeFinding = $state('');
  let runtimeMode = $state<RuntimeMode>('VERIFY');
  let runtimePreset = $state<RuntimeRecord>();
  let runtimeAudit = $state<GetAuditResponse>();
  let runtimeRecords = $state<RuntimeRecord[]>([]);
  let runtimeRefreshing = $state(false);
  let runtimeLoadError = $state('');
  let runtimeFocusId = $state('');
  let runtimeFocusVersion = $state(0);
  let runtimePanelElement = $state<HTMLDivElement>();
  let manualRuntimeOpen = $state(false);
  let runtimeReadState: RunState | undefined;
  let loadingAudit: Promise<GetAuditResponse> | undefined;
  let loadingRuntime: Promise<void> | undefined;
  let viewer = $state('code');
  let events = $state<RunEvent[]>([]);
  let phases = $state<RunPhase[]>([]);
  let streamStatus = $state('连接中');
  let error = $state('');
  let notFound = $state(false);
  let loadingUnits = $state(false);
  let selectedId = $state('');
  let reportVersion = $state(0);
  let cancelBusy = $state(false);
  let cancelDialogOpen = $state(false);
  let cancelAttempted = $state(false);
  let cancelError = $state('');
  let cursor = $state(0n);
  let alive = true;
  let loadingRun: Promise<void> | undefined;
  let unitQueryGeneration = 0;
  let searchTimer: ReturnType<typeof setTimeout>;
  const controller = new AbortController();
  const summary = $derived(parseJson<Summary>(run?.summaryJson || '', {}));
  const metadata = $derived(parseJson<UnitMetadata>(unit?.metadataJson || '', {}));
  const files = $derived(summary.files || []);
  const gaps = $derived(files.filter((file) => !['PARSED', 'NOT_SOURCE'].includes(file.status)));
  const isRuntimeRun = $derived(['RUNTIME_VERIFICATION', 'DYNAMIC_TESTING'].includes(run?.scope || ''));
  const canFuzz = $derived(
    ['STRUCTURE_ANALYSIS', 'SECURITY_AUDIT'].includes(run?.scope || '') && supportsFuzz(snapshot),
  );
  const plans = $derived(verificationPlans(runtimeAudit?.tasks));
  $effect(() => {
    if (initialView === 'fuzz' && canFuzz) untrack(() => void openRuntimePlans('', 'FUZZ'));
  });
  const runtimeTabVisible = $derived(plans.length > 0 || manualRuntimeOpen);
  const canConfigureRuntime = $derived(
    !isRuntimeRun &&
      (canFuzz ||
        plans.length > 0 ||
        runtimeRecords.length > 0 ||
        (run?.scope === 'STRUCTURE_ANALYSIS' && isTerminal(run.state) && run.unitCount > 0n)),
  );
  const visiblePhases = $derived(
    phases.map((phase) => {
      if (phase.id === 'VERIFICATION_PLAN' && plans.length)
        return {
          ...phase,
          detail: `已生成 ${plans.length} 份方案；${runtimeRecords.length ? '实际验证结论见“覆盖与产物”。' : '尚未启动运行验证。'}`,
        };
      if (phase.id === 'RUNTIME') {
        const record = runtimeRecords.find((record) => record.runId === runId);
        return {
          ...phase,
          title: run?.scope === 'DYNAMIC_TESTING' ? '动态模糊测试' : '运行验证',
          detail: record
            ? runtimeFeedback(record, parseJson<RuntimeResult | null>(record.resultJson, null)).title
            : phase.detail,
        };
      }
      return phase;
    }),
  );
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
  const cancellation = $derived.by(() => {
    if (run?.state === RunState.CANCELLED)
      return {
        tone: 'complete',
        title: '任务已取消',
        detail: '执行已停止，已完成的分析结果和证据仍可查看、导出。',
      };
    if (run?.state === RunState.CANCELLING)
      return {
        tone: 'pending',
        title: '正在取消任务',
        detail: '取消请求已记录，正在停止当前执行。确认停止后会自动更新状态，已完成的结果会保留。',
      };
    if (run && isTerminal(run.state) && cancelAttempted)
      return {
        tone: 'complete',
        title: `任务已结束 · ${runLabel(run.state)}`,
        detail: '请以当前任务状态为准，已有结果仍可查看、导出。',
      };
    if (cancelBusy)
      return {
        tone: 'pending',
        title: '正在提交取消请求',
        detail: '正在联系控制服务，请稍候。',
      };
    if (cancelError)
      return {
        tone: 'error',
        title: '取消请求未确认',
        detail: `${cancelError}。可重试取消，或刷新任务状态。`,
      };
    return undefined;
  });

  function acceptRun(next: AuditRun | undefined) {
    if (!next) return false;
    // A poll started before cancellation must not undo an acknowledged stop or terminal state.
    if (run && isTerminal(run.state) && next.state !== run.state) return false;
    if (run?.state === RunState.CANCELLING && !isTerminal(next.state) && next.state !== RunState.CANCELLING)
      return false;
    run = next;
    return true;
  }

  function acceptRuntime(records: RuntimeRecord[]) {
    const completed = records.some(
      (record) =>
        !runtimePending(record.status) &&
        runtimeRecords.find((previous) => previous.id === record.id)?.status !== record.status,
    );
    runtimeRecords = mergeRuntimeRecords(runtimeRecords, records);
    if (completed) void loadRun();
  }

  // AuditPanel and runtime views share this request and snapshot. Plans can be
  // discovered while their tab is hidden, and a completed audit keeps polling
  // its independently running verification tasks.
  function loadAudit() {
    if (loadingAudit) return loadingAudit;
    const readState = run?.state;
    runtimeRefreshing = true;
    loadingAudit = findingsApi
      .getAudit({ runId }, { signal: controller.signal })
      .then((response) => {
        if (alive) {
          runtimeAudit = response;
          acceptRuntime(response.runtime);
          runtimeReadState = readState;
          runtimeLoadError = '';
        }
        return response;
      })
      .catch((failure) => {
        if (alive) runtimeLoadError = errorMessage(failure);
        throw failure;
      })
      .finally(() => {
        loadingAudit = undefined;
        runtimeRefreshing = false;
      });
    return loadingAudit;
  }

  function refreshRuntime() {
    if (loadingRuntime) return loadingRuntime;
    loadingRuntime = (async () => {
      try {
        if (run?.scope === 'SECURITY_AUDIT') await loadAudit();
        else {
          const readState = run?.state;
          runtimeRefreshing = true;
          const response = await runtimeApi.listRuntime({ runId }, { signal: controller.signal });
          if (alive) {
            acceptRuntime(response.records);
            runtimeReadState = readState;
            runtimeLoadError = '';
          }
        }
      } catch (failure) {
        if (alive) runtimeLoadError = errorMessage(failure);
      }
    })().finally(() => {
      loadingRuntime = undefined;
      runtimeRefreshing = false;
    });
    return loadingRuntime;
  }

  async function openRuntimePlans(findingId = '', mode?: RuntimeMode, preset?: RuntimeRecord) {
    runtimeFinding = findingId;
    const plan = findingId ? plans.find((task) => task.itemKey === findingId) : plans[0];
    runtimeMode = mode || (plan && readVerificationPlan(plan).config?.mode === 'FUZZ' ? 'FUZZ' : 'VERIFY');
    if (preset) runtimePreset = { ...preset };
    manualRuntimeOpen = true;
    tab = 'runtime';
    await tick();
    runtimePanelElement?.scrollIntoView({ block: 'start' });
    runtimePanelElement?.focus({ preventScroll: true });
  }

  function openRuntimeResults(recordId = '', findingId = '') {
    runtimeFocusId =
      recordId ||
      [...runtimeRecords].reverse().find((record) => !findingId || record.findingId === findingId)?.id ||
      '';
    runtimeFocusVersion += 1;
    tab = 'coverage';
  }

  function runtimeStarted(record: RuntimeRecord) {
    acceptRuntime([record]);
    openRuntimeResults(record.id);
    void refreshRuntime();
    void loadRun();
    void onchanged();
  }

  function loadRun() {
    if (loadingRun) return loadingRun;
    loadingRun = (async () => {
      try {
        const response = await runsApi.getRun({ runId }, { signal: controller.signal });
        if (!alive) return;
        const previousCount = run?.unitCount;
        const previousResult = parseJson<Summary>(run?.summaryJson || '', {}).result_artifact_id;
        if (!acceptRun(response.run)) return;
        if (run && !initialTabSelected) {
          tab =
            run.scope === 'SECURITY_AUDIT'
              ? 'audit'
              : ['RUNTIME_VERIFICATION', 'DYNAMIC_TESTING'].includes(run.scope)
                ? 'coverage'
                : 'program';
          initialTabSelected = true;
        }
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
        // timeoutMs: 0 disables the transport's 15s default deadline. WatchRun is
        // a long-lived stream that the server only ends when the run is terminal,
        // so the default deadline would abort it every 15s and surface as a
        // permanent "connection interrupted, reconnecting" while an audit runs.
        for await (const message of runsApi.watchRun(
          { runId, afterSeq: cursor },
          { signal: controller.signal, timeoutMs: 0 },
        )) {
          if (!alive) return;
          streamStatus = '实时连接';
          if (message.event && message.event.seq > cursor) {
            cursor = message.event.seq;
            events = [message.event, ...events].slice(0, 500);
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
    if (cancelBusy || !run || isTerminal(run.state) || run.state === RunState.CANCELLING) return;
    cancelDialogOpen = false;
    cancelAttempted = true;
    cancelBusy = true;
    cancelError = '';
    try {
      const response = await runsApi.cancelRun({ runId }, { signal: controller.signal });
      if (!alive) return;
      if (!response.run) throw new Error('控制服务未返回任务状态');
      acceptRun(response.run);
      void loadRun();
      void onchanged();
    } catch (failure) {
      if (alive) cancelError = errorMessage(failure);
    } finally {
      cancelBusy = false;
    }
  }
  onMount(() => {
    void loadRun();
    void watch();
    const poll = setInterval(() => {
      if (!notFound && (!run || !isTerminal(run.state))) void loadRun();
      if (
        run &&
        (run.scope !== 'SECURITY_AUDIT' || tab !== 'audit') &&
        (!isTerminal(run.state) ||
          runtimeReadState !== run.state ||
          runtimeLoadError ||
          runtimeRecords.some((record) => runtimePending(record.status)))
      )
        void refreshRuntime();
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
  $effect(() => {
    const state = run?.state;
    if (state !== undefined)
      untrack(() => {
        if (tab !== 'audit' || isTerminal(state)) void refreshRuntime();
      });
  });
  $effect(() => {
    if (tab === 'runtime' || tab === 'coverage') void refreshRuntime();
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
  <a href="#/runs" class="back-link run-back-link"><ArrowLeft size={14} />全部分析任务</a>
  <div class="run-heading">
    <div class="run-identity">
      <div class="run-title-line">
        <h1 title={snapshot?.name}>{snapshot?.name || '程序结构分析'}</h1>
        <span class="run-scope">{scopeLabel(run?.scope || '')}</span>
      </div>
      <dl class="run-meta" aria-label="任务信息">
        <div>
          <dt>任务</dt>
          <dd><code title={runId}>{runId.slice(0, 8)}</code></dd>
        </div>
        <div>
          <dt>创建于</dt>
          <dd><time datetime={run?.createdAt || undefined}>{dateTime(run?.createdAt || '')}</time></dd>
        </div>
        <div class="run-meta-project">
          <dt>项目</dt>
          <dd title={projectName || '固定快照分析'}>{projectName || '固定快照分析'}</dd>
        </div>
      </dl>
      {#if run && !isTerminal(run.state)}
        <div class="run-control">
          <button
            class="button cancel-run-button"
            disabled={cancelBusy || run.state === RunState.CANCELLING}
            aria-haspopup="dialog"
            onclick={() => (cancelDialogOpen = true)}
          >
            {#if cancelBusy || run.state === RunState.CANCELLING}<LoaderCircle size={16} class="spin" />
            {:else}<CircleStop size={16} />{/if}
            {run.state === RunState.CANCELLING ? '正在取消…' : cancelBusy ? '提交取消中…' : '取消任务'}
          </button>
          <span>取消后保留已有结果</span>
        </div>
      {/if}
    </div>
    <ReportExport
      {run}
      snapshotName={snapshot?.name || runId.slice(0, 8)}
      oncreated={() => {
        reportVersion += 1;
        void loadRun();
      }}
      onhistory={() => (tab = 'reports')}
    />
  </div>
  {#if cancellation}
    <div
      class={`cancel-feedback ${cancellation.tone}`}
      role={cancellation.tone === 'error' ? 'alert' : 'status'}
    >
      {#if cancellation.tone === 'pending'}<LoaderCircle size={20} class="spin" />
      {:else if cancellation.tone === 'error'}<AlertCircle size={20} />
      {:else}<CheckCircle2 size={20} />{/if}
      <div>
        <strong>{cancellation.title}</strong>
        <p>{cancellation.detail}</p>
      </div>
      {#if cancellation.tone === 'error'}
        <div class="cancel-feedback-actions">
          <button class="button cancel-run-button small" onclick={cancel}>重试取消</button>
          <button class="text-button" onclick={() => void loadRun()}>刷新状态</button>
        </div>
      {/if}
    </div>
  {/if}
  {#if cancelDialogOpen && run}
    <CancelRunDialog
      {run}
      snapshotName={snapshot?.name || runId.slice(0, 8)}
      onclose={() => (cancelDialogOpen = false)}
      onconfirm={cancel}
    />
  {/if}
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
    {#if summary.analysis_reuse}<p class="footnote">
        已复用此快照的反编译结果（Ghidra {summary.analysis_reuse.tool_version}）。
        <a class="text-button" href={`#/runs/${summary.analysis_reuse.source_run_id}`}>查看来源任务</a>
      </p>{/if}
    <RunProgress
      phases={visiblePhases}
      runState={run.state}
      {statusMessage}
      showEnvironmentLink={!isTerminal(run.state)}
      canSelect={(phase) =>
        (phase.id !== 'RECOVERY' || Boolean(summary.recovery)) &&
        (phase.id !== 'RUNTIME' || runtimeRecords.length > 0 || plans.length > 0 || isRuntimeRun)}
      onselect={(phase) => {
        if (phase.unitId) {
          tab = 'program';
          void selectUnit(phase.unitId);
        } else if (phase.id === 'RECOVERY') tab = 'recovery';
        else if (phase.id === 'RUNTIME') {
          if (runtimeRecords.length || isRuntimeRun) openRuntimeResults();
          else void openRuntimePlans();
        } else if (phase.id === 'VERIFICATION_PLAN') {
          if (plans.length) void openRuntimePlans();
          else tab = 'audit';
        } else if (phase.id === 'STRUCTURE') tab = 'program';
        else if (phase.id === 'PREPARATION') tab = 'events';
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
      {#if runtimeTabVisible}<button
          role="tab"
          aria-selected={tab === 'runtime' && runtimeMode === 'VERIFY'}
          class:active={tab === 'runtime' && runtimeMode === 'VERIFY'}
          onclick={() => void openRuntimePlans('', 'VERIFY')}><ListChecks size={16} />运行验证</button
        >{/if}
      {#if canFuzz}<button
          role="tab"
          aria-selected={tab === 'runtime' && runtimeMode === 'FUZZ'}
          class:active={tab === 'runtime' && runtimeMode === 'FUZZ'}
          onclick={() => void openRuntimePlans('', 'FUZZ')}><FlaskConical size={16} />动态模糊测试</button
        >{/if}
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
    {#if runtimeTabVisible}<div
        class:hidden-panel={tab !== 'runtime'}
        bind:this={runtimePanelElement}
        tabindex="-1"
        style:scroll-margin-top="80px"
      >
        <RuntimePanel
          {run}
          {snapshot}
          {unit}
          bind:mode={runtimeMode}
          preset={runtimePreset}
          {notify}
          audit={runtimeAudit}
          records={runtimeRecords}
          refreshing={runtimeRefreshing}
          loadError={runtimeLoadError}
          onrefresh={refreshRuntime}
          onstarted={runtimeStarted}
          onshowresults={openRuntimeResults}
          findingId={runtimeFinding}
        />
      </div>{/if}
    {#if run.scope === 'SECURITY_AUDIT'}<div class:hidden-panel={tab !== 'audit'}>
        <AuditPanel
          {run}
          {notify}
          {loadAudit}
          {runtimeRecords}
          knownUnits={units}
          active={tab === 'audit'}
          onverify={(id) => void openRuntimePlans(id)}
          onfuzz={canFuzz ? (id) => void openRuntimePlans(id, 'FUZZ') : undefined}
          onresults={(id) => openRuntimeResults('', id)}
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
      <CoveragePanel {summary} {artifacts}>
        {#snippet verification()}
          {#if runtimeRecords.length || plans.length || isRuntimeRun}
            <RuntimeResults
              {runId}
              records={runtimeRecords}
              findings={runtimeAudit?.findings}
              focusId={runtimeFocusId}
              focusVersion={runtimeFocusVersion}
              refreshing={runtimeRefreshing}
              loadError={runtimeLoadError}
              hasPlans={plans.length > 0}
              onrefresh={refreshRuntime}
              onconfigure={canConfigureRuntime
                ? (mode, record) => void openRuntimePlans(record?.findingId || '', mode, record)
                : undefined}
              onupdate={(record) => acceptRuntime([record])}
              onevents={() => (tab = 'events')}
              {notify}
            />
          {:else if canConfigureRuntime}
            <div>
              <button class="button secondary" onclick={() => void openRuntimePlans()}
                >配置本地测试<ArrowUpRight size={14} /></button
              >
            </div>
          {/if}
        {/snippet}
      </CoveragePanel>
    {:else if tab === 'events'}
      <RunEvents {events} {phases} {streamStatus} runState={run.state} />
    {/if}
  {:else if !error}<div class="empty-panel">
      <RefreshCw class="spin" size={24} />
      <p>正在读取分析任务…</p>
    </div>{/if}
{/if}
