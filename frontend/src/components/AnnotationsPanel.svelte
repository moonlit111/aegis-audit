<script lang="ts">
  import { onMount } from 'svelte';
  import { Plus, Save, RefreshCw } from '@lucide/svelte';
  import type { AuditRun, LogicAnnotation, ProgramUnit } from '../gen/audit/v1/audit_pb';
  import { programsApi, requestId, errorMessage } from '../lib/api';
  import { isTerminal } from '../lib/format';
  let {
    run,
    onselectunit,
    notify,
    onchanged = () => {},
  }: {
    run: AuditRun;
    onselectunit: (id: string) => void;
    notify: (message: string) => void;
    onchanged?: () => void;
  } = $props();
  const tags: Record<string, string> = {
    AUTHENTICATION: '认证',
    CRYPTOGRAPHY: '加解密',
    REGISTRATION: '注册',
  };
  let annotations = $state<LogicAnnotation[]>([]);
  let units = $state<ProgramUnit[]>([]);
  let unit = $state<ProgramUnit>();
  let unitId = $state('');
  let query = $state('');
  let creating = $state(false);
  let tag = $state('AUTHENTICATION');
  let rationale = $state('');
  let startLine = $state(1);
  let endLine = $state(1);
  let error = $state('');
  let busy = $state(false);
  let editing = $state('');
  let editRevision = $state(0);
  let editTag = $state('');
  let editText = $state('');
  let loading = false;
  let refreshAgain = false;
  let generation = 0;
  let searchTimer: ReturnType<typeof setTimeout>;
  const controller = new AbortController();
  const base = $derived(unit?.language === 'binary' ? 1 : unit?.startLine || 1);
  const last = $derived(base + (unit?.code.split('\n').length || 1) - 1);
  const excerpt = $derived(
    unit && startLine >= base && endLine <= last && endLine >= startLine
      ? unit.code
          .split('\n')
          .slice(startLine - base, endLine - base + 1)
          .map((line, index) => `${startLine + index}  ${line}`)
          .join('\n')
      : '',
  );
  async function refresh() {
    if (loading) {
      refreshAgain = true;
      return;
    }
    loading = true;
    try {
      const response = await programsApi.listAnnotations({ runId: run.id }, { signal: controller.signal });
      if (!controller.signal.aborted) annotations = response.annotations;
    } catch (failure) {
      if (!controller.signal.aborted) error = errorMessage(failure);
    } finally {
      loading = false;
      if (refreshAgain && !controller.signal.aborted) {
        refreshAgain = false;
        void refresh();
      }
    }
  }
  async function searchUnits() {
    const request = ++generation;
    try {
      const result = await programsApi.listUnits(
        { runId: run.id, query, limit: 80 },
        { signal: controller.signal },
      );
      if (request !== generation || controller.signal.aborted) return;
      units = result.units;
      if (!units.some((u) => u.id === unitId)) {
        unitId = units[0]?.id || '';
        await chooseUnit();
      }
    } catch (failure) {
      if (!controller.signal.aborted) error = errorMessage(failure);
    }
  }
  async function chooseUnit() {
    unit = undefined;
    if (!unitId) return;
    const selected = unitId;
    try {
      const result = await programsApi.getUnit({ unitId: selected }, { signal: controller.signal });
      if (selected !== unitId || controller.signal.aborted) return;
      unit = result.unit;
      startLine = unit?.language === 'binary' ? 1 : unit?.startLine || 1;
      endLine = Math.min(startLine + 5, startLine + (unit?.code.split('\n').length || 1) - 1);
    } catch (failure) {
      if (!controller.signal.aborted) error = errorMessage(failure);
    }
  }
  async function create(event: SubmitEvent) {
    event.preventDefault();
    if (busy || !unit || !excerpt || endLine - startLine > 100) return;
    busy = true;
    error = '';
    try {
      await programsApi.createAnnotation({
        requestId: requestId(),
        runId: run.id,
        unitId: unit.id,
        tag,
        rationale: rationale.trim(),
        evidence: [{ unitId: unit.id, startLine, endLine, quote: '' }],
      });
      creating = false;
      rationale = '';
      await refresh();
      onchanged();
      notify('人工标注已保存，引用内容已按原始代码核对。');
    } catch (failure) {
      error = errorMessage(failure);
    } finally {
      busy = false;
    }
  }
  function edit(annotation: LogicAnnotation) {
    editing = annotation.id;
    editRevision = annotation.revision;
    editTag = annotation.tag;
    editText = annotation.rationale;
  }
  async function save(event: SubmitEvent) {
    event.preventDefault();
    if (busy) return;
    busy = true;
    error = '';
    try {
      await programsApi.updateAnnotation({
        requestId: requestId(),
        annotationId: editing,
        expectedRevision: editRevision,
        tag: editTag,
        rationale: editText.trim(),
      });
      editing = '';
      await refresh();
      onchanged();
      notify('标注修订已保存。');
    } catch (failure) {
      error = errorMessage(failure);
    } finally {
      busy = false;
    }
  }
  onMount(() => {
    void refresh();
    const timer = setInterval(() => {
      if (!isTerminal(run.state)) void refresh();
    }, 1800);
    return () => {
      controller.abort();
      clearInterval(timer);
      clearTimeout(searchTimer);
    };
  });
  $effect(() => {
    if (isTerminal(run.state)) void refresh();
  });
</script>

<section class="annotations-workspace" aria-label="关键逻辑标注">
  <div class="panel-title">
    <h2>关键逻辑 · {annotations.length} 项</h2>
    <div class="annotation-actions">
      <button
        class="button secondary"
        onclick={() => {
          creating = !creating;
          if (creating) void searchUnits();
        }}><Plus size={15} />新建人工标注</button
      >
      <button class="text-button" aria-label="刷新标注" onclick={refresh}><RefreshCw size={15} /></button>
    </div>
  </div>
  <p class="annotation-note">
    同一快照且代码一致的人工标注，会作为后续模型任务的参考。已完成的分析不会自动重跑，结论仍须通过原文证据校验。
  </p>
  {#if error}<div class="error-banner" role="alert">{error}</div>{/if}
  {#if creating}<form class="panel annotation-editor" onsubmit={create}>
      <h3>新建人工标注</h3>
      <label class="field"
        >搜索标注单元<input
          bind:value={query}
          oninput={() => {
            clearTimeout(searchTimer);
            searchTimer = setTimeout(() => void searchUnits(), 250);
          }}
          placeholder="函数名或文件路径"
        /></label
      >
      <label class="field"
        >标注程序单元<select bind:value={unitId} onchange={chooseUnit}>
          {#each units as item}<option value={item.id}
              >{item.name} · {item.path} · {item.address || `L${item.startLine}–L${item.endLine}`}</option
            >{/each}
        </select></label
      >
      {#if !units.length}<p class="muted">当前没有可标注的程序单元，请等待结构解析或调整搜索条件。</p>{/if}
      <div class="annotation-fields">
        <label class="field"
          >逻辑类型<select bind:value={tag}
            >{#each Object.entries(tags) as [value, title]}<option {value}>{title}</option>{/each}</select
          ></label
        >
        <label class="field"
          >证据起始行<input type="number" min={base} max={last} bind:value={startLine} required /></label
        >
        <label class="field"
          >证据结束行<input
            type="number"
            min={startLine}
            max={Math.min(last, startLine + 100)}
            bind:value={endLine}
            required
          /></label
        >
      </div>
      <label class="field"
        >标注依据<textarea
          bind:value={rationale}
          required
          maxlength="2000"
          rows="4"
          placeholder="解释这段代码为何属于该逻辑，并说明已核对的条件"
        ></textarea></label
      >
      <p class="muted">
        证据预览 · {unit?.path || '请选择单元'}{unit?.address
          ? ` · 入口 ${unit.address}，行号为伪代码行`
          : ''}
      </p>
      <pre class="annotation-code">{excerpt || '请选择有效的行范围（最多 101 行）'}</pre>
      <div class="annotation-actions">
        <button class="button primary" disabled={busy || !unit || !excerpt || !rationale.trim()}
          ><Save size={14} />保存人工标注</button
        >
        <button type="button" class="button secondary" onclick={() => (creating = false)}>取消</button>
      </div>
    </form>{/if}
  <div class="annotation-list">
    {#each annotations as annotation}<article class="panel">
        <div class="panel-title">
          <h3>{tags[annotation.tag] || annotation.tag}</h3>
          <span class="subtle"
            >{annotation.actor === 'HUMAN' ? '人工标注' : '自动标注'} · v{annotation.revision}</span
          >
        </div>
        {#each annotation.evidence as reference}<div class="evidence-card">
            <button class="text-button" onclick={() => onselectunit(reference.unitId)}
              >{reference.path} · L{reference.startLine}–L{reference.endLine}{reference.address
                ? ` · ${reference.address}`
                : ''}</button
            >
            <pre>{reference.quote}</pre>
          </div>{/each}
        <p>{annotation.rationale}</p>
        {#if editing === annotation.id}<form onsubmit={save} class="annotation-editor">
            <label class="field"
              >修订逻辑类型<select bind:value={editTag}
                >{#each Object.entries(tags) as [value, title]}<option {value}>{title}</option>{/each}</select
              ></label
            >
            <label class="field"
              >修订标注依据<textarea bind:value={editText} required rows="3" maxlength="2000"
              ></textarea></label
            >
            <div class="annotation-actions">
              <button class="button secondary" disabled={busy || !editText.trim()}>保存标注修订</button
              ><button type="button" class="text-button" onclick={() => (editing = '')}>取消修订</button>
            </div>
          </form>{:else}<button class="text-button" onclick={() => edit(annotation)}>修订标注</button>{/if}
      </article>{/each}
    {#if !annotations.length && !creating}<div class="empty-panel">
        尚无关键逻辑标注，可以从上方新建人工标注。
      </div>{/if}
  </div>
</section>

<style>
  .annotations-workspace {
    padding: var(--space-4) 0;
  }
  .annotation-actions {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: var(--space-2);
  }
  .annotation-note {
    color: var(--muted);
    margin: var(--space-3) 0 var(--space-4);
  }
  .annotation-editor {
    display: grid;
    gap: var(--space-3);
    margin: var(--space-4) 0;
  }
  .annotation-fields {
    display: grid;
    gap: var(--space-3);
    grid-template-columns: 2fr 1fr 1fr;
  }
  .annotation-code {
    background: var(--surface-subtle);
    padding: var(--space-3);
    overflow: auto;
    max-height: 320px;
    font: var(--text-sm) / 1.65 var(--font-mono);
  }
  article p {
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
  @media (max-width: 600px) {
    .annotation-fields {
      grid-template-columns: 1fr;
    }
  }
</style>
