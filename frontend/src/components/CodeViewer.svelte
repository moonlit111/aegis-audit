<script lang="ts">
  import { onMount } from 'svelte';
  import type { editor } from 'monaco-editor';
  import EditorWorker from 'monaco-editor/esm/vs/editor/editor.worker?worker';
  import type { ProgramUnit } from '../gen/audit/v1/audit_pb';
  let { unit }: { unit: ProgramUnit } = $props();
  let container: HTMLDivElement;
  let instance: editor.IStandaloneCodeEditor | undefined;
  let monaco: typeof import('monaco-editor') | undefined;
  let ready = $state(false);
  let failure = $state('');

  function update() {
    if (!instance || !monaco) return;
    const previous = instance.getModel();
    const language = unit.language === 'binary' ? 'cpp' : unit.language;
    const model = monaco.editor.createModel(unit.code, language);
    instance.setModel(model);
    previous?.dispose();
    const offset = unit.language === 'binary' ? 0 : Math.max(0, unit.startLine - 1);
    instance.updateOptions({
      lineNumbers: (line) => String(line + offset),
      ariaLabel: `代码 ${unit.path} ${unit.name}`,
    });
    instance.setScrollTop(0);
  }
  $effect(() => {
    unit;
    if (ready) update();
  });
  onMount(() => {
    let disposed = false;
    (globalThis as typeof globalThis & { MonacoEnvironment: { getWorker: () => Worker } }).MonacoEnvironment =
      { getWorker: () => new EditorWorker() };
    Promise.all([
      import('monaco-editor/esm/vs/editor/editor.api'),
      import('monaco-editor/esm/vs/basic-languages/python/python.contribution'),
      import('monaco-editor/esm/vs/basic-languages/go/go.contribution'),
      import('monaco-editor/esm/vs/basic-languages/cpp/cpp.contribution'),
    ])
      .then(([module]) => {
        if (disposed) return;
        monaco = module;
        module.editor.defineTheme('aegis', {
          base: 'vs',
          inherit: true,
          rules: [
            { token: 'comment', foreground: '5f6b7c' },
            { token: 'keyword', foreground: '1d4ed8' },
            { token: 'string', foreground: '9a3412' },
          ],
          colors: {
            'editor.background': '#ffffff',
            'editor.foreground': '#0f172a',
            'editorGutter.background': '#ffffff',
            'editorLineNumber.foreground': '#5f6b7c',
            'editorLineNumber.activeForeground': '#334155',
            'editor.lineHighlightBackground': '#f8fafc',
            'editor.selectionBackground': '#dbeafe',
            'editor.inactiveSelectionBackground': '#eff6ff',
          },
        });
        instance = module.editor.create(container, {
          theme: 'aegis',
          readOnly: true,
          domReadOnly: true,
          automaticLayout: true,
          minimap: { enabled: false },
          fontSize: 14,
          lineHeight: 24,
          fontFamily: '"SFMono-Regular", Consolas, "Liberation Mono", monospace',
          padding: { top: 20, bottom: 20 },
          scrollBeyondLastLine: false,
          renderLineHighlight: 'none',
          wordWrap: 'off',
          tabSize: 4,
          overviewRulerLanes: 0,
          hideCursorInOverviewRuler: true,
          contextmenu: false,
          links: false,
          stickyScroll: { enabled: false },
        });
        ready = true;
      })
      .catch((error) => {
        failure = String(error);
      });
    return () => {
      disposed = true;
      instance?.getModel()?.dispose();
      instance?.dispose();
    };
  });
</script>

<div class="code-viewer" data-testid="code-viewer">
  <div class="monaco-host" bind:this={container}></div>
  {#if !ready && !failure}<div class="viewer-loading">正在加载代码视图…</div>{/if}
  {#if failure}<pre class="code-fallback">{unit.code}</pre>{/if}
</div>
