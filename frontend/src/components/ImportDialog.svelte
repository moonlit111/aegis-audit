<script lang="ts">
  import { onMount } from 'svelte';
  import {
    Archive,
    Binary,
    FolderOpen,
    GitBranch,
    Upload,
    X,
    ArrowRight,
    LoaderCircle,
  } from '@lucide/svelte';
  import { zip, type Zippable } from 'fflate';
  import type { Project } from '../gen/audit/v1/audit_pb';
  import { TargetKind } from '../gen/audit/v1/audit_pb';
  import { projectsApi, upload, requestId, errorMessage } from '../lib/api';
  import { bytes } from '../lib/format';

  let {
    projects,
    initialProjectId = '',
    onclose,
    onimported,
  }: {
    projects: Project[];
    initialProjectId?: string;
    onclose: () => void;
    onimported: (project: string, snapshot: string) => void;
  } = $props();
  let dialog: HTMLDialogElement;
  let projectId = $state('');
  let name = $state('');
  let mode = $state<'source' | 'folder' | 'binary' | 'git'>('source');
  let files = $state<File[]>([]);
  let gitUrl = $state('');
  let revision = $state('');
  let busy = $state(false);
  let progress = $state(0);
  let step = $state('');
  let error = $state('');
  const modes = [
    { id: 'source', label: '源码 ZIP', icon: Archive },
    { id: 'folder', label: '本地文件夹', icon: FolderOpen },
    { id: 'binary', label: 'PE / ELF', icon: Binary },
    { id: 'git', label: 'Git 仓库', icon: GitBranch },
  ] as const;
  const size = $derived(files.reduce((total, file) => total + file.size, 0));
  const ready = $derived(
    (projectId || name.trim()) && (mode === 'git' ? gitUrl.trim() && revision.trim() : files.length > 0),
  );
  onMount(() => {
    projectId = initialProjectId;
    dialog.showModal();
  });

  function chooseMode(value: typeof mode) {
    mode = value;
    files = [];
    error = '';
  }
  function chooseFiles(event: Event) {
    files = Array.from((event.target as HTMLInputElement).files || []);
    error = '';
  }
  async function packFolder(): Promise<Blob> {
    if (files.length > 20_000 || size > 128 * 1024 * 1024)
      throw new Error('浏览器文件夹导入上限为 20,000 个文件、128 MiB。更大的项目请打包为 ZIP。');
    const entries: Zippable = Object.create(null);
    for (const file of files) {
      if (file.size > 32 * 1024 * 1024) throw new Error(`文件 ${file.name} 超过单文件 32 MiB 上限。`);
      const path = file.webkitRelativePath.split('/').slice(1).join('/') || file.name;
      entries[path] = new Uint8Array(await file.arrayBuffer());
    }
    return new Promise((resolve, reject) =>
      zip(entries, { level: 1 }, (failure, result) => {
        if (failure) reject(failure);
        else resolve(new Blob([new Uint8Array(result).buffer], { type: 'application/zip' }));
      }),
    );
  }
  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!ready || busy) return;
    busy = true;
    error = '';
    progress = 0;
    try {
      let artifactId = '';
      let snapshotName = '';
      if (mode !== 'git') {
        step = mode === 'folder' ? '正在打包文件夹…' : '正在上传…';
        const data = mode === 'folder' ? await packFolder() : files[0];
        snapshotName =
          mode === 'folder'
            ? (files[0].webkitRelativePath.split('/')[0] || 'source') + '.zip'
            : files[0].name;
        step = '正在上传…';
        artifactId = await upload(data, snapshotName, (percent) => {
          progress = percent;
        });
      }
      step = '正在创建快照…';
      let id = projectId;
      if (!id) {
        const response = await projectsApi.createProject({ requestId: requestId(), name: name.trim() });
        id = response.project!.id;
        projectId = id;
      }
      const response = await projectsApi.createSnapshot({
        requestId: requestId(),
        projectId: id,
        name: snapshotName,
        kind: mode === 'git' ? TargetKind.GIT : mode === 'binary' ? TargetKind.BINARY : TargetKind.SOURCE,
        artifactId,
        gitUrl: mode === 'git' ? gitUrl.trim() : '',
        gitRevision: mode === 'git' ? revision.trim() : '',
      });
      onimported(id, response.snapshot!.id);
    } catch (failure) {
      error = errorMessage(failure);
    } finally {
      busy = false;
    }
  }
</script>

<dialog
  bind:this={dialog}
  class="import-dialog"
  oncancel={(event) => {
    event.preventDefault();
    if (!busy) onclose();
  }}
  aria-labelledby="import-title"
>
  <div class="dialog-heading">
    <div class="icon-tile"><Upload size={22} /></div>
    <button class="icon-button" aria-label="关闭导入窗口" disabled={busy} onclick={onclose}
      ><X size={20} /></button
    >
  </div>
  <h2 id="import-title">导入分析目标</h2>
  <p class="muted">创建固定版本的快照，保留源文件哈希与解析依据。</p>
  <form onsubmit={submit}>
    <label class="field"
      >所属项目<select bind:value={projectId} disabled={busy} aria-label="所属项目"
        ><option value="">新建项目</option>{#each projects as project}<option value={project.id}
            >{project.name}</option
          >{/each}</select
      ></label
    >
    {#if !projectId}<label class="field"
        >项目名称<input
          bind:value={name}
          required
          maxlength="120"
          placeholder="例如：文档服务源码分析"
          disabled={busy}
        /></label
      >{/if}
    <div class="field-label">目标来源</div>
    <div class="import-modes" role="group" aria-label="目标来源">
      {#each modes as item}<button
          type="button"
          class:active={mode === item.id}
          aria-pressed={mode === item.id}
          disabled={busy}
          onclick={() => chooseMode(item.id)}><item.icon size={19} />{item.label}</button
        >{/each}
    </div>
    {#if mode === 'git'}
      <label class="field"
        >HTTPS 仓库地址<input
          type="url"
          bind:value={gitUrl}
          placeholder="https://github.com/owner/repository.git"
          pattern="https://.*"
          required
          disabled={busy}
        /></label
      >
      <label class="field"
        >提交、标签或分支<input
          bind:value={revision}
          placeholder="例如：v1.2.0 或完整 commit SHA"
          required
          disabled={busy}
        /></label
      >
      <p class="field-help">导入后记录实际提交 SHA。不递归获取子模块，不执行仓库构建脚本。</p>
    {:else}
      <div
        class="drop-zone"
        class:has-files={files.length > 0}
        role="group"
        aria-label="文件选择区域"
        ondragover={(event) => event.preventDefault()}
        ondrop={(event) => {
          event.preventDefault();
          if (!busy && mode !== 'folder') files = Array.from(event.dataTransfer?.files || []).slice(0, 1);
        }}
      >
        <Upload size={26} strokeWidth={1.4} />
        <strong
          >{files.length
            ? mode === 'folder'
              ? `${files.length} 个文件 · ${bytes(size)}`
              : files[0].name
            : mode === 'folder'
              ? '选择本地源码文件夹'
              : '将文件拖到这里'}</strong
        >
        <span
          >{files.length
            ? '重新选择可以替换当前文件'
            : mode === 'binary'
              ? '支持 PE x86 / x64、ELF x86_64'
              : 'Python、Go、C、C++'}</span
        >
        <label class="button secondary file-picker"
          >{mode === 'folder' ? '选择文件夹' : mode === 'binary' ? '选择二进制文件' : '选择 ZIP 文件'}
          {#if mode === 'folder'}<input
              type="file"
              webkitdirectory
              multiple
              onchange={chooseFiles}
              disabled={busy}
              aria-label="选择文件夹"
            />
          {:else}<input
              type="file"
              accept={mode === 'source' ? '.zip' : undefined}
              onchange={chooseFiles}
              disabled={busy}
              aria-label={mode === 'binary' ? '选择二进制文件' : '选择 ZIP 文件'}
            />{/if}
        </label>
      </div>
      <p class="field-help">
        {mode === 'folder'
          ? '浏览器打包上限 128 MiB；单个源码文件导入上限 32 MiB。'
          : '上传上限 512 MiB；源码 ZIP 解压上限 512 MiB、20,000 个条目。'} 导入记录会列出排除文件。
      </p>
    {/if}
    <div class="scope-note">
      <span class="mini-label">本轮能力</span>程序结构解析、可选漏洞审计、动态测试与利用证据留痕。
    </div>
    {#if error}<div class="error-banner" role="alert">{error}</div>{/if}
    {#if busy}<div class="upload-status" role="status">
        <span>{step}</span><span>{progress}%</span><progress max="100" value={progress}></progress>
      </div>{/if}
    <div class="dialog-actions">
      <button type="button" class="button secondary" disabled={busy} onclick={onclose}>取消</button><button
        type="submit"
        class="button primary"
        disabled={!ready || busy}
        >{#if busy}<LoaderCircle class="spin" size={16} />{:else}<ArrowRight size={16} />{/if}{busy
          ? '处理中…'
          : '导入并创建快照'}</button
      >
    </div>
  </form>
</dialog>
