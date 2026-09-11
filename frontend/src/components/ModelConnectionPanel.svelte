<script lang="ts">
  import { Cable, Check, LoaderCircle, ArrowUpRight, Settings2, Save } from '@lucide/svelte';
  import type { ModelCall, ModelConnection } from '../gen/audit/v1/audit_pb';
  import { artifactUrl, errorMessage, requestId, systemApi } from '../lib/api';
  import { dateTime } from '../lib/format';
  let { connection, onchanged }: { connection?: ModelConnection; onchanged: () => Promise<void> } = $props();
  let staged = $state<ModelCall>();
  let submitting = $state(false);
  let error = $state('');
  let notice = $state('');
  let editing = $state(false);
  let saving = $state(false);
  let providerKind = $state('DEEPSEEK');
  let endpoint = $state('https://api.deepseek.com');
  let model = $state('deepseek-v4-flash');
  let apiKey = $state('');
  let keyAction = $state('REPLACE');
  let revision = $state('');
  const keySources: Record<string, string> = {
    WEB_SAVED: '网页保存（Windows 加密）',
    LOCAL_FILE: '本地凭据文件',
    AEGIS_MODEL_API_KEY: '环境变量 AEGIS_MODEL_API_KEY',
    DEEPSEEK_API_KEY: '环境变量 DEEPSEEK_API_KEY',
    NONE: '未配置',
  };
  const call = $derived(staged || connection?.lastCall);
  const running = $derived(submitting || call?.status === 'RUNNING');
  const verified = $derived(connection?.configured && call?.status === 'SUCCEEDED');
  $effect(() => {
    if (staged && connection?.lastCall?.id === staged.id) staged = undefined;
  });
  async function check() {
    submitting = true;
    error = '';
    notice = '';
    try {
      staged = (await systemApi.checkModelConnection({ requestId: requestId() })).call;
      await onchanged();
    } catch (failure) {
      error = errorMessage(failure);
    } finally {
      submitting = false;
    }
  }
  function edit() {
    providerKind = connection?.providerKind || 'DEEPSEEK';
    endpoint = connection?.endpoint || 'https://api.deepseek.com';
    model = connection?.model || 'deepseek-v4-flash';
    revision = connection?.revision || 'legacy';
    apiKey = '';
    keyAction = connection?.configured ? 'KEEP' : 'REPLACE';
    error = '';
    notice = '';
    editing = true;
  }
  function changeProvider() {
    if (providerKind === 'DEEPSEEK') {
      endpoint = 'https://api.deepseek.com';
      model = 'deepseek-v4-flash';
    } else {
      endpoint = '';
      model = '';
    }
    apiKey = '';
    keyAction = 'REPLACE';
  }
  async function save(event: SubmitEvent) {
    event.preventDefault();
    if (saving) return;
    saving = true;
    error = '';
    notice = '';
    try {
      const response = await systemApi.saveModelSettings({
        requestId: requestId(),
        providerKind,
        endpoint: endpoint.trim(),
        model: model.trim(),
        apiKey: keyAction === 'REPLACE' ? apiKey.trim() : '',
        keyAction,
        expectedRevision: revision,
      });
      connection = response.connection;
      apiKey = '';
      staged = undefined;
      editing = false;
      notice = '连接设置已保存，可点击“检测连接”验证。';
      await onchanged();
    } catch (failure) {
      error = errorMessage(failure);
    } finally {
      saving = false;
    }
  }
</script>

<section class="panel environment-panel model-panel">
  <div class="panel-title">
    <div class="executor-title">
      <span class="icon-tile"><Cable size={21} /></span>
      <div>
        <h2>{connection?.provider || '模型连接'}</h2>
        <span class="subtle">{connection?.endpoint || 'https://api.deepseek.com'}</span>
      </div>
    </div>
    <span class={`badge ${verified ? 'success' : 'neutral'}`}
      >{#if verified}<Check
          size={12}
        />调用已验证{:else if running}检查中{:else if call?.status === 'FAILED'}连接失败{:else if call?.status === 'INTERRUPTED'}检查中断{:else if connection?.configured}已配置
        · 待检查{:else}未配置{/if}</span
    >
  </div>
  <div class="model-connection-body">
    <div>
      <span class="field-label">模型</span><strong>{connection?.model || 'deepseek-v4-flash'}</strong>
      <p class="muted">连接检测验证模型的 JSON 响应，并记录服务商返回的实际用量。</p>
      <p class="muted">凭据来源：{keySources[connection?.keySource || 'NONE'] || connection?.keySource}</p>
    </div>
    <button class="button secondary" onclick={check} disabled={!connection?.configured || running}
      >{#if running}<LoaderCircle class="spin" size={14} />{:else}<Cable size={14} />{/if}{running
        ? '正在检测…'
        : '检测连接'}</button
    >
  </div>
  <div class="model-settings">
    <div class="model-settings-actions">
      <button class="button secondary" onclick={edit} disabled={saving}
        ><Settings2 size={15} />{connection?.configured ? '编辑模型连接' : '配置模型连接'}</button
      >
      {#if notice}<p role="status">{notice}</p>{/if}
    </div>
    {#if editing}<form class="model-editor" onsubmit={save}>
        <h3>模型连接设置</h3>
        <label class="field"
          >接口类型<select bind:value={providerKind} onchange={changeProvider}>
            <option value="DEEPSEEK">DeepSeek 官方</option><option value="OPENAI_COMPATIBLE"
              >OpenAI 兼容接口</option
            >
          </select></label
        >
        <label class="field"
          >API 基础地址<input
            type="url"
            bind:value={endpoint}
            disabled={providerKind === 'DEEPSEEK'}
            required
            maxlength="2048"
            placeholder="https://example.com/v1"
            autocomplete="off"
          /></label
        >
        <p class="muted">
          地址后会追加 /chat/completions。本机服务可用 http://127.0.0.1:端口/v1，其余地址使用 HTTPS。
        </p>
        <label class="field"
          >模型标识<input
            bind:value={model}
            required
            maxlength="100"
            autocomplete="off"
            placeholder="服务提供的模型名称"
          /></label
        >
        <label class="field"
          >密钥处理<select bind:value={keyAction} onchange={() => (apiKey = '')}>
            {#if connection?.configured}<option value="KEEP">保留现有密钥</option>{/if}
            <option value="REPLACE">填写新密钥</option><option value="CLEAR">移除网页保存的密钥</option>
          </select></label
        >
        {#if keyAction === 'REPLACE'}<label class="field"
            >API Key<input
              type="password"
              bind:value={apiKey}
              required
              maxlength="16384"
              autocomplete="new-password"
              spellcheck="false"
              placeholder="仅用于当前接口，不会回显保存值"
            /></label
          >{/if}
        <p class="muted">
          保存的密钥由当前 Windows 用户加密；移除后仍可从匹配接口的环境变量读取。兼容模式使用标准聊天消息和
          JSON 文本输出。
        </p>
        {#if connection?.settingsLocked}<p class="audit-gap">
            审计或连接检测正在使用配置，结束或取消完成后即可保存。当前填写内容会保留。
          </p>{/if}
        {#if revision !== connection?.revision}<p class="audit-gap">
            配置已在其他位置更新，请取消编辑后重新打开，避免覆盖新设置。
          </p>{/if}
        <div class="model-settings-actions">
          <button
            class="button primary"
            disabled={saving || connection?.settingsLocked || revision !== connection?.revision}
            ><Save size={14} />{saving ? '保存中…' : '保存配置'}</button
          >
          <button
            class="button secondary"
            type="button"
            onclick={() => {
              editing = false;
              apiKey = '';
              error = '';
            }}>取消编辑</button
          >
        </div>
      </form>{/if}
  </div>
  {#if call}<div class="model-call-record">
      <span>最近检查 {dateTime(call.finishedAt || call.createdAt)}</span>{#if call.usageAvailable}<span
          >输入 <b>{call.inputTokens.toString()}</b> / 输出 <b>{call.outputTokens.toString()}</b> tokens</span
        >{:else if call.status !== 'RUNNING'}<span>用量未确认</span>{/if}{#if call.latencyMs > 0n}<span
          >{(Number(call.latencyMs) / 1000).toFixed(2)} 秒</span
        >{/if}{#if call.artifactId}<a href={artifactUrl(call.artifactId)} class="text-button"
          >调用记录<ArrowUpRight size={12} /></a
        >{/if}
    </div>{/if}
  {#if error || call?.error || connection?.statusMessage}<div class="error-banner model-error" role="alert">
      {error || call?.error || connection?.statusMessage}
    </div>{/if}
</section>

<style>
  .model-settings {
    padding: 0 var(--space-6) var(--space-5);
  }
  .model-settings-actions {
    display: flex;
    gap: var(--space-3);
    align-items: center;
    flex-wrap: wrap;
    margin-top: var(--space-3);
  }
  .model-settings-actions p {
    color: var(--success);
  }
  .model-editor {
    display: grid;
    gap: var(--space-3);
    max-width: 760px;
    border-top: 1px solid var(--line);
    padding-top: var(--space-4);
    margin-top: var(--space-4);
  }
  .model-editor input,
  .model-editor select {
    width: 100%;
    min-width: 0;
  }
  .executor-title .subtle {
    overflow-wrap: anywhere;
  }
  @media (max-width: 600px) {
    .model-settings {
      padding-inline: var(--space-4);
    }
  }
</style>
