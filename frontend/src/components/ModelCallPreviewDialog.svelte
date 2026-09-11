<script lang="ts">
  import { onMount } from 'svelte';
  import { Cable, Download, FileJson, LoaderCircle, X } from '@lucide/svelte';
  import type { ModelCall } from '../gen/audit/v1/audit_pb';
  import { artifactUrl } from '../lib/api';
  import { dateTime } from '../lib/format';

  let {
    call,
    requestText,
    responseText,
    loading,
    error,
    onclose,
  }: {
    call: ModelCall;
    requestText: string;
    responseText: string;
    loading: boolean;
    error: string;
    onclose: () => void;
  } = $props();

  let dialog: HTMLDialogElement;
  let tab = $state<'output' | 'request' | 'response'>('output');

  type ChatMessage = {
    content?: string;
    role?: string;
  };
  type ChatResponse = {
    choices?: { finish_reason?: string; message?: ChatMessage }[];
    usage?: Record<string, unknown>;
  };
  type CallArtifact = ChatResponse & { response?: ChatResponse };

  function parseJson<T>(text: string, fallback: T): T {
    try {
      return (JSON.parse(text) || fallback) as T;
    } catch {
      return fallback;
    }
  }

  function prettyJson(text: string): string {
    try {
      return JSON.stringify(JSON.parse(text), null, 2);
    } catch {
      return text;
    }
  }

  function withoutReasoning(value: unknown): unknown {
    if (Array.isArray(value)) return value.map(withoutReasoning);
    if (!value || typeof value !== 'object') return value;
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([key]) => !['reasoning_content', 'reasoning'].includes(key))
        .map(([key, item]) => [key, withoutReasoning(item)]),
    );
  }

  function statusLabel(status: string): string {
    return (
      {
        RUNNING: '调用中',
        SUCCEEDED: '调用成功',
        FAILED: '调用失败',
        INVALID_RESPONSE: '响应无效',
        INTERRUPTED: '调用中断',
      }[status] || status
    );
  }

  const artifact = $derived(parseJson<CallArtifact | null>(responseText, null));
  const response = $derived(artifact?.choices ? artifact : artifact?.response);
  const message = $derived(response?.choices?.[0]?.message);
  const outputText = $derived(message?.content ? prettyJson(message.content) : '暂无模型输出');
  const requestJson = $derived(requestText ? prettyJson(requestText) : '');
  const responseJson = $derived(
    responseText ? JSON.stringify(withoutReasoning(parseJson(responseText, null)), null, 2) : '',
  );

  onMount(() => {
    dialog.showModal();
  });
</script>

<dialog bind:this={dialog} class="import-dialog model-call-dialog" oncancel={onclose}>
  <div class="dialog-heading">
    <div class="icon-tile"><Cable size={22} /></div>
    <button class="icon-button" aria-label="关闭调用记录" onclick={onclose}><X size={20} /></button>
  </div>
  <h2>模型调用记录</h2>
  <div class="model-call-summary">
    <div><span>模型</span><strong>{call.model}</strong></div>
    <div><span>状态</span><strong>{statusLabel(call.status)}</strong></div>
    <div><span>时间</span><strong>{dateTime(call.finishedAt || call.createdAt)}</strong></div>
    <div><span>耗时</span><strong>{(Number(call.latencyMs) / 1000).toFixed(2)} 秒</strong></div>
    <div>
      <span>Token 用量</span>
      <strong>输入 {call.inputTokens.toString()} · 输出 {call.outputTokens.toString()}</strong>
    </div>
    <div>
      <span>服务商请求</span>
      <strong title={call.providerRequestId}>{call.providerRequestId || '—'}</strong>
    </div>
  </div>
  <div class="model-call-tabs" role="tablist" aria-label="调用记录视图">
    <button
      type="button"
      role="tab"
      aria-selected={tab === 'output'}
      class:active={tab === 'output'}
      onclick={() => (tab = 'output')}>模型输出</button
    >
    {#if requestText}<button
        type="button"
        role="tab"
        aria-selected={tab === 'request'}
        class:active={tab === 'request'}
        onclick={() => (tab = 'request')}><FileJson size={15} />请求 JSON</button
      >{/if}
    <button
      type="button"
      role="tab"
      aria-selected={tab === 'response'}
      class:active={tab === 'response'}
      onclick={() => (tab = 'response')}><FileJson size={15} />响应 JSON</button
    >
  </div>
  <div class="model-call-content" role="tabpanel">
    {#if loading}<div class="model-call-loading">
        <LoaderCircle class="spin" size={18} />正在读取调用产物…
      </div>
    {:else if error}<div class="error-banner" role="alert">{error}</div>
    {:else if tab === 'output'}<pre>{outputText}</pre>
    {:else if tab === 'request'}<pre>{requestJson}</pre>
    {:else}<pre>{responseJson}</pre>{/if}
  </div>
  <p class="model-call-note">在线视图隐藏服务商 reasoning 字段；下载的原始 JSON 保留完整调试信息。</p>
  <div class="dialog-actions">
    <button type="button" class="button secondary" onclick={onclose}>关闭</button>
    <a class="button primary" href={artifactUrl(call.artifactId)}><Download size={15} />下载响应 JSON</a>
  </div>
</dialog>
