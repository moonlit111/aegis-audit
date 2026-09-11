<script lang="ts">
  import { onMount } from 'svelte';
  import { Cable, Download, FileJson, LoaderCircle, MessageSquareText, X } from '@lucide/svelte';
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
  let tab = $state<'output' | 'reasoning' | 'request' | 'response'>('output');

  type ChatMessage = {
    content?: string;
    reasoning_content?: string;
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

  const artifact = $derived(parseJson<CallArtifact | null>(responseText, null));
  const response = $derived(artifact?.choices ? artifact : artifact?.response);
  const message = $derived(response?.choices?.[0]?.message);
  const outputText = $derived(message?.content ? prettyJson(message.content) : '暂无模型输出');
  const reasoningText = $derived(message?.reasoning_content || '该响应未包含推理内容');
  const requestJson = $derived(requestText ? prettyJson(requestText) : '该调用没有请求产物');
  const responseJson = $derived(responseText ? prettyJson(responseText) : '暂无响应产物');

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
    <div><span>状态</span><strong>{call.status}</strong></div>
    <div><span>时间</span><strong>{dateTime(call.finishedAt || call.createdAt)}</strong></div>
    <div><span>耗时</span><strong>{Number(call.latencyMs) / 1000 || 0} 秒</strong></div>
    <div>
      <span>Tokens</span><strong>{call.inputTokens.toString()} / {call.outputTokens.toString()}</strong>
    </div>
    <div>
      <span>服务商请求</span><strong title={call.providerRequestId}>{call.providerRequestId || '—'}</strong>
    </div>
  </div>
  <div class="model-call-tabs" role="tablist" aria-label="调用记录视图">
    <button
      type="button"
      role="tab"
      aria-selected={tab === 'output'}
      class:active={tab === 'output'}
      onclick={() => (tab = 'output')}><MessageSquareText size={15} />模型输出</button
    >
    <button
      type="button"
      role="tab"
      aria-selected={tab === 'reasoning'}
      class:active={tab === 'reasoning'}
      onclick={() => (tab = 'reasoning')}>推理内容</button
    >
    <button
      type="button"
      role="tab"
      aria-selected={tab === 'request'}
      class:active={tab === 'request'}
      disabled={!requestText}
      onclick={() => (tab = 'request')}><FileJson size={15} />请求 JSON</button
    >
    <button
      type="button"
      role="tab"
      aria-selected={tab === 'response'}
      class:active={tab === 'response'}
      disabled={!responseText}
      onclick={() => (tab = 'response')}><FileJson size={15} />响应 JSON</button
    >
  </div>
  <div class="model-call-content" role="tabpanel">
    {#if loading}<div class="model-call-loading">
        <LoaderCircle class="spin" size={18} />正在读取调用产物…
      </div>
    {:else if error}<div class="error-banner" role="alert">{error}</div>
    {:else if tab === 'output'}<pre>{outputText}</pre>
    {:else if tab === 'reasoning'}<pre>{reasoningText}</pre>
    {:else if tab === 'request'}<pre>{requestJson}</pre>
    {:else}<pre>{responseJson}</pre>{/if}
  </div>
  <div class="dialog-actions">
    <button type="button" class="button secondary" onclick={onclose}>关闭</button>
    <a class="button primary" href={artifactUrl(call.artifactId)}><Download size={15} />下载响应 JSON</a>
  </div>
</dialog>
