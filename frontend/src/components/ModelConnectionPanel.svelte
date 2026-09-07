<script lang="ts">
  import { Cable, Check, LoaderCircle, ArrowUpRight } from '@lucide/svelte';
  import type { ModelCall, ModelConnection } from '../gen/audit/v1/audit_pb';
  import { artifactUrl, errorMessage, requestId, systemApi } from '../lib/api';
  import { dateTime } from '../lib/format';
  let { connection, onchanged }: { connection?: ModelConnection; onchanged: () => Promise<void> } = $props();
  let staged = $state<ModelCall>();
  let submitting = $state(false);
  let error = $state('');
  const call = $derived(staged || connection?.lastCall);
  const running = $derived(submitting || call?.status === 'RUNNING');
  const verified = $derived(connection?.configured && call?.status === 'SUCCEEDED');
  $effect(() => {
    if (staged && connection?.lastCall?.id === staged.id) staged = undefined;
  });
  async function check() {
    submitting = true;
    error = '';
    try {
      staged = (await systemApi.checkModelConnection({ requestId: requestId() })).call;
      await onchanged();
    } catch (failure) {
      error = errorMessage(failure);
    } finally {
      submitting = false;
    }
  }
</script>

<section class="panel environment-panel model-panel">
  <div class="panel-title">
    <div class="executor-title">
      <span class="icon-tile"><Cable size={21} /></span>
      <div>
        <h2>DeepSeek 官方</h2>
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
    </div>
    <button class="button secondary" onclick={check} disabled={!connection?.configured || running}
      >{#if running}<LoaderCircle class="spin" size={14} />{:else}<Cable size={14} />{/if}{running
        ? '正在检测…'
        : '检测连接'}</button
    >
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
  {#if !connection?.configured}<p class="muted model-setup">
      按<a
        href="https://github.com/moonlit111/aegis-audit/blob/main/Docs/安装与运行.md"
        target="_blank"
        rel="noreferrer">安装说明</a
      >完成本机模型配置。
    </p>{/if}
</section>
