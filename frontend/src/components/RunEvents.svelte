<script lang="ts">
  import { tick, untrack } from 'svelte';
  import { flip } from 'svelte/animate';
  import { fly } from 'svelte/transition';
  import { prefersReducedMotion } from 'svelte/motion';
  import { Activity, ArrowUp, Radio } from '@lucide/svelte';
  import type { RunEvent, RunPhase, RunState } from '../gen/audit/v1/audit_pb';
  import { dateTime, isTerminal, runLabel } from '../lib/format';

  let {
    events,
    phases,
    streamStatus,
    runState,
  }: {
    events: RunEvent[];
    phases: RunPhase[];
    streamStatus: string;
    runState: RunState;
  } = $props();

  // Opening another tab must not replay arrival effects for already visible events.
  const initialSequence = untrack(() => events[0]?.seq || 0n);
  const clock = new Intl.DateTimeFormat('zh-CN', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
  let list = $state<HTMLDivElement>();
  let following = $state(true);
  let seenSequence = $state(initialSequence);
  let previousSequence = -1n;
  const running = $derived(!isTerminal(runState));
  const live = $derived(running && streamStatus === '实时连接');
  const unreadCount = $derived(events.filter((event) => event.seq > seenSequence).length);
  const motion = $derived(running && following && !prefersReducedMotion.current);

  function onscroll() {
    if (!list) return;
    following = list.scrollTop <= 8;
    if (following) seenSequence = events[0]?.seq || 0n;
  }

  function showLatest() {
    if (list) list.scrollTop = 0;
    following = true;
    seenSequence = events[0]?.seq || 0n;
  }

  $effect.pre(() => {
    const sequence = events[0]?.seq || 0n;
    const element = list;
    if (!element || sequence === previousSequence) return;
    previousSequence = sequence;
    // Keep the same visible card in place while reading older events, including
    // when the 500-event window drops an entry from the bottom.
    const anchor = following
      ? undefined
      : Array.from(element.children).find(
          (row) => row.getBoundingClientRect().bottom > element.getBoundingClientRect().top,
        );
    const anchorTop = anchor?.getBoundingClientRect().top;
    void tick().then(() => {
      if (!element.isConnected) return;
      if (following) {
        element.scrollTop = 0;
        seenSequence = sequence;
      } else if (anchor?.isConnected && anchorTop !== undefined) {
        element.scrollTop += anchor.getBoundingClientRect().top - anchorTop;
      }
    });
  });
</script>

<section class="panel events-panel" aria-label="任务事件">
  <div class="panel-title">
    <div class="events-heading">
      <h2><Activity size={17} />任务事件</h2>
      <span class="subtle">最新事件在前 · 自动更新 · 保留最近 500 条</span>
    </div>
    <div class="events-actions">
      <span class="event-connection" class:live class:reconnecting={running && !live} role="status">
        {#if running}<i class="activity-dot" aria-hidden="true"></i>{/if}
        {live ? runLabel(runState) : streamStatus}
      </span>
      <span class="badge neutral">{events.length} 条</span>
      {#if !following}
        <button class="text-button latest-events" onclick={showLatest}>
          <ArrowUp size={14} />{unreadCount ? `${unreadCount} 条新事件` : '回到最新'}
        </button>
      {/if}
    </div>
  </div>
  <!-- svelte-ignore a11y_no_noninteractive_tabindex (The scrollable event log needs keyboard access.) -->
  <div
    class="event-list"
    bind:this={list}
    {onscroll}
    role="log"
    aria-label="任务事件列表"
    aria-live="polite"
    aria-relevant="additions"
    aria-atomic="false"
    tabindex="0"
  >
    {#each events as event (event.seq)}
      <div
        class="event-row"
        class:new-event={running && event.seq > initialSequence}
        data-seq={event.seq.toString()}
        in:fly={{ y: -14, duration: motion && event.seq > initialSequence ? 300 : 0 }}
        animate:flip={{ duration: motion ? 260 : 0 }}
      >
        <span class="event-seq">{event.seq.toString().padStart(3, '0')}</span>
        <time datetime={event.createdAt} title={dateTime(event.createdAt)}>
          {event.createdAt ? clock.format(new Date(event.createdAt)) : '—'}
        </time>
        <div class="event-content">
          <span class="event-kind">{event.kind}</span>
          {#if event.phaseId}
            <span class="subtle event-phase">
              · 阶段 {event.phaseOrder}/{event.phaseCount}
              {phases.find((phase) => phase.id === event.phaseId)?.title || event.phaseId}
            </span>
          {/if}
          <pre>{event.message}</pre>
          {#if event.total > 0n && event.kind === 'TOOL_PROGRESS'}
            <div class="event-progress">
              <progress aria-label="工具进度" max={Number(event.total)} value={Number(event.current)}
              ></progress>
              <span>{event.current.toString()} / {event.total.toString()}</span>
            </div>
          {/if}
        </div>
      </div>
    {:else}
      <div class="events-empty">
        <Radio size={19} />
        <span>{streamStatus === '事件已归档' ? '暂无任务事件' : '等待任务事件，收到后会自动显示…'}</span>
      </div>
    {/each}
  </div>
</section>

<style>
  .events-panel {
    overflow: hidden;
  }
  .panel-title {
    gap: var(--space-3);
    flex-wrap: wrap;
  }
  .events-heading {
    display: grid;
    gap: 4px;
  }
  h2,
  .events-actions,
  .event-connection {
    display: flex;
    align-items: center;
    gap: var(--space-2);
  }
  .events-actions {
    flex-wrap: wrap;
    gap: 10px 16px;
  }
  .event-connection {
    color: var(--muted);
    font-size: var(--text-sm);
  }
  .event-connection.live {
    color: var(--accent);
  }
  .event-connection.reconnecting {
    color: var(--warning);
  }
  .activity-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: currentColor;
    flex: none;
  }
  .live .activity-dot {
    animation: activity-pulse 1.8s ease-out infinite;
  }
  .event-list {
    overflow-anchor: none;
    scrollbar-gutter: stable;
  }
  .event-row {
    min-width: 0;
  }
  .event-row.new-event {
    animation: event-highlight 2.4s ease-out both;
  }
  .event-row time {
    white-space: nowrap;
  }
  .event-progress {
    flex-wrap: wrap;
  }
  .event-progress progress {
    max-width: 100%;
  }
  .latest-events {
    font-weight: 600;
  }
  .events-empty {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
    padding: var(--space-6);
    color: var(--muted);
  }
  @keyframes activity-pulse {
    0% {
      box-shadow: 0 0 0 0 var(--accent-line);
    }
    75%,
    100% {
      box-shadow: 0 0 0 6px transparent;
    }
  }
  @keyframes event-highlight {
    0%,
    20% {
      background: var(--accent-soft);
      border-color: var(--accent-line);
    }
    100% {
      background: var(--surface);
      border-color: var(--line);
    }
  }
</style>
