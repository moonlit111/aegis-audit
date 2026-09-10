<script lang="ts">
  import { onMount } from 'svelte';
  import cytoscape from 'cytoscape';
  import type { ProgramUnit, ProgramEdge } from '../gen/audit/v1/audit_pb';
  let {
    units,
    edges,
    focus,
    onselect,
  }: { units: ProgramUnit[]; edges: ProgramEdge[]; focus: string; onselect: (id: string) => void } = $props();
  let container: HTMLDivElement;
  let cy: cytoscape.Core | undefined;
  let mounted = $state(false);
  function render() {
    if (!cy) return;
    const nodes: cytoscape.ElementDefinition[] = units.map((unit) => ({
      data: { id: unit.id, label: unit.name.length > 34 ? unit.name.slice(0, 32) + '…' : unit.name },
      classes: unit.id === focus ? 'focus' : '',
    }));
    const links: cytoscape.ElementDefinition[] = [];
    const known = new Set(units.map((unit) => unit.id));
    edges.forEach((edge, index) => {
      if (!known.has(edge.sourceId)) return;
      const target = known.has(edge.targetId) ? edge.targetId : `unknown-${index}`;
      if (target.startsWith('unknown-'))
        nodes.push({ data: { id: target, label: edge.targetName.slice(0, 34) }, classes: 'unknown' });
      links.push({
        data: {
          id: `edge-${index}`,
          source: edge.sourceId,
          target,
          label:
            edge.certainty === 'INFERRED' ? '推断' : edge.certainty === 'UNKNOWN' ? '未解析' : '工具报告',
        },
        classes: edge.certainty.toLowerCase(),
      });
    });
    cy.elements().remove();
    cy.add([...nodes, ...links]);
    cy.layout({
      name: 'breadthfirst',
      directed: false,
      spacingFactor: 1.35,
      padding: 50,
      animate: false,
    }).run();
    cy.fit(undefined, 45);
    cy.maxZoom(1.8);
  }
  $effect(() => {
    units;
    edges;
    focus;
    if (mounted) render();
  });
  onMount(() => {
    cy = cytoscape({
      container,
      elements: [],
      wheelSensitivity: 0.2,
      minZoom: 0.15,
      maxZoom: 1.8,
      style: [
        {
          selector: 'node',
          style: {
            shape: 'round-rectangle',
            'background-color': '#ffffff',
            'border-width': 1,
            'border-color': '#64748b',
            label: 'data(label)',
            'font-size': 13,
            'font-family': '"Segoe UI", "Microsoft YaHei", sans-serif',
            color: '#334155',
            'text-valign': 'center',
            'text-halign': 'center',
            'text-wrap': 'ellipsis',
            'text-max-width': '156px',
            width: 180,
            height: 48,
          },
        },
        {
          selector: 'node.focus',
          style: { 'background-color': '#2563eb', color: '#ffffff', 'border-width': 0 },
        },
        {
          selector: 'node.unknown',
          style: {
            'background-color': '#f8fafc',
            'border-color': '#64748b',
            'border-style': 'dashed',
            color: '#475569',
          },
        },
        {
          selector: 'edge',
          style: {
            width: 1.4,
            'line-color': '#64748b',
            'target-arrow-color': '#64748b',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            label: 'data(label)',
            'font-size': 12,
            'font-family': '"Segoe UI", "Microsoft YaHei", sans-serif',
            color: '#475569',
            'text-background-color': '#ffffff',
            'text-background-opacity': 1,
            'text-background-padding': '3px',
          },
        },
        { selector: 'edge.inferred, edge.unknown', style: { 'line-style': 'dashed' } },
      ],
    });
    cy.on('tap', 'node', (event) => {
      const id: string = event.target.id();
      if (!id.startsWith('unknown-')) onselect(id);
    });
    const observer = new ResizeObserver(() => {
      cy?.resize();
      cy?.fit(undefined, 45);
    });
    observer.observe(container);
    mounted = true;
    return () => {
      observer.disconnect();
      cy?.destroy();
    };
  });
</script>

<div class="graph-toolbar">
  <span>当前函数的一跳调用关系 · 最多 200 条</span><button
    class="text-button"
    onclick={() => cy?.fit(undefined, 45)}>适应画布</button
  >
</div>
<div class="graph-canvas" bind:this={container} role="img" aria-label="当前函数的局部调用图"></div>
<div class="graph-legend">
  <span><i class="dot accent"></i>当前函数</span><span><i class="dash"></i>推断 / 未解析调用</span><span
    >点击节点查看代码 · 滚轮缩放</span
  >
</div>
