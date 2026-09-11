<script lang="ts">
  import { Plus, Trash2 } from '@lucide/svelte';
  import { readRuntimeConfig, withRuntimeDefaults } from '../lib/runtime';

  let {
    configJson,
    disabled = false,
    onchange,
  }: {
    configJson: string;
    disabled?: boolean;
    onchange: (json: string) => void;
  } = $props();

  const config = $derived(readRuntimeConfig(configJson));
  const normalized = $derived(config ? withRuntimeDefaults(config) : null);
  const fuzz = $derived((normalized?.fuzz || {}) as Record<string, unknown>);
  const seeds = $derived(Array.isArray(fuzz.seeds) ? fuzz.seeds : []);
  const fields = [
    { key: 'max_cases', label: '最大执行次数', max: 1_000_000 },
    { key: 'budget_seconds', label: '时间预算（秒）', max: 900 },
    { key: 'timeout_seconds', label: '单次超时（秒）', max: 15 },
    { key: 'random_seed', label: '随机种子', max: Number.MAX_SAFE_INTEGER },
  ];

  function update(key: string, value: unknown) {
    if (!config) return;
    onchange(
      JSON.stringify(
        key === 'path' || key === 'timeout_seconds'
          ? { ...config, [key]: value }
          : { ...config, fuzz: { ...fuzz, [key]: value } },
        null,
        2,
      ),
    );
  }

  function updateSeed(index: number, value: string) {
    update(
      'seeds',
      seeds.map((seed, position) => (position === index ? value : seed)),
    );
  }
</script>

<fieldset class="fuzz-fields" disabled={disabled || !config}>
  <legend>libFuzzer 配置</legend>
  <label class="field">
    目标入口（快照内 EXE）
    <input
      value={typeof config?.path === 'string' ? config.path : ''}
      oninput={(event) => update('path', event.currentTarget.value)}
      spellcheck="false"
      required
    />
  </label>
  <div class="fuzz-numbers">
    {#each fields as field}
      {@const value = field.key === 'timeout_seconds' ? normalized?.timeout_seconds : fuzz[field.key]}
      <label class="field">
        {field.label}
        <input
          type="number"
          min="1"
          max={field.max}
          step="1"
          value={typeof value === 'number' ? value : ''}
          oninput={(event) => update(field.key, event.currentTarget.valueAsNumber)}
          required
        />
      </label>
    {/each}
  </div>
  <div class="seed-heading">
    <h3>初始种子 <span>{seeds.length} / 32</span></h3>
    <button
      type="button"
      class="button secondary small"
      disabled={seeds.length >= 32}
      onclick={() => update('seeds', [...seeds, ''])}
      title="添加 UTF-8 文本种子"><Plus size={15} />添加种子</button
    >
  </div>
  <div class="fuzz-seeds">
    {#each seeds as seed, index}
      <div class="fuzz-seed">
        <label class="field">
          种子 {index + 1}（UTF-8）
          <textarea
            rows="2"
            value={typeof seed === 'string' ? seed : ''}
            oninput={(event) => updateSeed(index, event.currentTarget.value)}
            spellcheck="false"
            required
          ></textarea>
        </label>
        <button
          type="button"
          class="button secondary small remove-seed"
          aria-label={`移除种子 ${index + 1}`}
          title={`移除种子 ${index + 1}`}
          disabled={seeds.length <= 1}
          onclick={() =>
            update(
              'seeds',
              seeds.filter((_, position) => position !== index),
            )}><Trash2 size={15} /></button
        >
      </div>
    {/each}
  </div>
</fieldset>

<style>
  .fuzz-fields {
    display: grid;
    gap: 16px;
    min-width: 0;
    border: 0;
    padding: 0;
    margin: 0;
  }
  .fuzz-fields legend {
    margin-bottom: 14px;
    font-weight: 600;
    color: var(--ink);
  }
  .fuzz-numbers {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 14px 20px;
  }
  .seed-heading {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 10px;
  }
  .seed-heading h3 {
    font-size: var(--text-base);
  }
  .seed-heading span {
    font-weight: 400;
    color: var(--muted);
    margin-left: 6px;
  }
  .fuzz-seeds {
    display: grid;
    gap: 12px;
  }
  .fuzz-seed {
    display: grid;
    grid-template-columns: minmax(0, 1fr) 34px;
    align-items: end;
    gap: 10px;
  }
  .remove-seed {
    width: 34px;
    height: 34px;
    padding: 0;
    margin-bottom: 2px;
  }
  .field {
    min-width: 0;
    margin: 0;
  }
  .field input,
  .field textarea {
    width: 100%;
    min-width: 0;
  }
  .field textarea {
    resize: vertical;
    font-family: var(--font-mono, monospace);
  }
  @media (max-width: 600px) {
    .fuzz-numbers {
      grid-template-columns: minmax(0, 1fr);
    }
  }
</style>
