<!--
  GeneratorSurface.svelte — one engine, two surfaces (P4-12, GEN-05/06).

  variant="popover"    → anchored to the password field in EntryDetail; "Use"
                          fills the field (and the planner pushes the old value
                          to passwordHistory via the core change path, ENTRY-07).
  variant="standalone" → the full Generator screen; can save defaults to vault
                          `settings` or "save as new entry".

  ⚠ DEMO GENERATION ONLY. The sample output below uses a deterministic LCG so
  the reference renders believable strings WITHOUT Math.random (project ban) and
  WITHOUT real entropy. Production MUST generate via @cryptiq/core
  (`randombytes_uniform` + Fisher–Yates) and read bits from `estimateEntropyBits`
  / `computePoolSize` — never compute either in the component.
-->
<script lang="ts">
  type Variant = 'popover' | 'standalone';
  type Props = {
    variant?: Variant;
    /** popover: fill the password field with this value. */
    onUse?: (value: string) => void;
    /** standalone: persist current options to vault `settings`. */
    onSaveDefault?: () => void;
    /** standalone: create a new entry seeded with this password. */
    onSaveAsEntry?: (value: string) => void;
  };
  let { variant = 'popover', onUse, onSaveDefault, onSaveAsEntry }: Props = $props();

  // ── Options ────────────────────────────────────────────────────────────
  let mode = $state<'random' | 'passphrase'>('random');
  let length = $state(20);
  let upper = $state(true);
  let lower = $state(true);
  let digits = $state(true);
  let symbols = $state(true);
  let avoidAmbiguous = $state(true);

  let words = $state(4);
  let separator = $state<'-' | '.' | '_' | ' '>('-');
  let capitalize = $state(true);
  let includeNumber = $state(true);

  let seed = $state(1);
  let copied = $state(false);

  // ── DEMO derivation (see banner) ─────────────────────────────────────────
  const DEMO_CHARS =
    'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*?+=';
  const DEMO_WORDS = [
    'harbor', 'cinder', 'velvet', 'quartz', 'meadow', 'lantern', 'thicket',
    'cobalt', 'ripple', 'almond', 'gravel', 'plume', 'ember', 'willow',
  ];

  function demoRandom(len: number, s: number): string {
    let x = (s * 2654435761) >>> 0;
    let out = '';
    for (let i = 0; i < len; i++) {
      x = (Math.imul(x, 1664525) + 1013904223) >>> 0;
      out += DEMO_CHARS[x % DEMO_CHARS.length];
    }
    return out;
  }
  function demoPassphrase(n: number, s: number): string {
    let x = (s * 40503) >>> 0;
    const picked: string[] = [];
    for (let i = 0; i < n; i++) {
      x = (Math.imul(x, 1664525) + 1013904223) >>> 0;
      let w = DEMO_WORDS[x % DEMO_WORDS.length]!;
      if (capitalize) w = w[0]!.toUpperCase() + w.slice(1);
      picked.push(w);
    }
    let phrase = picked.join(separator);
    if (includeNumber) phrase += separator + ((x % 90) + 10);
    return phrase;
  }

  const output = $derived(
    mode === 'random' ? demoRandom(length, seed) : demoPassphrase(words, seed),
  );

  // ── Entropy (demo estimate) ──────────────────────────────────────────────
  const poolSize = $derived.by(() => {
    let p = 0;
    if (lower) p += avoidAmbiguous ? 24 : 26;
    if (upper) p += avoidAmbiguous ? 24 : 26;
    if (digits) p += avoidAmbiguous ? 8 : 10;
    if (symbols) p += 28;
    return Math.max(p, 1);
  });
  const bits = $derived(
    mode === 'random'
      ? Math.round(length * Math.log2(poolSize))
      : Math.round(words * Math.log2(7776) + (includeNumber ? 9 : 0)),
  );
  const strength = $derived.by(() => {
    if (bits < 60) return { label: 'Weak', tone: 'bg-cryptiq-danger', text: 'text-cryptiq-danger' };
    if (bits < 80) return { label: 'Fair', tone: 'bg-cryptiq-attention', text: 'text-cryptiq-fg-muted' };
    if (bits < 120) return { label: 'Strong', tone: 'bg-cryptiq-success', text: 'text-cryptiq-success' };
    return { label: 'Excellent', tone: 'bg-cryptiq-accent', text: 'text-cryptiq-accent' };
  });
  const meterPct = $derived(Math.min(100, Math.round((bits / 128) * 100)));

  function regenerate() {
    seed = (seed + 7) % 100000;
  }
  function copy() {
    // Visual feedback only — real copy routes through the Tauri clipboard
    // plugin in the wired screen (CONTEXT: per-field copy, UI-06).
    copied = true;
    setTimeout(() => (copied = false), 1500);
  }
</script>

<div
  class="flex flex-col gap-3.5 bg-cryptiq-surface text-cryptiq-fg
         {variant === 'popover'
    ? 'w-80 rounded-cryptiq-lg border border-cryptiq-border p-4 shadow-cryptiq-popover'
    : 'w-full max-w-md rounded-cryptiq-lg border border-cryptiq-border p-6 shadow-cryptiq-panel'}"
  role="group"
  aria-label="Password generator"
>
  <!-- Mode segmented control -->
  <div class="flex rounded-cryptiq bg-cryptiq-surface-2 p-0.5" role="tablist" aria-label="Generator mode">
    {#each [['random', 'Random'], ['passphrase', 'Passphrase']] as [value, label] (value)}
      <button
        type="button"
        role="tab"
        aria-selected={mode === value}
        onclick={() => (mode = value as 'random' | 'passphrase')}
        class="flex-1 rounded-[0.4rem] py-1.5 text-body font-medium transition-colors
               {mode === value
          ? 'bg-cryptiq-surface text-cryptiq-fg shadow-cryptiq-panel'
          : 'text-cryptiq-fg-muted hover:text-cryptiq-fg'}"
      >
        {label}
      </button>
    {/each}
  </div>

  <!-- Output -->
  <div class="rounded-cryptiq border border-cryptiq-border bg-cryptiq-surface-2 p-3">
    <p class="font-mono text-emphasis leading-snug break-all text-cryptiq-fg" aria-live="polite">
      {output}
    </p>
    <div class="mt-2.5 flex items-center justify-between">
      <!-- Strength meter -->
      <span class="flex items-center gap-2">
        <span class="h-1.5 w-24 overflow-hidden rounded-full bg-cryptiq-border" aria-hidden="true">
          <span class="block h-full rounded-full {strength.tone} transition-all duration-300" style="width:{meterPct}%"></span>
        </span>
        <span class="text-meta font-medium {strength.text}">{strength.label} · {bits} bits</span>
      </span>
      <span class="flex items-center gap-1">
        <button
          type="button"
          onclick={regenerate}
          title="Regenerate"
          aria-label="Regenerate"
          class="grid size-7 place-items-center rounded-cryptiq text-cryptiq-fg-muted transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-fg"
        >
          <svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
            <path d="M3 12a9 9 0 0 1 15.5-6.3L21 8" /><path d="M21 3v5h-5" />
            <path d="M21 12a9 9 0 0 1-15.5 6.3L3 16" /><path d="M3 21v-5h5" />
          </svg>
        </button>
        <button
          type="button"
          onclick={copy}
          title="Copy"
          aria-label="Copy password"
          class="grid size-7 place-items-center rounded-cryptiq transition-colors hover:bg-cryptiq-hover
                 {copied ? 'text-cryptiq-success' : 'text-cryptiq-fg-muted hover:text-cryptiq-fg'}"
        >
          {#if copied}
            <svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5" /></svg>
          {:else}
            <svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15V5a2 2 0 0 1 2-2h10" /></svg>
          {/if}
        </button>
      </span>
    </div>
  </div>

  <!-- Options -->
  {#if mode === 'random'}
    <label class="flex items-center justify-between gap-3 text-body text-cryptiq-fg-muted">
      <span>Length</span>
      <span class="flex items-center gap-2.5">
        <input
          type="range" min="8" max="64" bind:value={length}
          class="w-32" style="accent-color: var(--color-cryptiq-accent)"
          aria-label="Password length"
        />
        <span class="w-6 text-right font-mono text-body text-cryptiq-fg">{length}</span>
      </span>
    </label>
    <div class="flex flex-wrap gap-1.5">
      {#each [['upper', 'A-Z'], ['lower', 'a-z'], ['digits', '0-9'], ['symbols', '!@#'], ['avoidAmbiguous', 'No look-alikes']] as [key, label] (key)}
        {@const on =
          key === 'upper' ? upper
          : key === 'lower' ? lower
          : key === 'digits' ? digits
          : key === 'symbols' ? symbols
          : avoidAmbiguous}
        <button
          type="button"
          aria-pressed={on}
          onclick={() => {
            if (key === 'upper') upper = !upper;
            else if (key === 'lower') lower = !lower;
            else if (key === 'digits') digits = !digits;
            else if (key === 'symbols') symbols = !symbols;
            else avoidAmbiguous = !avoidAmbiguous;
          }}
          class="rounded-cryptiq border px-2.5 py-1 text-meta font-medium transition-colors
                 {on
            ? 'border-cryptiq-accent bg-cryptiq-selected text-cryptiq-accent'
            : 'border-cryptiq-border text-cryptiq-fg-muted hover:border-cryptiq-border-strong'}"
        >
          {label}
        </button>
      {/each}
    </div>
  {:else}
    <label class="flex items-center justify-between gap-3 text-body text-cryptiq-fg-muted">
      <span>Words</span>
      <span class="flex items-center gap-2.5">
        <input
          type="range" min="3" max="8" bind:value={words}
          class="w-32" style="accent-color: var(--color-cryptiq-accent)"
          aria-label="Word count"
        />
        <span class="w-6 text-right font-mono text-body text-cryptiq-fg">{words}</span>
      </span>
    </label>
    <div class="flex flex-wrap items-center gap-1.5">
      <span class="text-meta text-cryptiq-fg-muted">Separator</span>
      {#each [['-', '-'], ['.', '.'], ['_', '_'], [' ', '␣']] as [value, label] (value)}
        <button
          type="button"
          aria-pressed={separator === value}
          onclick={() => (separator = value as '-' | '.' | '_' | ' ')}
          class="grid size-7 place-items-center rounded-cryptiq border font-mono text-meta transition-colors
                 {separator === value
            ? 'border-cryptiq-accent bg-cryptiq-selected text-cryptiq-accent'
            : 'border-cryptiq-border text-cryptiq-fg-muted hover:border-cryptiq-border-strong'}"
        >
          {label}
        </button>
      {/each}
      <span class="ml-auto flex gap-1.5">
        <button
          type="button" aria-pressed={capitalize} onclick={() => (capitalize = !capitalize)}
          class="rounded-cryptiq border px-2.5 py-1 text-meta font-medium transition-colors
                 {capitalize ? 'border-cryptiq-accent bg-cryptiq-selected text-cryptiq-accent' : 'border-cryptiq-border text-cryptiq-fg-muted hover:border-cryptiq-border-strong'}"
        >Capitalize</button>
        <button
          type="button" aria-pressed={includeNumber} onclick={() => (includeNumber = !includeNumber)}
          class="rounded-cryptiq border px-2.5 py-1 text-meta font-medium transition-colors
                 {includeNumber ? 'border-cryptiq-accent bg-cryptiq-selected text-cryptiq-accent' : 'border-cryptiq-border text-cryptiq-fg-muted hover:border-cryptiq-border-strong'}"
        >Number</button>
      </span>
    </div>
  {/if}

  <!-- Footer -->
  {#if variant === 'popover'}
    <button
      type="button"
      onclick={() => onUse?.(output)}
      class="rounded-cryptiq bg-cryptiq-accent py-2 text-body font-semibold text-cryptiq-accent-fg transition-colors hover:bg-cryptiq-accent-hover"
    >
      Use this password
    </button>
  {:else}
    <div class="mt-1 flex items-center gap-2">
      <button
        type="button"
        onclick={() => onSaveDefault?.()}
        class="flex-1 rounded-cryptiq border border-cryptiq-border-strong py-2 text-body font-medium text-cryptiq-fg-muted transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-fg"
      >
        Save as default
      </button>
      <button
        type="button"
        onclick={() => onSaveAsEntry?.(output)}
        class="flex-1 rounded-cryptiq bg-cryptiq-accent py-2 text-body font-semibold text-cryptiq-accent-fg transition-colors hover:bg-cryptiq-accent-hover"
      >
        Save as new entry
      </button>
    </div>
  {/if}
</div>
