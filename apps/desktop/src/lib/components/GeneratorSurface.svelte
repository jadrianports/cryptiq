<!--
  GeneratorSurface.svelte — one engine, two surfaces (P4-12, GEN-05/06).

  variant="popover"    → anchored to the password field in EntryDetail; "Use"
                          fills the field (and EntryDetail pushes the old value
                          to passwordHistory via the core change path, ENTRY-07).
  variant="standalone" → the full Generator screen; can save defaults to vault
                          `settings` or "save as new entry".

  Generation is always via @cryptiq/core CSPRNG — never Math.random (T-04-18).
  The `generate` and `estimateBits` props are injected by the consumer (callback
  injection pattern). This keeps the component testable and ensures the same
  contract is used by both EntryDetail (04-05) and GeneratorScreen (04-06).

  Props:
    generate        — async (opts: GeneratorOptions) => string  (CSPRNG, never Math.random)
    estimateBits    — (opts: GeneratorOptions) => number  (theoretical bits)
    variant         — 'popover' | 'standalone' (layout)
    initialOptions  — optional seed from vault settings.generator (standalone only);
                      used to sync the surface to the user's saved defaults on mount.
    onUse           — popover: fill the password field with this value
    onSaveDefault   — standalone: persist current options to vault settings;
                      receives the current GeneratorOptions so the parent can persist them
    onSaveAsEntry   — standalone: create a new entry seeded with this password
-->
<script lang="ts">
  import type { GeneratorOptions, RandomOptions, PassphraseOptions } from '@cryptiq/core';
  import { DEFAULT_RANDOM_OPTIONS, DEFAULT_PASSPHRASE_OPTIONS } from '@cryptiq/core';

  type Variant = 'popover' | 'standalone';
  type Props = {
    /** Async generator backed by @cryptiq/core CSPRNG. NEVER Math.random. */
    generate: (opts: GeneratorOptions) => Promise<string>;
    /** Theoretical entropy estimator backed by @cryptiq/core estimateEntropyBits. */
    estimateBits: (opts: GeneratorOptions) => number;
    variant?: Variant;
    /**
     * standalone: optional seed from vault settings.generator.
     * When provided, the surface initialises its controls to match the saved defaults
     * so the standalone screen reflects the user's stored preferences on open.
     */
    initialOptions?: GeneratorOptions | undefined;
    /** popover: fill the password field with this value. */
    onUse?: (value: string) => void;
    /**
     * standalone: persist current options to vault settings.
     * Receives the current GeneratorOptions so the parent (GeneratorScreen) can
     * write them to vault settings.generator without needing a secondary state mirror.
     */
    onSaveDefault?: (opts: GeneratorOptions) => void;
    /** standalone: create a new entry seeded with this password. */
    onSaveAsEntry?: (value: string) => void;
  };
  let {
    generate,
    estimateBits,
    variant = 'popover',
    initialOptions,
    onUse,
    onSaveDefault,
    onSaveAsEntry,
  }: Props = $props();

  // ── Options (bound to the form controls) ────────────────────────────────
  // Seeded from initialOptions (vault settings.generator) when provided;
  // falls back to the core defaults. This lets the standalone screen reflect
  // the user's saved preferences without modifying the popover variant.
  //
  // We read initialOptions once here to derive the seed values and pass them
  // directly as $state initialisers (mount-time seed — intentional snapshot).
  // The helper is called inline to avoid the Svelte "captures initial value"
  // diagnostic on intermediate local consts.
  function _seedMode(): 'random' | 'passphrase' {
    return initialOptions?.mode ?? 'random';
  }
  function _seedR<K extends keyof import('@cryptiq/core').RandomOptions>(
    k: K,
  ): import('@cryptiq/core').RandomOptions[K] {
    const s = initialOptions?.mode === 'random' ? initialOptions : null;
    return (s?.[k] ?? DEFAULT_RANDOM_OPTIONS[k]) as import('@cryptiq/core').RandomOptions[K];
  }
  function _seedRC<K extends keyof import('@cryptiq/core').RandomOptions['classes']>(
    k: K,
  ): boolean {
    const s = initialOptions?.mode === 'random' ? initialOptions : null;
    return s?.classes[k] ?? DEFAULT_RANDOM_OPTIONS.classes[k];
  }
  function _seedP<K extends keyof import('@cryptiq/core').PassphraseOptions>(
    k: K,
  ): import('@cryptiq/core').PassphraseOptions[K] {
    const s = initialOptions?.mode === 'passphrase' ? initialOptions : null;
    return (s?.[k] ?? DEFAULT_PASSPHRASE_OPTIONS[k]) as import('@cryptiq/core').PassphraseOptions[K];
  }

  let mode = $state<'random' | 'passphrase'>(_seedMode());

  // Random options (mirrors DEFAULT_RANDOM_OPTIONS from @cryptiq/core)
  let length = $state(_seedR('length'));
  let classLower = $state(_seedRC('lowercase'));
  let classUpper = $state(_seedRC('uppercase'));
  let classDigits = $state(_seedRC('digits'));
  let classSymbols = $state(_seedRC('symbols'));
  let avoidAmbiguous = $state(_seedR('avoidAmbiguous'));

  // Passphrase options (mirrors DEFAULT_PASSPHRASE_OPTIONS from @cryptiq/core)
  let words = $state(_seedP('words'));
  let separator = $state(_seedP('separator'));
  let capitalize = $state(_seedP('capitalize'));
  let appendDigit = $state(_seedP('appendDigit'));

  // ── Build the GeneratorOptions union from form state ─────────────────────
  const opts = $derived<GeneratorOptions>(
    mode === 'random'
      ? ({
          mode: 'random',
          length,
          classes: { lowercase: classLower, uppercase: classUpper, digits: classDigits, symbols: classSymbols },
          avoidAmbiguous,
        } satisfies RandomOptions)
      : ({
          mode: 'passphrase',
          words,
          separator,
          capitalize,
          appendDigit,
        } satisfies PassphraseOptions),
  );

  // ── Generated output (updates whenever options change, via regenerate()) ─
  let output = $state('');
  let generating = $state(false);
  let copied = $state(false);

  // Auto-regenerate when opts change.
  $effect(() => {
    // Access opts to create a dependency so $effect re-runs when they change.
    const _o = opts;
    void regenerate(_o);
  });

  async function regenerate(currentOpts: GeneratorOptions = opts) {
    generating = true;
    try {
      output = await generate(currentOpts);
    } finally {
      generating = false;
    }
  }

  // ── Entropy ──────────────────────────────────────────────────────────────
  const bits = $derived(estimateBits(opts));
  const strength = $derived.by(() => {
    if (bits < 60) return { label: 'Weak', tone: 'bg-cryptiq-danger', text: 'text-cryptiq-danger' };
    if (bits < 80) return { label: 'Fair', tone: 'bg-cryptiq-attention', text: 'text-cryptiq-fg-muted' };
    if (bits < 120) return { label: 'Strong', tone: 'bg-cryptiq-success', text: 'text-cryptiq-success' };
    return { label: 'Excellent', tone: 'bg-cryptiq-accent', text: 'text-cryptiq-accent' };
  });
  const meterPct = $derived(Math.min(100, Math.round((bits / 128) * 100)));

  async function copyOutput() {
    // Visual feedback only — real copy is handled by the consumer's onUse or
    // the per-field copy path (UI-06). We write to clipboard only from copyField.ts.
    // The standalone generator screen wires its own copy via copyField (04-06).
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
    <p
      class="font-mono text-emphasis leading-snug break-all text-cryptiq-fg {generating ? 'opacity-50' : ''}"
      aria-live="polite"
    >
      {output || '…'}
    </p>
    <div class="mt-2.5 flex items-center justify-between">
      <!-- Strength meter -->
      <span class="flex items-center gap-2">
        <span class="h-1.5 w-24 overflow-hidden rounded-full bg-cryptiq-border" aria-hidden="true">
          <span class="block h-full rounded-full {strength.tone} transition-all duration-300" style="width:{meterPct}%"></span>
        </span>
        <span class="text-meta font-medium {strength.text}">{strength.label} · {Math.round(bits)} bits</span>
      </span>
      <span class="flex items-center gap-1">
        <button
          type="button"
          onclick={() => regenerate()}
          disabled={generating}
          title="Regenerate"
          aria-label="Regenerate"
          class="grid size-7 place-items-center rounded-cryptiq text-cryptiq-fg-muted transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-fg disabled:opacity-50"
        >
          <svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
            <path d="M3 12a9 9 0 0 1 15.5-6.3L21 8" /><path d="M21 3v5h-5" />
            <path d="M21 12a9 9 0 0 1-15.5 6.3L3 16" /><path d="M3 21v-5h5" />
          </svg>
        </button>
        <button
          type="button"
          onclick={copyOutput}
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
      {#each [
        { key: 'lower', label: 'a-z', get: () => classLower, set: (v: boolean) => { classLower = v; } },
        { key: 'upper', label: 'A-Z', get: () => classUpper, set: (v: boolean) => { classUpper = v; } },
        { key: 'digits', label: '0-9', get: () => classDigits, set: (v: boolean) => { classDigits = v; } },
        { key: 'symbols', label: '!@#', get: () => classSymbols, set: (v: boolean) => { classSymbols = v; } },
        { key: 'ambiguous', label: 'No look-alikes', get: () => avoidAmbiguous, set: (v: boolean) => { avoidAmbiguous = v; } },
      ] as item (item.key)}
        <button
          type="button"
          aria-pressed={item.get()}
          onclick={() => item.set(!item.get())}
          class="rounded-cryptiq border px-2.5 py-1 text-meta font-medium transition-colors
                 {item.get()
            ? 'border-cryptiq-accent bg-cryptiq-selected text-cryptiq-accent'
            : 'border-cryptiq-border text-cryptiq-fg-muted hover:border-cryptiq-border-strong'}"
        >
          {item.label}
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
          onclick={() => (separator = value as string)}
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
          type="button" aria-pressed={appendDigit} onclick={() => (appendDigit = !appendDigit)}
          class="rounded-cryptiq border px-2.5 py-1 text-meta font-medium transition-colors
                 {appendDigit ? 'border-cryptiq-accent bg-cryptiq-selected text-cryptiq-accent' : 'border-cryptiq-border text-cryptiq-fg-muted hover:border-cryptiq-border-strong'}"
        >Number</button>
      </span>
    </div>
  {/if}

  <!-- Footer -->
  {#if variant === 'popover'}
    <button
      type="button"
      onclick={() => onUse?.(output)}
      disabled={!output || generating}
      class="rounded-cryptiq bg-cryptiq-accent py-2 text-body font-semibold text-cryptiq-accent-fg transition-colors hover:bg-cryptiq-accent-hover disabled:opacity-50"
    >
      Use this password
    </button>
  {:else}
    <div class="mt-1 flex items-center gap-2">
      <button
        type="button"
        onclick={() => onSaveDefault?.(opts)}
        class="flex-1 rounded-cryptiq border border-cryptiq-border-strong py-2 text-body font-medium text-cryptiq-fg-muted transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-fg"
      >
        Save as default
      </button>
      <button
        type="button"
        onclick={() => onSaveAsEntry?.(output)}
        disabled={!output || generating}
        class="flex-1 rounded-cryptiq bg-cryptiq-accent py-2 text-body font-semibold text-cryptiq-accent-fg transition-colors hover:bg-cryptiq-accent-hover disabled:opacity-50"
      >
        Save as new entry
      </button>
    </div>
  {/if}
</div>
