<!--
  DemoPanel.svelte — the ONE connected demo flow (D-01): skim badges →
  passphrase → Derive → live stopwatch. This is Task 1's scaffold (39-02) —
  Encrypt/hex-grid/tamper/OOM-state/economics/post-demo-CTA land in Task 2.

  D-04/Phase-38 LOCKED structural contract, carried forward verbatim from the
  Phase-38 App.svelte shell (this panel now owns the only passphrase input on
  the page): type="text" ONLY, no <form> anywhere on the page, no submit
  control, autocomplete="off", name/id free of every credential token
  (user/email/pass/login/secret/identifier) AND clear of
  apps/extension/src/lib/fieldDetection.ts's STRONG_USERNAME_PATTERN —
  `demo-vault-value` is reused UNCHANGED from the Phase-38 shell (deliberately
  NOT `demo-passphrase-*`, which contains "pass"). Value is pre-filled and
  visible, and stays editable (D-04: re-runnable with the visitor's own words).
-->
<script lang="ts">
  import { derive } from '../demo/useCryptoWorker';
  import Stopwatch from './Stopwatch.svelte';

  let passphrase = $state('correct horse battery staple');

  type Phase = 'idle' | 'deriving' | 'derived';
  let phase = $state<Phase>('idle');
  let finalElapsedMs = $state<number | null>(null);

  async function handleDerive(): Promise<void> {
    // D-02: this is the ONLY place derive() is ever called — exclusively from
    // this explicit click handler, never on mount/idle.
    phase = 'deriving';
    finalElapsedMs = null;
    try {
      const result = await derive(passphrase);
      finalElapsedMs = result.elapsedMs;
      phase = 'derived';
    } catch {
      // OOM/error-state UI lands in Task 2 (D-05) — fail safe back to idle
      // rather than leaving the UI stuck showing a live stopwatch forever.
      phase = 'idle';
    }
  }
</script>

<section
  class="mx-auto w-full max-w-3xl rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface p-6 shadow-cryptiq-panel sm:p-8"
>
  <!-- Skim-badge row (D-01) — accent-BORDERED (not filled), calm, Emphasis-size. -->
  <div class="mb-6 flex flex-wrap gap-2.5" aria-label="What this demo proves">
    {#each ['256 MB', 'tamper-evident', 'fresh nonce'] as badge (badge)}
      <span
        class="rounded-full border border-cryptiq-accent px-3 py-1 text-emphasis text-cryptiq-accent"
      >
        {badge}
      </span>
    {/each}
  </div>

  <label for="demo-vault-value" class="mb-2 block text-body font-medium text-cryptiq-fg">
    Passphrase — edit it, it's yours
  </label>
  <div class="flex flex-col gap-3 sm:flex-row">
    <input
      type="text"
      name="demo-vault-value"
      id="demo-vault-value"
      autocomplete="off"
      class="w-full flex-1 rounded-cryptiq border border-cryptiq-border-strong bg-cryptiq-surface-2 px-3.5 py-2.5 font-mono text-body text-cryptiq-fg"
      bind:value={passphrase}
    />
    <button
      type="button"
      onclick={() => void handleDerive()}
      disabled={phase === 'deriving' || passphrase.length === 0}
      class="shrink-0 rounded-cryptiq bg-cryptiq-accent px-5 py-2.5 text-body font-semibold text-cryptiq-accent-fg transition-colors hover:bg-cryptiq-accent-hover disabled:cursor-not-allowed disabled:opacity-40"
    >
      Derive
    </button>
  </div>

  {#if phase === 'idle'}
    <div class="mt-6 rounded-cryptiq border border-dashed border-cryptiq-border p-5">
      <p class="text-body font-medium text-cryptiq-fg">Nothing's happened yet.</p>
      <p class="mt-1.5 text-body text-cryptiq-fg-muted">
        Type your own passphrase above, then click Derive to run the real Argon2id key
        derivation — 256 MiB, 3 passes — right here in your browser.
      </p>
    </div>
  {/if}

  {#if phase === 'deriving' || phase === 'derived'}
    <div class="mt-5 flex items-center gap-3">
      <Stopwatch running={phase === 'deriving'} finalMs={finalElapsedMs} />
      <span class="text-body text-cryptiq-fg-muted">256 MiB / 3 passes — one guess.</span>
    </div>
  {/if}
</section>
