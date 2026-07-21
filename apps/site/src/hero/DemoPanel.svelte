<!--
  DemoPanel.svelte — the ONE connected demo flow (D-01), top-to-bottom: skim
  badges → passphrase → Derive → live stopwatch → per-guess economics →
  Encrypt (twice, side-by-side) → click-any-byte tamper → OOM state →
  post-demo CTA.

  D-04/Phase-38 LOCKED structural contract, carried forward verbatim from the
  Phase-38 App.svelte shell (this panel now owns the only passphrase input on
  the page): type="text" ONLY, no <form> anywhere on the page, no submit
  control, autocomplete="off", name/id free of every credential token
  (user/email/pass/login/secret/identifier) AND clear of
  apps/extension/src/lib/fieldDetection.ts's STRONG_USERNAME_PATTERN —
  `demo-vault-value` is reused UNCHANGED from the Phase-38 shell (deliberately
  NOT `demo-passphrase-*`, which contains "pass"). Value is pre-filled and
  visible, and stays editable (D-04: re-runnable with the visitor's own words).

  DOC CORRECTION carried from 39-01/39-RESEARCH.md Pitfall 4: there is NO
  AeadAuthError class in packages/core. The tamper-fail state below renders
  the REAL VaultCorruptError / VAULT_CORRUPT surfaced by the Worker — never a
  paraphrase, never the nonexistent class name.
-->
<script lang="ts">
  import { derive, encrypt, decrypt, CryptoWorkerError } from '../demo/useCryptoWorker';
  import Stopwatch from './Stopwatch.svelte';
  import HexGrid from './HexGrid.svelte';

  let passphrase = $state('correct horse battery staple');

  type Phase = 'idle' | 'deriving' | 'derived' | 'oom';
  let phase = $state<Phase>('idle');
  let finalElapsedMs = $state<number | null>(null);
  let oomMessage = $state<string | null>(null);

  type CipherGrid = { ciphertext: Uint8Array; nonce: Uint8Array };
  let grids = $state<CipherGrid[]>([]);
  let encrypting = $state(false);
  let tamperResult = $state<{ gridIndex: number; byteIndex: number; code: string; name: string } | null>(
    null,
  );

  // D-17: the earned post-demo CTA — only once a derive succeeded AND a real
  // tamper-fail has actually been observed through the rendered grid.
  const showPostDemoCta = $derived(phase === 'derived' && tamperResult !== null);

  // D-08: per-guess attacker economics, extrapolated HONESTLY from the just-
  // MEASURED per-guess cost — a conservative, single-lane (non-parallelized)
  // basis for a hypothetical billion-guess (1e9) offline attack at the SAME
  // cost this browser just paid. Not an inflated marketing number.
  const billionGuessSeconds = $derived(
    finalElapsedMs !== null ? (finalElapsedMs / 1000) * 1_000_000_000 : null,
  );

  function formatDuration(totalSeconds: number): string {
    const years = totalSeconds / (365.25 * 24 * 3600);
    if (years >= 1) return `~${years.toFixed(1)} years`;
    const days = totalSeconds / 86400;
    if (days >= 1) return `~${days.toFixed(1)} days`;
    const hours = totalSeconds / 3600;
    if (hours >= 1) return `~${hours.toFixed(1)} hours`;
    return `~${totalSeconds.toFixed(0)} seconds`;
  }

  async function handleDerive(): Promise<void> {
    // D-02: this is the ONLY place derive() is ever called — exclusively from
    // this explicit click handler, never on mount/idle. The retry button
    // below calls this SAME function with no memLimit override — [Try again]
    // never lowers the 256 MiB floor (D-05).
    phase = 'deriving';
    finalElapsedMs = null;
    oomMessage = null;
    grids = [];
    tamperResult = null;
    try {
      const result = await derive(passphrase);
      finalElapsedMs = result.elapsedMs;
      phase = 'derived';
    } catch (err) {
      // Any derive failure renders as the OOM/attention state — a plain
      // derive (never given a memLimitOverride here) failing in the real
      // browser almost always means a genuine allocation refusal, which IS
      // the security argument (D-05), not a bug to hide.
      phase = 'oom';
      oomMessage =
        err instanceof CryptoWorkerError
          ? err.message
          : err instanceof Error
            ? err.message
            : 'Derivation failed unexpectedly.';
    }
  }

  async function handleEncrypt(): Promise<void> {
    encrypting = true;
    tamperResult = null;
    try {
      // DEMO-06: same plaintext, encrypted twice under the SAME derived key —
      // sealData's fresh-nonce-per-call guarantee (packages/core) means the
      // two ciphertexts differ even though nothing else changed.
      const plaintext = new TextEncoder().encode('Cryptiq demo ciphertext');
      const first = await encrypt(plaintext.slice());
      const second = await encrypt(plaintext.slice());
      grids = [first, second];
    } finally {
      encrypting = false;
    }
  }

  async function handleByteClick(gridIndex: number, byteIndex: number): Promise<void> {
    const grid = grids[gridIndex];
    if (!grid) return;
    // D-03: flip ONE byte in a LOCAL copy — the original ciphertext in
    // `grids` is never mutated, so every cell click is independently
    // falsifiable from the same starting ciphertext.
    const mutated = new Uint8Array(grid.ciphertext);
    mutated[byteIndex] = mutated[byteIndex]! ^ 0xff;
    try {
      await decrypt(mutated, grid.nonce);
      // A tampered ciphertext decrypting successfully would be a genuine
      // crypto bug, not a UI concern — intentionally no fabricated failure
      // state here; tamperResult simply stays whatever it already was.
    } catch (err) {
      if (err instanceof CryptoWorkerError) {
        // The REAL surfaced error is VAULT_CORRUPT / VaultCorruptError —
        // never AeadAuthError (39-RESEARCH.md Pitfall 4; no such class
        // exists in packages/core).
        tamperResult = { gridIndex, byteIndex, code: err.code, name: err.name };
      }
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

  <!-- Per-guess attacker economics (D-08) -->
  {#if phase === 'derived' && finalElapsedMs !== null && billionGuessSeconds !== null}
    <p class="mt-3 text-emphasis text-cryptiq-fg">
      That was {(finalElapsedMs / 1000).toFixed(2)}s and 256 MB for ONE guess. A GPU farm
      trying a billion guesses at that same per-guess cost needs {formatDuration(
        billionGuessSeconds,
      )} — that's the wall Argon2id builds.
    </p>
  {/if}

  <!-- OOM state (D-05) — attention, NOT danger; "argument, not a bug" -->
  {#if phase === 'oom'}
    <div class="mt-5 rounded-cryptiq border border-cryptiq-attention bg-cryptiq-surface-2 p-4">
      <p class="text-body text-cryptiq-fg">
        Couldn't allocate 256 MB. That's the argument, not a bug — an attacker's device needs
        the same allocation, every single guess.
      </p>
      {#if oomMessage}
        <p class="mt-1.5 font-mono text-meta text-cryptiq-fg-subtle">KDF_RESOURCE: {oomMessage}</p>
      {/if}
      <button
        type="button"
        onclick={() => void handleDerive()}
        class="mt-3 rounded-cryptiq border border-cryptiq-attention px-4 py-2 text-body font-semibold text-cryptiq-attention transition-colors hover:bg-cryptiq-attention/10"
      >
        Try again
      </button>
    </div>
  {/if}

  <!-- Encrypt action + encrypt-twice hex grids (DEMO-06) -->
  {#if phase === 'derived'}
    <div class="mt-6">
      <button
        type="button"
        onclick={() => void handleEncrypt()}
        disabled={encrypting}
        class="rounded-cryptiq bg-cryptiq-accent px-5 py-2.5 text-body font-semibold text-cryptiq-accent-fg transition-colors hover:bg-cryptiq-accent-hover disabled:cursor-not-allowed disabled:opacity-40"
      >
        Encrypt
      </button>

      {#if grids.length === 2}
        <p class="mt-3 text-body text-cryptiq-fg-muted">
          Same plaintext, encrypted twice. Fresh nonce each run — click any byte below to
          break it.
        </p>
        <div class="mt-3 grid grid-cols-1 gap-4 sm:grid-cols-2">
          {#each grids as grid, gridIndex (gridIndex)}
            <div>
              <p class="mb-1.5 text-meta font-medium text-cryptiq-fg-subtle">Run {gridIndex + 1}</p>
              <HexGrid
                bytes={grid.ciphertext}
                tamperedIndex={tamperResult && tamperResult.gridIndex === gridIndex
                  ? tamperResult.byteIndex
                  : null}
                onCellClick={(byteIndex) => void handleByteClick(gridIndex, byteIndex)}
              />
              {#if tamperResult && tamperResult.gridIndex === gridIndex}
                <div class="mt-2 rounded-cryptiq border border-cryptiq-danger-border bg-cryptiq-danger-surface p-3">
                  <p class="text-body text-cryptiq-danger">
                    Tampered. Decryption failed — exactly as it should.
                  </p>
                  <!-- The REAL surfaced error — VAULT_CORRUPT / VaultCorruptError.
                       There is no AeadAuthError class anywhere in packages/core
                       (39-RESEARCH.md Pitfall 4) — this must never read that name. -->
                  <p class="mt-1 font-mono text-meta text-cryptiq-danger">
                    {tamperResult.name} / {tamperResult.code}
                  </p>
                </div>
              {/if}
            </div>
          {/each}
        </div>
      {/if}
    </div>
  {/if}

  <!-- Post-demo CTA (D-17) — earned, not a permanent banner -->
  {#if showPostDemoCta}
    <div class="mt-6 border-t border-cryptiq-border pt-5">
      <a href="#download" class="font-semibold text-cryptiq-accent hover:underline">
        Convinced it's real? Get the desktop app ↓
      </a>
    </div>
  {/if}
</section>
