<!--
  SyncNowButton.svelte — Circular-arrows header icon button for Sync Now (D-04, Phase 12).

  SYNC-01 SC-1: the button is DISABLED while the vault is locked.
  D-04: circular-arrows icon button (size-8, rounded-cryptiq, bg-cryptiq-accent), hidden when
    zero peers are paired (the Settings → Sync section hosts "Pair a device" in that case).
  D-06: a $effect auto-starts the sync listener when unlocked+paired and stops it on lock.
  D-10: the button shows an animate-spin spinner while the sync is in-flight (isSyncInProgress).
  D-19: the master password is ALWAYS re-derived via vaultSession.verifyMasterPassword (Argon2id
    ~1s) on EVERY sync — never cached. Bytes are zeroed in `finally` on EVERY exit path.

  SECURITY:
    - `disabled={isDisabled}` enforces SYNC-01 SC-1 (T-10-18 / T-12-23).
    - D-19 always-re-derive + no-caching: the password bytes are owned exclusively by
      `handleConfirmSync`. They are encoded at call time via TextEncoder, passed to
      vaultSession.verifyMasterPassword(passwordBytes) (Argon2id re-derive), then to
      runSyncNow(configDir, passwordBytes), and zeroed via passwordBytes.fill(0) in the
      `finally` block on EVERY exit path (success, verify-fail, throw, cancel).
    - The bytes NEVER enter MasterRePromptModal. The modal is generic dialog chrome
      (backdrop + card + focus trap + Escape-cancel + {@render children()}). SyncNowButton
      passes its OWN password form as the children snippet. This keeps the password bytes
      strictly within SyncNowButton's lexical scope.
    - WHY NOT ConfirmMasterPassword: ConfirmMasterPassword has `onConfirmed: () => Promise<void>` —
      it verifies internally and zeroes its own bytes in `finally` BEFORE calling onConfirmed()
      with NO arguments. Because runSyncNow(configDir, passwordBytes) needs the live password
      bytes for the SYNC-05 peer auth check, ConfirmMasterPassword cannot supply them. Wrapping
      it would require caching the bytes externally — violating D-19. The modal-as-chrome pattern
      is the only approach that satisfies both the accessible dialog requirement and the
      no-bytes-in-modal / no-caching invariant simultaneously.
    - The master password is NEVER cached or stored in any module-level state.
    - No counts, entry titles, or passwords are rendered in this component (UI-18 fence).

  Source: 12-04-PLAN.md Task 2, 10-05-PLAN.md Tasks 2+3, 10-CONTEXT.md D-03/D-04/D-06,
    12-CONTEXT.md D-04/D-10/D-19, 12-UI-SPEC.md §"Sync Now button states", SYNC-01 SC-1.
-->
<script lang="ts">
  import { vaultSession } from '../state/vault.svelte';
  import { pairingStore } from '../sync/PairingStore.svelte';
  import { syncStore } from '../sync/SyncStore.svelte';
  import {
    runSyncNow,
    startSyncListenerIfPaired,
    stopSyncListener,
  } from '../sync/syncOrchestration';
  import { isSyncInProgress } from '../sync/syncLockState';
  import { SYNC_ICON_PATH } from '../sync/icons';
  import MasterRePromptModal from '../sync/MasterRePromptModal.svelte';

  type Props = {
    /** Tauri app config directory (passed to Rust sync commands). */
    configDir: string;
    /** Filesystem path to the vault file (Rust listener reads this to serve B's blob). */
    vaultPath: string;
  };

  let { configDir, vaultPath }: Props = $props();

  // ── Re-prompt state ──────────────────────────────────────────────────────────
  // showRePrompt controls whether MasterRePromptModal is visible.
  let showRePrompt = $state(false);

  // The typed password (transient — zeroed in finally after use, never persisted).
  // Using $state for plain UI-form text (not vault key bytes — safe to proxy here).
  let password = $state('');

  // Re-prompt status
  let promptError = $state<string | null>(null);
  let promptSubmitting = $state(false);

  // ── Derived: hasPeer ─────────────────────────────────────────────────────────
  // True when at least one peer is paired. The button is HIDDEN when false (D-04).
  const hasPeer = $derived(pairingStore.peers.length > 0);

  // ── Derived: spinning ───────────────────────────────────────────────────────
  // True when a sync is in-flight — drives the spinner/icon swap (D-10).
  const spinning = $derived(isSyncInProgress(syncStore.status));

  // ── Button disabled expression (SYNC-01 SC-1 / D-19) ────────────────────────
  // Disabled when: vault is locked OR a sync is already in progress.
  const isDisabled = $derived(!vaultSession.isUnlocked || spinning);

  // ── D-06 Listener lifecycle $effect ─────────────────────────────────────────
  //
  // Auto-start the sync listener when unlocked AND a peer is paired (D-06).
  // Auto-stop when the vault locks (D-06 close-on-lock).
  //
  // The $effect runs when either isUnlocked or hasPeer changes. The
  // startSyncListenerIfPaired helper guards against double-start via
  // syncStore.listenerActive. stopSyncListener is idempotent.
  $effect(() => {
    if (vaultSession.isUnlocked && hasPeer) {
      // Unlock + peer present → start the listener (D-06).
      void startSyncListenerIfPaired(configDir, vaultPath);
    } else {
      // Locked (or no peer) → stop the listener (D-06 close-on-lock).
      void stopSyncListener();
    }
  });

  // ── Button click: open the re-prompt ────────────────────────────────────────
  function handleSyncClick(): void {
    if (isDisabled) return;
    // Reset any prior sync error and re-prompt state before showing the prompt.
    syncStore.reset();
    promptError = null;
    password = '';
    showRePrompt = true;
  }

  // ── Re-prompt cancel ────────────────────────────────────────────────────────
  function handleCancel(): void {
    showRePrompt = false;
    password = '';
    promptError = null;
  }

  // ── Re-prompt submit: D-19 always-re-derive + no-caching ────────────────────
  //
  // ORDER (D-19 invariant — MUST NOT be altered):
  //   1. Encode the typed password as UTF-8 bytes at call time.
  //   2. vaultSession.verifyMasterPassword(bytes) — re-derives Argon2id against
  //      THIS vault's params. A wrong password returns false; do NOT connect.
  //   3. Only after local verify passes: call runSyncNow(configDir, bytes).
  //      runSyncNow is the D-05 orchestration layer — Noise IK connect + blob
  //      exchange + SYNC-05 auth check. B's vault key is secureWiped inside it.
  //   4. Zero password bytes in finally on EVERY exit path (D-19 / no caching).
  //
  // SECURITY:
  //   - passwordBytes.fill(0) in finally — no plaintext bytes linger (D-19).
  //   - No master password caching at any scope (D-19 / T-10-19).
  //   - runSyncNow returns void; B's vault key is secureWiped inside it (T-10-24).
  //   - The bytes never enter MasterRePromptModal (modal holds no password state).
  async function handleConfirmSync(): Promise<void> {
    if (promptSubmitting || password.length === 0) return;
    promptSubmitting = true;
    promptError = null;

    // Encode at call time — do NOT retain the plaintext beyond this handler (D-19).
    const passwordBytes = new TextEncoder().encode(password);

    try {
      // Step 1 — D-19 LOCAL-VERIFY-BEFORE-CONNECT:
      // Re-derive Argon2id against THIS vault's params and tryUnwrap the master wrap.
      // A null/false result means the password is wrong — re-show the prompt, do NOT connect.
      const locallyVerified = await vaultSession.verifyMasterPassword(passwordBytes);
      if (!locallyVerified) {
        // Wrong password: re-show the re-prompt. Do NOT call runSyncNow or connect.
        promptError = 'That password is incorrect. Please try again.';
        return; // finally still runs — passwordBytes zeroed
      }

      // Step 2 — D-19 gate passed: close the re-prompt and proceed to connect.
      showRePrompt = false;
      password = '';

      // Step 3 — Run the initiator flow (runSyncNow is invoked ONLY after local verify).
      // runSyncNow: connects → IK handshake → binding check → recv B's blob → SYNC-05 auth.
      // B's vault key is secureWiped inside runSyncNow before it returns (T-10-24).
      await runSyncNow(configDir, passwordBytes);
    } catch {
      // runSyncNow throws typed errors (SyncPeerUnreachableError, SyncBindingMismatchError, etc.).
      // syncStore.lastError is already set by runSyncNow's catch path.
      // Do NOT re-throw: the error is displayed via SyncErrorAlert in MainView.
    } finally {
      // Zero the password bytes on EVERY exit path (D-19 / no caching / T-10-19).
      // This runs even if verifyMasterPassword throws or runSyncNow throws.
      passwordBytes.fill(0);
      promptSubmitting = false;
    }
  }

  function handleKeydown(e: KeyboardEvent): void {
    if (e.key === 'Enter') {
      void handleConfirmSync();
    } else if (e.key === 'Escape') {
      handleCancel();
    }
  }
</script>

<!--
  D-04: button is HIDDEN entirely when zero peers are paired.
  SYNC-01 SC-1: disabled while locked or sync is in progress.
-->
{#if hasPeer}
  <button
    type="button"
    onclick={handleSyncClick}
    disabled={isDisabled}
    aria-label={spinning ? 'Sync in progress' : 'Sync Now'}
    aria-disabled={spinning ? 'true' : undefined}
    title="Sync Now"
    class="grid size-8 shrink-0 place-items-center rounded-cryptiq bg-cryptiq-accent text-cryptiq-accent-fg
           transition-colors hover:bg-cryptiq-accent-hover outline-none
           focus-visible:ring-2 focus-visible:ring-cryptiq-ring
           disabled:cursor-not-allowed disabled:opacity-50"
  >
    {#if spinning}
      <!-- Spinner (D-10 / D-13) — animate-spin with reduced-motion guard via .sync-spinner -->
      <svg
        class="size-4 animate-spin sync-spinner"
        viewBox="0 0 24 24"
        fill="none"
        aria-hidden="true"
      >
        <!-- Background track -->
        <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2.5" class="opacity-20" />
        <!-- Spinning arc (1/4 of circumference) -->
        <path
          d="M22 12a10 10 0 0 0-10-10"
          stroke="currentColor"
          stroke-width="2.5"
          stroke-linecap="round"
        />
      </svg>
    {:else}
      <!-- Circular-arrows sync icon (D-04) — same path as Sidebar "Needs update" filter -->
      <svg class="size-4" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
        <path d={SYNC_ICON_PATH} />
      </svg>
    {/if}
  </button>
{/if}

<!--
  D-19 master re-prompt modal.
  MasterRePromptModal provides the dialog chrome (backdrop, card, focus trap, Escape-cancel).
  The password form is passed as the children snippet — the bytes stay in THIS component.
  The modal holds NO password bytes and performs NO crypto (see top-of-file rationale).
-->
{#if showRePrompt}
  <MasterRePromptModal onCancelled={handleCancel}>
    {#snippet children()}
      <!-- Password input -->
      <div class="space-y-1.5">
        <label for="sync-master-pw" class="text-meta font-medium text-cryptiq-fg">
          Master password
        </label>
        <input
          id="sync-master-pw"
          type="password"
          autocomplete="current-password"
          bind:value={password}
          disabled={promptSubmitting}
          onkeydown={handleKeydown}
          placeholder="Enter your master password"
          class="w-full rounded-cryptiq border border-cryptiq-border-strong bg-cryptiq-surface-2
                 px-3 py-2 text-body text-cryptiq-fg placeholder:text-cryptiq-fg-subtle
                 focus:border-cryptiq-accent focus:outline-none focus:ring-1 focus:ring-cryptiq-ring
                 disabled:opacity-60"
        />
      </div>

      <!-- Wrong-password error (D-19 / UI-SPEC) -->
      {#if promptError !== null}
        <p class="mt-2 text-meta text-cryptiq-danger" role="alert">{promptError}</p>
      {/if}

      <!-- Sync / Cancel actions -->
      <div class="mt-4 flex items-center gap-3">
        <button
          type="button"
          onclick={() => void handleConfirmSync()}
          disabled={promptSubmitting || password.length === 0}
          class="rounded-cryptiq bg-cryptiq-accent px-4 py-2 text-body font-semibold text-cryptiq-accent-fg
                 transition-colors hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {promptSubmitting ? 'Verifying…' : 'Sync'}
        </button>
        <button
          type="button"
          onclick={handleCancel}
          disabled={promptSubmitting}
          class="text-body text-cryptiq-fg-muted transition-colors hover:text-cryptiq-fg disabled:opacity-60"
        >
          Cancel
        </button>
      </div>
    {/snippet}
  </MasterRePromptModal>
{/if}

<style>
  @media (prefers-reduced-motion: reduce) {
    .sync-spinner {
      animation: none;
      opacity: 0.5;
    }
  }
</style>
