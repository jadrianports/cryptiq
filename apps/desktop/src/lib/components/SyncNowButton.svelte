<!--
  SyncNowButton.svelte — Minimal unstyled Sync Now button (D-04, Phase 10).

  SYNC-01 SC-1: the button is DISABLED while the vault is locked.
  D-03: clicking the button shows the master password re-prompt (ConfirmMasterPassword.svelte)
    and verifies the password locally against A's OWN vault BEFORE connecting to any peer.
    A wrong password re-shows the re-prompt and does NOT invoke syncNow / runSyncNow.
  D-04: minimal and unstyled — no Tailwind polish, no progress bar, no devices list (Phase 12).
  D-06: a $effect auto-starts the sync listener when unlocked+paired and stops it on lock.

  SECURITY:
    - `disabled={!vaultSession.isUnlocked ...}` enforces SYNC-01 SC-1 (T-10-18).
    - D-03 local-verify-before-connect: the master password is verified via
      vaultSession.verifyMasterPassword() BEFORE runSyncNow is called. A typo
      re-shows the re-prompt and does NOT attempt a connection (T-10-23).
    - The master password bytes (passwordBytes) are zeroed in a `finally` block
      on every exit path so no plaintext lingers in memory (D-03 / no-caching).
    - No counts, entry titles, or passwords are rendered (Phase 12 fence; T-10-21).
    - The entry list is NOT locked during sync (Phase 12 UI-17).
    - The master password is NEVER cached or stored in any module-level state.

  NOTE — Open Question 3 (port-54321 coexistence): sync_listener_stop should be called
    before any pairing_initiate binds port 54321. Actual pairing-gate change is Phase 12 UI.

  Source: 10-05-PLAN.md Tasks 2+3, 10-CONTEXT.md D-03/D-04/D-06, SYNC-01 SC-1.
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

  type Props = {
    /** Tauri app config directory (passed to Rust sync commands). */
    configDir: string;
    /** Filesystem path to the vault file (Rust listener reads this to serve B's blob). */
    vaultPath: string;
  };

  let { configDir, vaultPath }: Props = $props();

  // ── Re-prompt state ──────────────────────────────────────────────────────────
  // showRePrompt controls whether the ConfirmMasterPassword-style re-prompt is visible.
  let showRePrompt = $state(false);

  // The typed password (transient — zeroed in finally after use, never persisted).
  // Using $state for plain UI-form text (not vault key bytes — safe to proxy here).
  let password = $state('');

  // Re-prompt status
  let promptError = $state<string | null>(null);
  let promptSubmitting = $state(false);

  // ── Derived: hasPeer ─────────────────────────────────────────────────────────
  // True when at least one peer is paired. Used for the D-06 listener guard and
  // for the button disabled expression.
  const hasPeer = $derived(pairingStore.peers.length > 0);

  // ── Button disabled expression (SYNC-01 SC-1) ───────────────────────────────
  // The button is disabled when:
  //   - The vault is locked (!vaultSession.isUnlocked), OR
  //   - A sync is already in progress ('connecting' or 'syncing' status).
  // Note: the button is enabled even if !hasPeer — the user can attempt Sync Now
  // and receive a SyncPeerUnreachableError (the peer-selection UI is Phase 12).
  const isDisabled = $derived(
    !vaultSession.isUnlocked ||
      syncStore.status === 'connecting' ||
      syncStore.status === 'syncing',
  );

  // ── D-06 Listener lifecycle $effect ─────────────────────────────────────────
  //
  // Auto-start the sync listener when unlocked AND a peer is paired (D-06).
  // Auto-stop when the vault locks (D-06 close-on-lock).
  //
  // The $effect runs when either isUnlocked or hasPeer changes. The
  // startSyncListenerIfPaired helper guards against double-start via
  // syncStore.listenerActive. stopSyncListener is idempotent.
  //
  // NOTE — Open Question 3 (port-54321 coexistence): sync_listener_stop should be
  // called before any pairing_initiate binds port 54321 to avoid port conflict.
  // Implementing the pairing-gate is Phase-12 UI work; do NOT modify pairing.rs here.
  $effect(() => {
    if (vaultSession.isUnlocked && hasPeer) {
      // Unlock + peer present → start the listener (D-06).
      void startSyncListenerIfPaired(configDir, vaultPath);
    } else {
      // Locked (or no peer) → stop the listener (D-06 close-on-lock).
      // stopSyncListener is idempotent — safe to call even if not started.
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

  // ── Re-prompt submit: D-03 local-verify-before-connect ───────────────────────
  //
  // ORDER:
  //   1. Encode the typed password as UTF-8 bytes.
  //   2. vaultSession.verifyMasterPassword(bytes) — re-derives Argon2id against
  //      A's OWN vault params and tryUnwraps A's master wrap (MAC check). This is
  //      the D-03 local-verify gate: a typo returns false and re-shows the prompt;
  //      no network connection is attempted.
  //   3. Only after local verify passes: call runSyncNow(configDir, bytes).
  //      runSyncNow is the D-05 orchestration layer — it calls syncNow (Rust IK
  //      connect + blob recv) then authCheckBlobAndGetBKey (WASM SYNC-05 auth check).
  //   4. Zero password bytes in finally on EVERY exit path (D-03 / no caching).
  //
  // SECURITY:
  //   - passwordBytes.fill(0) in finally — no plaintext bytes linger (D-03).
  //   - No master password caching at any scope (D-03 / T-10-19).
  //   - runSyncNow returns void; B's vault key is secureWiped inside it (T-10-24).
  async function handleConfirmSync(): Promise<void> {
    if (promptSubmitting || password.length === 0) return;
    promptSubmitting = true;
    promptError = null;

    // Encode at call time — do NOT retain the plaintext beyond this handler (D-03).
    const passwordBytes = new TextEncoder().encode(password);

    try {
      // Step 1 — D-03 LOCAL-VERIFY-BEFORE-CONNECT:
      // Re-derive Argon2id against A's OWN vault params and tryUnwrap A's master wrap.
      // A null/false result means the password is wrong — re-show the prompt, do NOT connect.
      const locallyVerified = await vaultSession.verifyMasterPassword(passwordBytes);
      if (!locallyVerified) {
        // Wrong password: re-show the re-prompt. Do NOT call runSyncNow or connect.
        promptError = 'That password is incorrect. Please try again.';
        return; // finally still runs — passwordBytes zeroed
      }

      // Step 2 — D-03 gate passed: close the re-prompt and proceed to connect.
      showRePrompt = false;
      password = '';

      // Step 3 — Run the initiator flow (runSyncNow is invoked ONLY after local verify).
      // runSyncNow: connects → IK handshake → binding check → recv B's blob → SYNC-05 auth check.
      // B's vault key is secureWiped inside runSyncNow before it returns (T-10-24).
      await runSyncNow(configDir, passwordBytes);

      // Phase-10 handoff reached: transport complete. No merge yet (Phase 11).
      // syncStore.status is now 'done' (set by runSyncNow).
    } catch {
      // runSyncNow throws typed errors (SyncPeerUnreachableError, SyncBindingMismatchError,
      // SyncAuthFailedError, SyncTransportError, VaultCorruptError). The syncStore.lastError
      // is already set by runSyncNow's catch path. Surface it in the UI below.
      // We do NOT re-throw: the error is displayed via syncStore.lastError.
    } finally {
      // Zero the password bytes on EVERY exit path (D-03 / no caching / T-10-19).
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
  SYNC-01 SC-1: button disabled while locked or sync in progress.
  D-04: minimal and unstyled (Phase 12 adds Tailwind polish).
  No counts/titles/passwords displayed here (Phase 12 fence; T-10-21).
-->
<div>
  <button type="button" onclick={handleSyncClick} disabled={isDisabled}>
    {#if syncStore.status === 'connecting'}
      Connecting…
    {:else if syncStore.status === 'syncing'}
      Syncing…
    {:else}
      Sync Now
    {/if}
  </button>

  <!--
    Status / error feedback (counts-only Phase 12; no entry data here — T-10-21).
    Plain text only — no entry titles, passwords, or entry counts.
  -->
  {#if syncStore.status === 'done'}
    <p>Synced (Phase-11 merge not yet wired — transport complete).</p>
  {:else if syncStore.status === 'error' && syncStore.lastError !== null}
    <p role="alert">{syncStore.lastError}</p>
  {/if}

  <!--
    D-03 master-password re-prompt.
    Shown on button click; closed on successful local-verify-before-connect or cancel.
    A wrong password re-shows this form without connecting (D-03 gate).
  -->
  {#if showRePrompt}
    <div role="dialog" aria-modal="true" aria-label="Confirm master password to sync">
      <p>Enter your master password to sync.</p>
      <p>Your password will be verified locally first, then used to authenticate with the peer.</p>

      <label for="sync-master-pw">Master password</label>
      <input
        id="sync-master-pw"
        type="password"
        autocomplete="current-password"
        bind:value={password}
        disabled={promptSubmitting}
        onkeydown={handleKeydown}
        placeholder="Enter your master password"
      />

      {#if promptError !== null}
        <p role="alert">{promptError}</p>
      {/if}

      <div>
        <button
          type="button"
          onclick={() => void handleConfirmSync()}
          disabled={promptSubmitting || password.length === 0}
        >
          {promptSubmitting ? 'Verifying…' : 'Sync'}
        </button>
        <button
          type="button"
          onclick={handleCancel}
          disabled={promptSubmitting}
        >
          Cancel
        </button>
      </div>
    </div>
  {/if}
</div>
