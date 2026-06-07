// apps/desktop/src/lib/sync/SyncStore.svelte.ts
//
// Reactive sync-status store for the sync subsystem (Phase 10).
//
// ARCHITECTURE DECISIONS:
//
//   $state.raw (NOT $state):
//     Status/error state are secret-adjacent: they capture the lifecycle of operations
//     that operate on vault keys and master passwords. A deep Svelte `$state` proxy
//     could surface intermediate state through DevTools / the reactivity graph.
//     `$state.raw` stores by reference and only reacts to WHOLE-VALUE reassignment —
//     same discipline as vault.svelte.ts and PairingStore.svelte.ts.
//     This MUST NOT become `$state(`. (CLAUDE.md frontend/security, Pitfall 7 defense.)
//
//   Non-reactive #listenerActive:
//     Whether the Rust sync listener is currently running does not need to drive UI
//     reactivity — it is a guard flag for the D-06 $effect to avoid redundant invokes.
//     Kept as a plain private field (no $state, no $state.raw).
//
//   No key bytes:
//     The store MUST NOT hold or copy any vault key, master password, or peer key bytes.
//     (PairingStore rule — see PairingStore.svelte.ts lines 19-20.)
//
//   Whole-value reassignment on mutation:
//     setStatus/setError/reset reassign the backing $state.raw fields to new values so
//     Svelte consumers see the change. String primitives are inherently atomic — no deep
//     proxy issues — but the whole-value pattern is still enforced for consistency.
//
//   Module-level singleton:
//     `export const syncStore = new SyncStore()` — mirrors vaultSession and pairingStore.
//
// SECURITY:
//   - No counts, titles, passwords, or entry data stored here (Phase 12 fence; T-10-21).
//   - No master-password caching (D-03 — the password is a transient arg to runSyncNow).
//
// Source: 10-05-PLAN.md Task 1, 10-PATTERNS.md §"SyncStore.svelte.ts (NEW)",
//   CLAUDE.md frontend/security, PairingStore.svelte.ts pattern.

export type SyncStatus = 'idle' | 'connecting' | 'syncing' | 'done' | 'error';

class SyncStore {
  // $state.raw: status reassigned on state transitions — no deep proxy (Pitfall 7).
  // MUST use $state.raw, NEVER $state( for any sync lifecycle state.
  #status = $state.raw<SyncStatus>('idle');

  // $state.raw: last error message (string, no typed-error object — the typed error
  // is caught and its message is stored here for minimal display; no stack trace, no
  // path detail that could leak handshake-vs-network distinction — T-10-20).
  #lastError = $state.raw<string | null>(null);

  // NON-reactive: plain boolean guard for the D-06 $effect. Not in the reactive graph.
  // True while the Rust sync_listener_start task is believed to be running.
  #listenerActive = false;

  // ---------------------------------------------------------------------------
  // Readable state (reactive via $state.raw)
  // ---------------------------------------------------------------------------

  /**
   * The current sync status.
   *
   * Reactive via $state.raw — consumers see the new value on every reassignment.
   * 'idle'       → no sync in progress
   * 'connecting' → IK handshake in flight
   * 'syncing'    → vault blob exchange + auth check in flight
   * 'done'       → last sync completed successfully (Phase-11 handoff reached)
   * 'error'      → last sync failed; see lastError for the display message
   */
  get status(): SyncStatus {
    return this.#status;
  }

  /**
   * The last error message from a failed sync, or null when no error.
   *
   * Reactive via $state.raw. Set when status becomes 'error'; cleared on reset().
   *
   * SECURITY: this is a user-facing display message only — no stack traces, no
   * handshake internals, no path/branch detail that could leak crypto state.
   * The typed error classification is done internally (T-10-20 — connect + handshake
   * both map to SyncPeerUnreachableError, indistinguishable by design).
   */
  get lastError(): string | null {
    return this.#lastError;
  }

  /**
   * Whether the Rust sync listener is believed to be active.
   *
   * NON-reactive — not in the reactive graph. Used by the D-06 $effect as a guard
   * to avoid redundant syncListenerStart invokes.
   */
  get listenerActive(): boolean {
    return this.#listenerActive;
  }

  // ---------------------------------------------------------------------------
  // State mutations (whole-value reassignment for $state.raw reactivity)
  // ---------------------------------------------------------------------------

  /**
   * Set the sync status. Clears lastError when transitioning away from 'error'.
   *
   * @param status The new status value.
   */
  setStatus(status: SyncStatus): void {
    // Whole-value reassignment fires $state.raw reactivity.
    this.#status = status;
    // Clear the error when the status moves away from 'error' so stale errors
    // do not persist into a new connecting/syncing cycle.
    if (status !== 'error') {
      this.#lastError = null;
    }
  }

  /**
   * Set the last error message and transition status to 'error'.
   *
   * SECURITY: pass only a user-facing display message — no stack traces, no
   * handshake internals (T-10-20). The orchestration layer is responsible for
   * mapping typed errors to safe display strings before calling this.
   *
   * @param message The user-facing error message.
   */
  setError(message: string): void {
    // Whole-value reassignment fires $state.raw reactivity.
    this.#status = 'error';
    this.#lastError = message;
  }

  /**
   * Reset status to 'idle' and clear the last error. Called at the start of a new
   * sync attempt so stale error state does not persist.
   */
  reset(): void {
    this.#status = 'idle';
    this.#lastError = null;
  }

  // ---------------------------------------------------------------------------
  // Listener state (non-reactive — internal guard only)
  // ---------------------------------------------------------------------------

  /**
   * Mark the listener as active. Called by the D-06 $effect after a successful
   * syncListenerStart invoke.
   */
  markListenerActive(): void {
    this.#listenerActive = true;
  }

  /**
   * Mark the listener as inactive. Called by the D-06 $effect after a successful
   * syncListenerStop invoke.
   */
  markListenerInactive(): void {
    this.#listenerActive = false;
  }
}

// ---------------------------------------------------------------------------
// Module-level singleton (mirrors `export const vaultSession = new VaultSession()`)
// ---------------------------------------------------------------------------

/**
 * The module-level SyncStore singleton.
 *
 * Import this, not the class:
 *   import { syncStore } from '$lib/sync/SyncStore.svelte';
 */
export const syncStore = new SyncStore();
