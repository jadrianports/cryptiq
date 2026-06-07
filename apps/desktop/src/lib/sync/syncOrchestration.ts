// apps/desktop/src/lib/sync/syncOrchestration.ts
//
// JS-side initiator orchestration for the Phase-10 sync transport (D-05 steps 1–3).
//
// ARCHITECTURE:
//   This module bridges the Rust IK transport (syncBridge.ts) with the core WASM
//   auth check (authCheckBlobAndGetBKey from @cryptiq/core). It maps Rust error
//   strings to the typed TS errors from @cryptiq/core, and manages the SyncStore
//   status transitions.
//
// D-05 PROTOCOL (Phase 10 scope — steps 1–3 only):
//   1. A connects to B over Noise IK; vaultPairId binding verified in Rust before
//      any vault bytes flow (SYNC-03). Handled inside `sync_now` on the Rust side.
//   2. B sends its full encrypted vault to A (Rust returns it as number[]).
//   3. A calls authCheckBlobAndGetBKey(masterPassword, bBytes) — re-derives Argon2id
//      against B's OWN KDF params and tryUnwraps B's master key (SYNC-05).
//   → PHASE-11 HANDOFF: steps 4–6 (merge + re-seal + cold-decrypt-verify + atomic save)
//      are NOT wired here. B's vault key is secureWiped immediately at the handoff.
//
// D-03 LOCAL-VERIFY-BEFORE-CONNECT (PRECONDITION):
//   `runSyncNow` is invoked ONLY AFTER the caller has already verified the master
//   password locally against A's OWN unlocked vault (e.g. via ConfirmMasterPassword.svelte
//   + vaultSession.verifyMasterPassword(), which re-derives Argon2id against A's params
//   and performs a tryUnwrap MAC check). A typo must be caught locally — before any
//   network connection is attempted (T-10-23 / D-03 / SYNC-01 SC-1).
//
//   runSyncNow does NOT repeat the local verify — the caller owns the D-03 gate.
//   The master password is passed as a Uint8Array argument to authCheckBlobAndGetBKey;
//   runSyncNow is responsible for secureWiping it in the calling context's finally block.
//   (The caller — SyncNowButton.svelte — zeros the password in its own finally.)
//
// SECURITY (threat register T-10-18 through T-10-24):
//   - Master password NEVER crosses IPC: syncNow(configDir) takes no password param;
//     authCheckBlobAndGetBKey runs in WASM (T-10-15 / SYNC-05).
//   - B's 32-byte vault key is secureWiped in a try/finally at the Phase-11 handoff
//     point so it NEVER dangling in the JS heap (T-10-24 / WARNING 7 / CLAUDE.md
//     caller-owns-lifecycle).
//   - runSyncNow returns `void` — the raw key is NEVER handed to the UI layer.
//   - No counts/titles/passwords in status messages (Phase 12 fence; T-10-21).
//   - Rust error strings → typed TS errors before reaching the UI (T-10-20).
//
// CORE PURITY: @cryptiq/core is pure TS/WASM. This file lives in apps/desktop
//   (importing @tauri-apps/* and the Svelte stores is ALLOWED here).
//
// Source: 10-05-PLAN.md Task 1, 10-CONTEXT.md D-03/D-05/D-06, 10-RESEARCH.md
//   Resolution 3 (error strings) + Resolution 6 (JS orchestration excerpt),
//   CLAUDE.md caller-owns-secret-lifecycle + secureWipe.

import { authCheckBlobAndGetBKey, secureWipe } from '@cryptiq/core';
import {
  SyncPeerUnreachableError,
  SyncBindingMismatchError,
  SyncTransportError,
  SyncAuthFailedError,
} from '@cryptiq/core';
import { syncNow, syncListenerStart, syncListenerStop } from './syncBridge';
import { syncStore } from './SyncStore.svelte';

// ---------------------------------------------------------------------------
// Error-mapping convention (mirrors the comment in syncBridge.ts)
//
// The Rust `sync_now` command surfaces errors as thrown strings. Each string is
// mapped to a typed TS error before it reaches the UI, so the UI branches on
// stable `.code` strings (not on raw Rust error text that could change):
//
//   "connect timed out" (substring)      → SyncPeerUnreachableError
//   "IK handshake failed" (substring)   → SyncPeerUnreachableError (no info leak)
//   "connect failed" (substring)        → SyncPeerUnreachableError (Rust os-error prefix)
//   "actively refused" (substring)      → SyncPeerUnreachableError (Windows ECONNREFUSED)
//   "os error 10061" (substring)        → SyncPeerUnreachableError (Windows ECONNREFUSED code)
//   "no connection could be made"       → SyncPeerUnreachableError (Windows full message)
//   "unreachable" (substring)           → SyncPeerUnreachableError (network unreachable)
//   "sync_now: binding check" (substr)  → SyncBindingMismatchError
//   framing / IO errors                 → SyncTransportError
//
// NOTE: connect timeout + handshake failure intentionally map to the SAME error
// (SyncPeerUnreachableError) so the UI cannot distinguish IK failure from network
// failure — T-10-20 / SYNC-06 leakage mitigation.
//
// FIX 5 (review): On Windows, ECONNREFUSED surfaces as Rust's os-error string
// "No connection could be made because the target machine actively refused it.
// (os error 10061)" — none of the original substrings matched this, causing offline
// peers to fall through to SyncTransportError (wrong recovery code). Added the
// Windows-specific substrings above; msg is lowercased once before all checks to
// prevent casing variations from defeating any match.
// ---------------------------------------------------------------------------

/**
 * Map a Rust error string from `sync_now` to the appropriate typed TS error.
 *
 * Returns a typed SyncPeerUnreachableError, SyncBindingMismatchError, or
 * SyncTransportError. Called from runSyncNow's catch block.
 *
 * SECURITY: this mapping is intentionally coarse for connect/handshake failures
 * (T-10-20 — both map to SyncPeerUnreachableError, indistinguishable).
 * The binding-check branch is kept separate and fires only AFTER the IK channel
 * is authenticated, so revealing a mismatch is safe and does not narrow the
 * reachable/unreachable distinction to the UI (T-10-20 / SYNC-06).
 */
function mapRustSyncError(
  raw: unknown,
): SyncPeerUnreachableError | SyncBindingMismatchError | SyncTransportError {
  // Lowercase once — Rust error messages may have mixed casing across OS versions;
  // doing a single toLowerCase() here prevents casing from defeating any match.
  const m = String(raw).toLowerCase();

  // Connect timeout + IK handshake failure + OS-level connection refused all →
  // SyncPeerUnreachableError. Intentionally coarse: the UI cannot distinguish
  // "timeout" from "handshake MAC failure" from "actively refused" (T-10-20).
  //
  // Substrings cover:
  //   cross-platform: 'connect timed out', 'timed out', 'IK handshake failed',
  //                   'connection refused', 'unreachable'
  //   Rust prefix:    'connect failed'   (sync_now: connect failed: <os error>)
  //   Windows:        'actively refused', 'os error 10061',
  //                   'no connection could be made'
  if (
    m.includes('connect timed out') ||
    m.includes('ik handshake failed') ||
    m.includes('connection refused') ||
    m.includes('timed out') ||
    m.includes('connect failed') ||
    m.includes('actively refused') ||
    m.includes('os error 10061') ||
    m.includes('no connection could be made') ||
    m.includes('unreachable')
  ) {
    return new SyncPeerUnreachableError(String(raw));
  }

  // Binding check failure (vaultPairId mismatch) → SyncBindingMismatchError.
  // This ONLY fires after the IK channel is authenticated (after handshake), so
  // revealing a binding mismatch is safe — it does not leak crypto state (T-10-20).
  if (m.includes('binding check') || m.includes('vault_pair_id')) {
    return new SyncBindingMismatchError(String(raw));
  }

  // Everything else (framing errors, IO errors, unexpected) → SyncTransportError.
  return new SyncTransportError(String(raw));
}

// ---------------------------------------------------------------------------
// Initiator orchestration
// ---------------------------------------------------------------------------

/**
 * Run the Phase-10 sync initiator flow end-to-end (D-05 steps 1–3).
 *
 * PRECONDITION — D-03 LOCAL-VERIFY-BEFORE-CONNECT (CALLER MUST ENFORCE):
 *   The caller MUST have already verified `masterPassword` locally against A's OWN
 *   unlocked vault (via vaultSession.verifyMasterPassword()) BEFORE calling this
 *   function. A typo must be caught locally — before any network connection is
 *   attempted — so that a wrong password never wastes a connection (T-10-23 / D-03).
 *   runSyncNow does NOT repeat the local verify; it is invoked only after the
 *   local-verify gate has passed.
 *
 * SECURITY:
 *   - `masterPassword` is a Uint8Array; the caller MUST zero it in a `finally` block
 *     (D-03 / no master-password caching). The caller (SyncNowButton.svelte) owns
 *     this zeroing — runSyncNow does NOT zero the password it received.
 *   - B's 32-byte vault key is secureWiped in a try/finally at the Phase-11 handoff
 *     before this function returns (T-10-24 / WARNING 7 / CLAUDE.md caller-owns-lifecycle).
 *   - runSyncNow returns `void` — the raw key is NEVER returned to the UI layer.
 *   - No counts/titles/passwords in status messages (Phase 12 fence; T-10-21).
 *
 * @param configDir      Tauri app config directory (passed to `sync_now` Rust command).
 * @param masterPassword The master password as a UTF-8 encoded byte array. CALLER MUST
 *                       zero this in a `finally` block. It is passed directly to
 *                       authCheckBlobAndGetBKey (WASM — never crosses IPC).
 * @returns              void — the Phase-10 handoff is complete; B's key is wiped.
 * @throws {SyncPeerUnreachableError}   if the peer is unreachable / IK handshake fails.
 * @throws {SyncBindingMismatchError}   if the vaultPairId binding check fails.
 * @throws {SyncTransportError}         if a framing or IO error occurs.
 * @throws {SyncAuthFailedError}        if B's vault uses a different master password.
 * @throws {VaultCorruptError}          if B's received blob is not a valid VaultDocumentV1.
 */
export async function runSyncNow(configDir: string, masterPassword: Uint8Array): Promise<void> {
  // Transition to 'connecting': the IK handshake + binding check happen in Rust.
  syncStore.setStatus('connecting');

  // Step 1 + 2: Rust side — connect to stored peer IP:54321, run Noise IK handshake,
  // verify vaultPairId binding (SYNC-03), receive B's full encrypted vault blob.
  // `syncNow` returns B's blob as a number[] (Tauri Vec<u8> serialization).
  // The master password NEVER crosses IPC (Pitfall 5 / T-10-15).
  let bBlobNumbers: number[];
  try {
    bBlobNumbers = await syncNow(configDir);
  } catch (e) {
    // Map Rust error string to a typed TS error, set SyncStore state, re-throw.
    const typed = mapRustSyncError(e);
    // SECURITY: typed.message may contain the raw Rust string, which is fine for the
    // error object itself. The UI renders syncStore.lastError (a safe display string
    // set below), not the typed error message directly.
    syncStore.setError(
      typed instanceof SyncBindingMismatchError
        ? 'Sync failed: this peer has a different vault. Ensure you are syncing with the correct device.'
        : 'Sync failed: could not reach the peer. Check that the other device is online and unlocked.',
    );
    throw typed;
  }

  // Step 3: SYNC-05 auth check — authCheckBlobAndGetBKey runs in WASM (core/libsodium).
  // Convert the number[] blob to Uint8Array for the core function.
  syncStore.setStatus('syncing');
  const bBytes = new Uint8Array(bBlobNumbers);

  // B's vault key is a 32-byte Uint8Array returned by authCheckBlobAndGetBKey.
  // Caller-owns-lifecycle: we MUST secureWipe it in a try/finally at the handoff point
  // below — before runSyncNow returns on ANY exit path (T-10-24 / WARNING 7).
  let bVaultKey: Uint8Array;
  try {
    bVaultKey = await authCheckBlobAndGetBKey(masterPassword, bBytes);
  } catch (e) {
    // authCheckBlobAndGetBKey can throw:
    //   SyncAuthFailedError  — wrong master password (AEAD MAC failure on peer wrap)
    //   VaultCorruptError    — malformed peer blob (parseOuter rejected the envelope)
    //   KdfResourceError     — Argon2id OOM during key derivation
    //
    // FIX 5b: only set the "passwords don't match" message for SyncAuthFailedError.
    // Labelling VaultCorruptError or KdfResourceError as a password mismatch misleads
    // recovery — a corrupt blob or an OOM requires a different user action than
    // "re-enter your password". Re-throw the ORIGINAL error unchanged in both cases.
    if (e instanceof SyncAuthFailedError) {
      syncStore.setError(
        'Sync failed: the master passwords do not match. Ensure both vaults use the same master password.',
      );
    } else {
      syncStore.setError('Sync failed: could not verify the peer vault.');
    }
    throw e;
  }

  // ── PHASE-11 HANDOFF ──────────────────────────────────────────────────────
  //
  // B's 32-byte vault key is now in memory. In Phase 11, this is the point where
  // the merge continuation (mergeInnerDocs + re-seal + cold-decrypt-verify +
  // atomic save) would begin — the merge owns the key's lifecycle and calls
  // secureWipe after re-sealing both vaults.
  //
  // PHASE 11 HANDOFF: when the merge + re-seal + cold-decrypt-verify + atomic save
  // are wired here, REMOVE the immediate secureWipe below and instead hand bVaultKey
  // to the merge continuation (which then owns the wipe after re-sealing both vaults).
  // DO NOT implement merge/re-seal/save in Phase 10.
  //
  // Because the Phase-11 merge continuation is NOT wired in Phase 10, we MUST
  // secureWipe bVaultKey immediately so no key bytes dangle in the JS heap
  // (T-10-24 / WARNING 7 / CLAUDE.md caller-owns-lifecycle). The wipe runs even on
  // a downstream throw via try/finally.
  try {
    // Phase 11 merge steps would go here (steps 4–6 of D-05). Not implemented in Phase 10.
    // (Intentionally left as a clearly-marked no-op to signal the handoff boundary.)
  } finally {
    // PHASE-10 SECURE-WIPE: zero B's vault key before runSyncNow returns.
    // This wipe runs even if the (currently empty) try block above were to throw.
    await secureWipe(bVaultKey);
    // After Phase 11: remove the above secureWipe call and instead let the merge
    // continuation call it after re-sealing both vaults (SAFE-04).
  }

  // ── END PHASE-11 HANDOFF ──────────────────────────────────────────────────

  // Phase-10 handoff reached: transport complete, auth gate passed, B's key wiped.
  // The actual data convergence (merge/save) is Phase 11.
  syncStore.setStatus('done');
}

// ---------------------------------------------------------------------------
// D-06 listener lifecycle helpers (used by the SyncNowButton $effect)
// ---------------------------------------------------------------------------

/**
 * Start the sync listener if a peer is paired (D-06).
 *
 * Called by the D-06 $effect when `vaultSession.isUnlocked` becomes true AND a
 * peer exists in peers.json. Sets the listenerActive guard flag to prevent
 * redundant double-start invokes (the Rust command is idempotent, but avoid noise).
 *
 * D-06: the listener opens whenever the vault is unlocked and peer exists;
 * it reuses the port-54321 firewall grant from pairing (no new firewall prompt).
 *
 * NOTE — Open Question 3 (port-54321 coexistence): sync_listener_stop SHOULD be
 * called before any pairing_initiate binds port 54321, so a running sync listener
 * does not block a pairing attempt. The actual pairing-gate is Phase-12 UI work;
 * do NOT modify pairing.rs or the pairing flow here.
 *
 * @param configDir Tauri app config directory.
 * @param vaultPath Filesystem path to the vault file (Rust listener reads this to
 *                  serve B's blob to the initiator).
 */
export async function startSyncListenerIfPaired(
  configDir: string,
  vaultPath: string,
): Promise<void> {
  // Guard: do not double-start if we believe the listener is already active.
  if (syncStore.listenerActive) return;

  try {
    await syncListenerStart(configDir, vaultPath);
    syncStore.markListenerActive();
  } catch {
    // Non-fatal: if the listener fails to start (e.g. port already bound from a
    // prior session that did not close cleanly), leave listenerActive false so the
    // next $effect trigger will retry.
    syncStore.markListenerInactive();
  }
}

/**
 * Stop the sync listener (D-06 close-on-lock).
 *
 * Called by the D-06 $effect when `vaultSession.isUnlocked` becomes false (the
 * vault locked). Clears the listenerActive guard flag.
 *
 * Idempotent — safe to call even if the listener was not started (the Rust command
 * is a no-op when no listener is running).
 */
export async function stopSyncListener(): Promise<void> {
  // Clear the flag optimistically — if the stop fails, we re-clear to false anyway.
  syncStore.markListenerInactive();
  try {
    await syncListenerStop();
  } catch {
    // Non-fatal: if the stop fails, the Rust listener will eventually time out /
    // be cleaned up on process exit. The flag is already cleared above.
  }
}
