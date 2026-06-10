// apps/desktop/src/lib/sync/syncOrchestration.ts
//
// JS-side initiator orchestration for the Phase-10/11 sync transport.
//
// ARCHITECTURE:
//   This module bridges the Rust IK transport (syncBridge.ts) with the core WASM
//   auth check (authCheckBlobAndGetBKey from @cryptiq/core), merge engine, and
//   re-seal pipeline. It maps Rust error strings to the typed TS errors from
//   @cryptiq/core, and manages the SyncStore status transitions.
//
// D-05 PROTOCOL (Phase 10 steps 1–3 + Phase 11 steps 4–6):
//   1. A connects to B over Noise IK; vaultPairId binding verified in Rust before
//      any vault bytes flow (SYNC-03). Handled inside `sync_now` on the Rust side.
//   2. B sends its full encrypted vault to A (Rust returns it as number[]).
//   3. A calls authCheckBlobAndGetBKey(masterPassword, bBytes) — re-derives Argon2id
//      against B's OWN KDF params and tryUnwraps B's master key (SYNC-05).
//   4. A merges both InnerDocs (mergeInnerDocs) and re-seals under BOTH keys (Phase 11).
//   5. A cold-verifies BOTH re-sealed blobs BEFORE sending or saving (SAFE-03, Phase 11).
//   6. A sends B's blob (syncProvideMergedBlob → sync_provide_merged_blob → Rust sends
//      on live Noise channel), awaits ack, then saves A's own vault (D-01, Phase 11).
//
// D-03 LOCAL-VERIFY-BEFORE-CONNECT (PRECONDITION):
//   `runSyncNow` is invoked ONLY AFTER the caller has already verified the master
//   password locally against A's OWN unlocked vault (e.g. via ConfirmMasterPassword.svelte
//   + vaultSession.verifyMasterPassword()). A typo must be caught locally — before any
//   network connection is attempted (T-10-23 / D-03 / SYNC-01 SC-1).
//
//   runSyncNow does NOT repeat the local verify — the caller owns the D-03 gate.
//   The master password is passed as a Uint8Array argument to authCheckBlobAndGetBKey;
//   runSyncNow is responsible for secureWiping it in the calling context's finally block.
//   (The caller — SyncNowButton.svelte — zeros the password in its own finally.)
//
// SECURITY (threat register T-10-18 through T-10-24, T-11-14 through T-11-20):
//   - Master password NEVER crosses IPC: syncNow(configDir) takes no password param;
//     authCheckBlobAndGetBKey runs in WASM (T-10-15 / SYNC-05).
//   - B's 32-byte vault key is secureWiped in the merge continuation's finally after
//     re-sealing both vaults — NEVER dangling in the JS heap (SAFE-04).
//   - runSyncNow returns `void` — the raw key is NEVER handed to the UI layer.
//   - No counts/titles/passwords in status messages (Phase 12 fence; T-10-21, T-11-19).
//   - Rust error strings → typed TS errors before reaching the UI (T-10-20).
//   - Merged plaintext InnerDoc NEVER crosses IPC — only sealed blob bytes, saveOk
//     boolean, and vaultPath string cross any invoke boundary (SAFE-04, T-11-14).
//   - Cold-verify BOTH re-sealed blobs BEFORE calling any save callback (SAFE-03);
//     abort-before-write on any mismatch (SAFE-01).
//
// CORE PURITY: @cryptiq/core is pure TS/WASM. This file lives in apps/desktop
//   (importing @tauri-apps/* and the Svelte stores is ALLOWED here).
//
// Source: 10-05-PLAN.md Task 1, 11-04-PLAN.md Tasks 2–3.

import { listen } from '@tauri-apps/api/event';
import type { UnlistenFn } from '@tauri-apps/api/event';
import {
  authCheckBlobAndGetBKey,
  secureWipe,
  mergeInnerDocs,
  resealInnerDoc,
  unlockVault,
  decryptInner,
  parseOuter,
  SyncTransportError,
  SyncPartnerNotSavedError,
  SyncNoAckError,
  SyncPartnerBusyError,
  SyncLockedMidSyncError,
  MergeSchemaMismatchError,
} from '@cryptiq/core';
import type { InnerDoc, MergeCounts, MergeContext } from '@cryptiq/core';
import {
  SyncPeerUnreachableError,
  SyncBindingMismatchError,
  SyncAuthFailedError,
} from '@cryptiq/core';
import {
  syncNow,
  syncListenerStart,
  syncListenerStop,
  syncProvideMergedBlob,
  syncConfirmSave,
} from './syncBridge';
import { syncStore } from './SyncStore.svelte';
import { vaultSession } from '../state/vault.svelte';

// ---------------------------------------------------------------------------
// Error-mapping convention (mirrors the comment in syncBridge.ts)
//
// The Rust `sync_now` command surfaces errors as thrown strings. Each string is
// mapped to a typed TS error before it reaches the UI, so the UI branches on
// stable `.code` strings (not on raw Rust error text that could change):
//
//   "connect timed out" (substring)        → SyncPeerUnreachableError
//   "IK handshake failed" (substring)     → SyncPeerUnreachableError (no info leak)
//   "connect failed" (substring)          → SyncPeerUnreachableError (Rust os-error prefix)
//   "actively refused" (substring)        → SyncPeerUnreachableError (Windows ECONNREFUSED)
//   "os error 10061" (substring)          → SyncPeerUnreachableError (Windows ECONNREFUSED code)
//   "no connection could be made"         → SyncPeerUnreachableError (Windows full message)
//   "unreachable" (substring)             → SyncPeerUnreachableError (network unreachable)
//   "sync_now: binding check" (substr)    → SyncBindingMismatchError
//   "sync already in progress" / "busy"   → SyncPartnerBusyError (D-08)
//   "locked mid" / "locked_mid_sync"      → SyncLockedMidSyncError (D-06)
//   framing / IO errors                   → SyncTransportError
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
 * Returns a typed SyncPeerUnreachableError, SyncBindingMismatchError,
 * SyncPartnerBusyError, SyncLockedMidSyncError, or SyncTransportError.
 * Called from runSyncNow's catch block.
 *
 * SECURITY: this mapping is intentionally coarse for connect/handshake failures
 * (T-10-20 — both map to SyncPeerUnreachableError, indistinguishable).
 * The binding-check branch is kept separate and fires only AFTER the IK channel
 * is authenticated, so revealing a mismatch is safe and does not narrow the
 * reachable/unreachable distinction to the UI (T-10-20 / SYNC-06).
 */
function mapRustSyncError(
  raw: unknown,
):
  | SyncPeerUnreachableError
  | SyncBindingMismatchError
  | SyncPartnerBusyError
  | SyncLockedMidSyncError
  | SyncTransportError {
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

  // D-08: second sync already in flight → SyncPartnerBusyError.
  if (m.includes('sync already in progress') || m.includes('busy')) {
    return new SyncPartnerBusyError(String(raw));
  }

  // D-06: partner's vault locked mid-sync → SyncLockedMidSyncError.
  // Match only the specific mid-sync markers — a bare 'locked' substring would
  // false-match benign strings like 'unlocked', 'blocked', or 'deadlocked' and
  // misclassify an unrelated transport error as a lock-mid-sync (wrong recovery hint).
  if (m.includes('locked mid') || m.includes('locked_mid_sync')) {
    return new SyncLockedMidSyncError(String(raw));
  }

  // Everything else (framing errors, IO errors, unexpected) → SyncTransportError.
  return new SyncTransportError(String(raw));
}

// ---------------------------------------------------------------------------
// Phase-11 A-side merge continuation (D-01/D-03/D-05/D-11, SAFE-01..04)
// ---------------------------------------------------------------------------

/**
 * Input type for `applyRemoteMergedBlob`.
 * D-11: transport-agnostic (no invoke inside this function).
 */
export interface ApplyRemoteMergedBlobInputs {
  /** A's current in-memory InnerDoc (already upgraded — cast from vaultSession.vault.entries). */
  aInner: InnerDoc;
  /** A's vault key (from vaultSession.unsafeGetKey()). */
  aVaultKey: Uint8Array;
  /** A's current outer VaultDocumentV1 (from parseOuter / vaultSession.vault.doc). */
  aDoc: import('@cryptiq/core').VaultDocumentV1;
  /** B's decrypted InnerDoc (from decryptInner(bDoc.data, bVaultKey) + JSON.parse). */
  bInner: InnerDoc;
  /** B's vault key (from authCheckBlobAndGetBKey). NOTE: caller MUST own lifecycle. */
  bVaultKey: Uint8Array;
  /** B's outer VaultDocumentV1 (from parseOuter(bBytes)). */
  bDoc: import('@cryptiq/core').VaultDocumentV1;
  /** Merge context — device IDs + clocks. */
  mergeCtx: MergeContext;
  /**
   * D-11 injected callback: send B's sealed blob AND await B's ack.
   * Resolves after B has saved and acked. Throws SyncNoAckError on timeout/no-ack.
   * Transport wires this as: bytes → Array.from → syncProvideMergedBlob → Rust sends.
   */
  saveBBlob: (bytes: Uint8Array) => Promise<void>;
  /**
   * D-11 injected callback: save A's sealed blob to A's vault.
   * Called ONLY after saveBBlob resolves (D-01 ordering: B saves first → ack → A saves).
   * Throws SyncPartnerNotSavedError if A's save fails after ack received.
   */
  saveABlob: (bytes: Uint8Array) => Promise<void>;
  /**
   * The master password — required for cold-verify (SAFE-03/Pitfall 8).
   * Used ONLY inside unlockVault for re-derive; never stored or passed across IPC.
   */
  masterPassword: Uint8Array;
}

/**
 * Transport-agnostic A-side merge continuation (D-11, Phase 11 steps 4–6 of D-05).
 *
 * Given A's and B's decrypted InnerDocs + keys + docs + merge context + two injected
 * save callbacks, this function:
 *   1. Merges (mergeInnerDocs).
 *   2. Re-seals under A's key → aNewBlob; re-seals under B's key → bNewBlob.
 *   3. Wipes merged-InnerDoc JSON bytes in finally (SAFE-04, Pitfall 3).
 *   4. Cold-verifies BOTH blobs via unlockVault re-derive + JSON.stringify compare
 *      BEFORE calling either save callback (SAFE-03/D-03/SAFE-01 abort-before-write).
 *   5. On success: await saveBBlob(bNewBlob) then await saveABlob(aNewBlob) (D-01 order).
 *   6. Returns MergeCounts.
 *
 * On cold-verify failure on EITHER blob: throws SyncTransportError and NEITHER
 * saveBBlob NOR saveABlob is called (abort-before-write invariant).
 *
 * SAFE-04: bVaultKey is wiped in a finally in the caller (runSyncNow); transient
 * cold-verify keys are each wiped in their own try/finally (Pitfall 8).
 *
 * D-11: NO invoke() or syncProvideMergedBlob inside this function. Those are
 * the injected callbacks supplied by runSyncNow. This keeps the merge + reseal
 * + cold-verify core reusable by a future cloud transport.
 *
 * @throws SyncTransportError if either cold-verify fails (abort-before-write).
 * @throws any error from mergeInnerDocs, resealInnerDoc, unlockVault, or the
 *         injected save callbacks (saveBBlob → SyncNoAckError; saveABlob →
 *         SyncPartnerNotSavedError).
 */
export async function applyRemoteMergedBlob(
  inputs: ApplyRemoteMergedBlobInputs,
): Promise<MergeCounts> {
  const { aInner, aVaultKey, aDoc, bInner, bVaultKey, bDoc, mergeCtx, saveBBlob, saveABlob, masterPassword } = inputs;

  // Step 1: Merge A's and B's InnerDocs.
  const mergeResult = mergeInnerDocs(aInner, bInner, mergeCtx);
  const merged = mergeResult.merged;

  // Step 2 + 3: Re-seal the merged InnerDoc under A's key and B's key.
  // resealInnerDoc OWNS and zeroes the plaintext byte buffer it allocates (SAFE-04,
  // Pitfall 3) — there is no caller-side plaintext byte buffer to wipe here. The
  // `merged` OBJECT itself is JS-managed (unwipeable), an accepted residual consistent
  // with the rest of the vault path.
  const aNewBlob = await resealInnerDoc(merged, aVaultKey, aDoc);
  const bNewBlob = await resealInnerDoc(merged, bVaultKey, bDoc);

  // Step 4: Cold-verify BOTH blobs BEFORE calling any save callback (SAFE-03/D-03).
  // Uses unlockVault with the master password to re-derive the key from stored KDF
  // params in the re-sealed blobs (Pitfall 8: fresh re-derived key, NOT #vaultKey).
  //
  // Any failure (wrong password, AEAD MAC failure, entries mismatch) throws
  // SyncTransportError and aborts BEFORE either save callback is called (SAFE-01).
  //
  // Cold-verify A's new blob:
  let verifyAResult: { vault: import('@cryptiq/core').UnlockedVault; vaultKey: Uint8Array } | null = null;
  try {
    try {
      verifyAResult = await unlockVault(aNewBlob, { masterPassword });
    } catch (e) {
      throw new SyncTransportError(
        `Cold-decrypt verification failed on A blob: ${(e as Error).message}`,
      );
    }
    if (JSON.stringify(verifyAResult.vault.entries) !== JSON.stringify(merged)) {
      throw new SyncTransportError('Cold-decrypt verification mismatch on A blob');
    }
  } finally {
    if (verifyAResult !== null) {
      await secureWipe(verifyAResult.vaultKey); // wipe transient re-derived key (Pitfall 8)
    }
  }

  // Cold-verify B's new blob:
  let verifyBResult: { vault: import('@cryptiq/core').UnlockedVault; vaultKey: Uint8Array } | null = null;
  try {
    try {
      verifyBResult = await unlockVault(bNewBlob, { masterPassword });
    } catch (e) {
      throw new SyncTransportError(
        `Cold-decrypt verification failed on B blob: ${(e as Error).message}`,
      );
    }
    if (JSON.stringify(verifyBResult.vault.entries) !== JSON.stringify(merged)) {
      throw new SyncTransportError('Cold-decrypt verification mismatch on B blob');
    }
  } finally {
    if (verifyBResult !== null) {
      await secureWipe(verifyBResult.vaultKey); // wipe transient re-derived key (Pitfall 8)
    }
  }

  // Step 5: Both verify passes. Save B first, await ack, then save A (D-01 ordering).
  await saveBBlob(bNewBlob);
  await saveABlob(aNewBlob);

  return mergeResult.counts;
}

// ---------------------------------------------------------------------------
// Initiator orchestration
// ---------------------------------------------------------------------------

/**
 * Run the Phase-10/11 sync initiator flow end-to-end (D-05 steps 1–6).
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
 *   - B's 32-byte vault key is secureWiped in the merge continuation's finally.
 *   - runSyncNow returns `void` — the raw key is NEVER returned to the UI layer.
 *   - No counts/titles/passwords in status messages (Phase 12 fence; T-10-21).
 *
 * @param configDir      Tauri app config directory (passed to `sync_now` Rust command).
 * @param masterPassword The master password as a UTF-8 encoded byte array. CALLER MUST
 *                       zero this in a `finally` block. It is passed directly to
 *                       authCheckBlobAndGetBKey (WASM — never crosses IPC).
 * @returns              void — the Phase-11 merge + save pipeline is complete.
 * @throws {SyncPeerUnreachableError}   if the peer is unreachable / IK handshake fails.
 * @throws {SyncBindingMismatchError}   if the vaultPairId binding check fails.
 * @throws {SyncPartnerBusyError}       if the partner is already syncing (D-08).
 * @throws {SyncLockedMidSyncError}     if the partner locked mid-sync (D-06).
 * @throws {SyncTransportError}         if a framing / IO error or cold-verify failure occurs.
 * @throws {SyncAuthFailedError}        if B's vault uses a different master password.
 * @throws {SyncNoAckError}             if no ack is received from B (D-02b).
 * @throws {SyncPartnerNotSavedError}   if ack received but A's save fails (D-02a).
 * @throws {VaultCorruptError}          if B's received blob is not a valid VaultDocumentV1.
 */
export async function runSyncNow(configDir: string, masterPassword: Uint8Array): Promise<void> {
  // Mark this device as the sync initiator (D-12 — App.svelte B-side toast must not fire
  // for A-initiated done transitions). Set BEFORE setStatus so the flag is true for the
  // entire A-side path. The B-side handleMergedBlobForB never calls runSyncNow, so the
  // flag stays false for incoming (B-side) syncs.
  syncStore.setInitiatorMode(true);
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
        : typed instanceof SyncPartnerBusyError
          ? 'Sync failed: the peer is already syncing. Try again in a moment.'
          : typed instanceof SyncLockedMidSyncError
            ? 'Sync failed: the peer vault locked mid-sync. Unlock the peer and sync again.'
            : 'Sync failed: could not reach the peer. Check that the other device is online and unlocked.',
    );
    throw typed;
  }

  // Step 3: SYNC-05 auth check — authCheckBlobAndGetBKey runs in WASM (core/libsodium).
  // Convert the number[] blob to Uint8Array for the core function.
  syncStore.setStatus('syncing');
  const bBytes = new Uint8Array(bBlobNumbers);

  // B's vault key is a 32-byte Uint8Array returned by authCheckBlobAndGetBKey.
  // Caller-owns-lifecycle: MUST secureWipe it in the merge continuation's finally
  // (SAFE-04 — the merge continuation owns the wipe after re-sealing both vaults).
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

  // ── PHASE-11 MERGE CONTINUATION (D-05 steps 4–6) ─────────────────────────
  //
  // bVaultKey is now in memory. The merge continuation owns the wipe (SAFE-04).
  // Steps 4–6: merge → reseal ×2 → cold-verify ×2 → saveBBlob → saveABlob.
  // applyRemoteMergedBlob is transport-agnostic (D-11) — saveBBlob and saveABlob
  // are the LAN-specific wiring injected here.

  try {
    syncStore.setStatus('merging');

    // Build B's decrypted InnerDoc from the blob returned by authCheckBlobAndGetBKey.
    // parseOuter + decryptInner are CONFIRMED public via index.ts:18 (Plan 04 facts).
    const bDoc = parseOuter(bBytes);
    // Decrypt B's vault to its InnerDoc, then immediately wipe the plaintext bytes (SAFE-04).
    const bInnerBytes = await decryptInner(bDoc.data, bVaultKey);
    let bInner: InnerDoc;
    try {
      bInner = JSON.parse(new TextDecoder().decode(bInnerBytes)) as InnerDoc;
    } finally {
      await secureWipe(bInnerBytes);
    }

    // A's current InnerDoc: vaultSession.vault.entries is already an upgraded InnerDoc
    // (asInnerDoc is module-private at crud.ts:52 — cast confirmed in Plan 04 facts).
    const aVault = vaultSession.vault;
    if (aVault === null) {
      // Session locked mid-sync — surface as lock error.
      syncStore.setError('Sync failed: vault locked mid-sync. Unlock and sync again.');
      throw new SyncLockedMidSyncError('Vault locked mid-sync on A side.');
    }
    const aInner = aVault.entries as InnerDoc;
    const aVaultKey = vaultSession.unsafeGetKey();
    const aDoc = aVault.doc;

    // Merge context for A-side (D-05 / RESEARCH Pattern 5).
    // localDeviceId / remoteDeviceId are used for tiebreaking; they just need to be
    // distinct opaque strings — the real device UUIDs live in peers.json (Phase 9).
    // For Phase 11 we use stable identifiers derived from the vault meta label or
    // fallback to role names ('initiator'/'responder'). Phase 12 can wire the real
    // device IDs from getLocalDeviceInfo when the Phase-12 UI drives sync.
    const mergeCtx: MergeContext = {
      localDeviceId: aDoc.meta.deviceLabel ?? 'initiator',
      remoteDeviceId: bDoc.meta.deviceLabel ?? 'responder',
      localNowMs: Date.now(),
      remoteNowMs: Date.now(),
    };

    // LAN wiring for saveBBlob: convert Uint8Array to number[] for Tauri serialization,
    // then resolve the sync_now oneshot via sync_provide_merged_blob (Rust sends on channel).
    // The ack is implicit: syncProvideMergedBlob blocks until Rust receives the send result.
    // A SyncNoAckError will be thrown from the underlying Rust timeout if no ack arrives (D-02b).
    const saveBBlobLan = async (bNewBlob: Uint8Array): Promise<void> => {
      syncStore.setStatus('saving');
      try {
        await syncProvideMergedBlob(Array.from(bNewBlob));
      } catch (e) {
        // If the Rust side times out awaiting B's ack, map to SyncNoAckError.
        const m = String(e).toLowerCase();
        if (m.includes('ack timeout') || m.includes('no changes confirmed')) {
          throw new SyncNoAckError(
            'sync did not complete — no changes confirmed on this device; sync again',
          );
        }
        throw new SyncTransportError(String(e));
      }
    };

    // LAN wiring for saveABlob (D-01: runs ONLY after B saved + acked).
    // Write the EXACT cold-verified bytes (aNewBlob) through the adapter via saveRawBlob
    // — NOT vaultSession.save(), which would (1) re-seal a SECOND, never-cold-verified
    // ciphertext and (2) suppress the pre-sync backup via content-hash dedup when the
    // merge is a no-op for A (idle peer). saveRawBlob passes no contentHash, so the
    // SAFE-02 pre-sync backup ALWAYS rotates (D-10). Save FIRST, reload on success — so
    // a save failure never leaves A's in-memory state ahead of disk (mirrors the B side).
    const saveABlobLan = async (aNewBlob: Uint8Array): Promise<void> => {
      try {
        await vaultSession.saveRawBlob(aNewBlob, { maxBackups: 5 });
      } catch {
        // D-06 vs D-02a: a lock stolen mid-save is a lock-mid-sync, not a save failure.
        if (vaultSession.vault === null) {
          throw new SyncLockedMidSyncError('Vault locked mid-sync on A side.');
        }
        throw new SyncPartnerNotSavedError(
          'partner updated; this device did not save — sync again',
        );
      }
      // Save committed: reload A's session from the merged entries ($state.raw, D-07).
      // Decrypt the just-written verified bytes to obtain the merged InnerDoc, then wipe
      // the plaintext (SAFE-04). A post-commit reload failure is non-fatal — disk already
      // holds the verified merged blob; the session reflects it on next unlock.
      let aReloadBytes: Uint8Array | null = null;
      try {
        const aReloadDoc = parseOuter(aNewBlob);
        aReloadBytes = await decryptInner(aReloadDoc.data, aVaultKey);
        const aReloadInner = JSON.parse(new TextDecoder().decode(aReloadBytes)) as InnerDoc;
        await vaultSession.reloadFromMergedInner(aReloadInner);
      } catch {
        // non-fatal post-commit reload failure (see above).
      } finally {
        if (aReloadBytes !== null) await secureWipe(aReloadBytes);
      }
    };

    // Run the transport-agnostic merge pipeline.
    const counts = await applyRemoteMergedBlob({
      aInner,
      aVaultKey,
      aDoc,
      bInner,
      bVaultKey,
      bDoc,
      mergeCtx,
      saveBBlob: saveBBlobLan,
      saveABlob: saveABlobLan,
      masterPassword,
    });

    // Full success: store counts (D-16) and update status.
    // Pitfall 7: lastSyncedAt is updated on A only after full success (ack + A-save done).
    syncStore.storeLastCounts(counts);
    syncStore.setStatus('done');
  } catch (e) {
    // Re-throw typed errors directly; map anything else.
    if (
      e instanceof SyncNoAckError ||
      e instanceof SyncPartnerNotSavedError ||
      e instanceof SyncTransportError ||
      e instanceof SyncLockedMidSyncError
    ) {
      if (syncStore.status !== 'error') {
        syncStore.setError(
          e instanceof SyncNoAckError
            ? 'Sync failed: no ack from partner — no changes confirmed. Try again.'
            : e instanceof SyncPartnerNotSavedError
              ? 'Sync failed: partner updated but this device did not save. Sync again.'
              : 'Sync failed: merge or save error. Try again.',
        );
      }
      throw e;
    }
    throw e;
  } finally {
    // SAFE-04: secureWipe bVaultKey on EVERY exit path from the continuation.
    // This replaces the Phase-10 immediate wipe at the old handoff placeholder.
    await secureWipe(bVaultKey);
  }

  // ── END PHASE-11 MERGE CONTINUATION ──────────────────────────────────────
}

// ---------------------------------------------------------------------------
// D-06 listener lifecycle helpers (used by the SyncNowButton $effect)
// ---------------------------------------------------------------------------

// Unlisten function for the B-side 'sync-merged-blob-received' event.
// Stored here so stopSyncListener can clean it up (D-06 close-on-lock).
let _mergedBlobUnlisten: UnlistenFn | null = null;

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
 * PHASE-11: registers the B-side `sync-merged-blob-received` Tauri event listener
 * BEFORE syncListenerStart resolves (Open Question 1 / RESEARCH — eager registration
 * to avoid dropped events: Tauri events are fire-and-forget; a missed event causes
 * ack timeout on A which surfaces as SyncNoAckError).
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
    // Register the B-side event handler EAGERLY before starting the Rust listener
    // so no `sync-merged-blob-received` event can be dropped between start and listen.
    if (_mergedBlobUnlisten === null) {
      _mergedBlobUnlisten = await listen<number[]>(
        'sync-merged-blob-received',
        async (event) => {
          const blobBytes = new Uint8Array(event.payload);
          await handleMergedBlobForB(blobBytes, {
            getBSessionKey: () => vaultSession.unsafeGetKey(),
            getBCurrentInner: () => vaultSession.vault?.entries as InnerDoc,
            getBDoc: () => {
              const v = vaultSession.vault;
              return v !== null ? v.doc : null;
            },
            saveBlob: async (sealedBytes: Uint8Array) => {
              // Save the re-sealed bytes through the adapter's save-mutex + backup rotation.
              // vaultSession.saveRawBlob routes directly to adapter.save() — no second
              // re-encryption; the bytes from resealInnerDoc are already ciphertext (SAFE-02 /
              // Pitfall 5: NOT a direct vault_write_atomic invoke).
              await vaultSession.saveRawBlob(sealedBytes, { maxBackups: 5 });
            },
            reloadSession: async (mergedEntries: object) => {
              await vaultSession.reloadFromMergedInner(mergedEntries);
            },
            confirmSave: syncConfirmSave,
          });
        },
      );
    }

    await syncListenerStart(configDir, vaultPath);
    syncStore.markListenerActive();
  } catch {
    // Non-fatal: if the listener fails to start (e.g. port already bound from a
    // prior session that did not close cleanly), leave listenerActive false so the
    // next $effect trigger will retry.
    syncStore.markListenerInactive();
    // Clean up the event listener if Rust start failed.
    if (_mergedBlobUnlisten !== null) {
      _mergedBlobUnlisten();
      _mergedBlobUnlisten = null;
    }
  }
}

/**
 * Stop the sync listener (D-06 close-on-lock).
 *
 * Called by the D-06 $effect when `vaultSession.isUnlocked` becomes false (the
 * vault locked). Clears the listenerActive guard flag and unregisters the B-side
 * Tauri event listener.
 *
 * Idempotent — safe to call even if the listener was not started (the Rust command
 * is a no-op when no listener is running).
 */
export async function stopSyncListener(): Promise<void> {
  // Clear the flag optimistically — if the stop fails, we re-clear to false anyway.
  syncStore.markListenerInactive();

  // Unregister the B-side event listener (D-06: listener closes on lock).
  if (_mergedBlobUnlisten !== null) {
    _mergedBlobUnlisten();
    _mergedBlobUnlisten = null;
  }

  try {
    await syncListenerStop();
  } catch {
    // Non-fatal: if the stop fails, the Rust listener will eventually time out /
    // be cleaned up on process exit. The flag is already cleared above.
  }
}

// ---------------------------------------------------------------------------
// Phase-11 B-side merged-blob handler (D-05/D-07, SAFE-04, D-01)
// ---------------------------------------------------------------------------

/**
 * Dependency-injection seams for `handleMergedBlobForB` (D-11 + testability).
 */
export interface HandleMergedBlobForBDeps {
  /** Returns B's session key (vaultSession.unsafeGetKey()). */
  getBSessionKey: () => Uint8Array;
  /** Returns B's current in-memory InnerDoc (vaultSession.vault.entries as InnerDoc). */
  getBCurrentInner: () => InnerDoc;
  /** Returns B's outer VaultDocumentV1 (vaultSession.vault.doc), or null if locked. */
  getBDoc: () => import('@cryptiq/core').VaultDocumentV1 | null;
  /**
   * Saves B's re-sealed blob bytes through the adapter (must route through
   * TauriVaultStorageAdapter for save-mutex + backup rotation — Pitfall 5 / SAFE-02).
   * Called with the sealed Uint8Array bytes (NOT plaintext — ciphertext only).
   * Does NOT reload the in-memory session (reloadSession is called after saveBlob).
   */
  saveBlob: (sealedBytes: Uint8Array) => Promise<void>;
  /** Reloads B's in-memory session from the merged InnerDoc (D-07). */
  reloadSession: (mergedEntries: object) => Promise<void>;
  /** Signals Rust that B has saved (true) or failed (false) to resolve the ack oneshot. */
  confirmSave: (saveOk: boolean) => Promise<void>;
}

/**
 * B-side handler for the 'sync-merged-blob-received' Tauri event (D-05/D-07).
 *
 * Decrypts A's merged blob with B's in-memory session key (NOT a master-password
 * re-derive — Pitfall 2), parses + schemaVersion-checks the InnerDoc (fail-closed),
 * re-merges with B's current in-memory doc (D-05), re-seals under B's key,
 * saves through the adapter (mutex serialized, SAFE-02), reloads the session
 * ($state.raw, D-07), then calls confirmSave(true).
 *
 * On ANY failure (decrypt, schema mismatch, save) OR if B's session is locked
 * mid-handler (#vault null, D-06 lock-wins): calls confirmSave(false) and does NOT
 * reload the session. A will surface SyncNoAckError (D-02b).
 *
 * SAFE-04: merged plaintext JSON bytes wiped in finally. B's session key is B's
 * OWN #vaultKey — it is NEVER received over the wire; no key crosses IPC.
 *
 * @param blobBytes Raw ciphertext bytes of A's merged-for-B blob (from Tauri event).
 * @param deps      DI seams (defaults bind to vaultSession).
 */
export async function handleMergedBlobForB(
  blobBytes: Uint8Array,
  deps: HandleMergedBlobForBDeps,
): Promise<void> {
  const { getBSessionKey, getBCurrentInner, getBDoc, saveBlob, reloadSession, confirmSave } = deps;

  syncStore.setStatus('merging');

  try {
    // D-06 lock-wins: if B's vault is locked, abort without reload.
    const bDoc = getBDoc();
    if (bDoc === null) {
      await confirmSave(false);
      syncStore.setStatus('error');
      return;
    }

    // Decrypt A's merged blob with B's in-memory session key (NOT unlockVault+password,
    // NOT a master-password re-derive — Pitfall 2/RESEARCH Pattern 5/Confirmed Facts #5).
    // parseOuter(blobBytes) parses the RECEIVED blob (sealed under B's key by A);
    // decryptInner uses B's SESSION KEY (the in-memory #vaultKey), not a re-derive.
    const bSessionKey = getBSessionKey();
    const receivedBlobDoc = parseOuter(blobBytes);
    // Decrypt A's merged blob with B's in-memory session key, then wipe the plaintext
    // bytes immediately (SAFE-04).
    const innerBytes = await decryptInner(receivedBlobDoc.data, bSessionKey);
    let receivedMerged: InnerDoc;
    try {
      receivedMerged = JSON.parse(new TextDecoder().decode(innerBytes)) as InnerDoc;
    } finally {
      await secureWipe(innerBytes);
    }

    // schemaVersion fail-closed (D-09/HARDEN-02 upstream).
    if (receivedMerged.schemaVersion !== 1 && receivedMerged.schemaVersion !== 2) {
      throw new MergeSchemaMismatchError(
        `Received merged blob has unsupported schemaVersion: ${String(receivedMerged.schemaVersion)}`,
      );
    }

    // B's current InnerDoc for re-merge.
    const bCurrentInner = getBCurrentInner();

    // Re-merge: B's current in-memory doc + received merged doc (D-05, Pattern 5).
    // Both timestamps from B's clock — skew check is no-op (RESEARCH Pattern 5).
    const bCtx: MergeContext = {
      localDeviceId: bDoc.meta.deviceLabel ?? 'responder',
      remoteDeviceId: 'initiator',
      localNowMs: Date.now(),
      remoteNowMs: Date.now(),
    };
    const bMergeResult = mergeInnerDocs(bCurrentInner, receivedMerged, bCtx);
    const bFinal = bMergeResult.merged;

    // Re-seal under B's key (uses session key directly — no re-derive on B).
    // resealInnerDoc is from @cryptiq/core (Plan 01 verb).
    // bFinalBytes = ciphertext sealed bytes passed directly to saveBlob so the
    // adapter receives the exact bytes that reseal produced (SAFE-02 save-mutex +
    // backup rotation). This avoids a second re-encryption in vaultSession.save()
    // and ensures the save step operates on COMMITTED ciphertext before reload.
    const bFinalBytes = await resealInnerDoc(bFinal, bSessionKey, bDoc);

    // D-07 + D-01 ordering: save FIRST through the adapter (mutex serialized —
    // Pitfall 5 / SAFE-02 backup rotation), THEN reload the session on success, THEN
    // confirm to Rust. A failed save propagates to the catch below → no reload,
    // confirmSave(false). resealInnerDoc already zeroed its plaintext byte buffer
    // (SAFE-04); `bFinal` is a live JS object (unwipeable, accepted residual).
    syncStore.setStatus('saving');
    await saveBlob(bFinalBytes);

    // Save succeeded: reload the session from merged entries ($state.raw, D-07).
    await reloadSession(bFinal);

    // Store per-device counts (D-16).
    syncStore.storeLastCounts(bMergeResult.counts);
    // Resolve the Rust oneshot → listener sends ack to A (D-01).
    await confirmSave(true);
    syncStore.setStatus('done');
  } catch {
    // Any failure → confirmSave(false) so A surfaces SyncNoAckError (D-02b).
    // Do NOT reload the session on failure (B's state stays consistent).
    try {
      await confirmSave(false);
    } catch {
      // Best-effort — Rust-side oneshot may have already timed out.
    }
    syncStore.setStatus('error');
    syncStore.setError('Sync failed: could not apply the received merged vault. Sync again.');
  }
}
