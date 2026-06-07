// packages/core/src/sync/syncAuth.ts
//
// SYNC-05 same-master-password auth check (Phase 10, Plan 04).
//
// Purpose: prove that both vaults (A's and B's) share the same master password BEFORE
// any merge is attempted. When A receives B's full encrypted vault blob over the Noise
// IK channel, A parses the blob and re-derives an Argon2id key using B's OWN KDF params
// (B's salt, opsLimit, memLimit — different from A's since each vault has a unique salt).
// A then calls tryUnwrap against B's master wrap. A null result (AEAD MAC failure) means
// the passwords differ → SyncAuthFailedError (SYNC-05). A non-null 32-byte result is B's
// vault key; the caller owns its lifecycle + secureWipe (Phase 11 SAFE-04 will wipe it).
//
// SECURITY PROPERTIES (threat register T-10-14 through T-10-17):
//   - Master password NEVER crosses IPC: this function takes the password as a JS arg only;
//     Rust returns only ciphertext bytes (T-10-15).
//   - Transient derived key memzero'd in a finally on EVERY exit path (T-10-16).
//   - Malformed/hostile B blob: parseOuter validates the envelope and throws
//     VaultCorruptError before any key derivation occurs (T-10-17).
//   - Fail closed: MAC failure or missing master wrap → SyncAuthFailedError (T-10-14).
//
// CORE PURITY: no @tauri-apps/*, no svelte, no node:fs / node:path. Sodium accessed
// ONLY via getSodium() (SEC-01/SEC-02). No console.* (CLAUDE.md convention).
//
// Source: RESEARCH Resolution 6 (3-step auth check), CONTEXT D-03 (no master-pw caching),
//   10-04-PLAN.md Task 1 action spec.

import { getSodium } from '../crypto/sodium';
import { deriveKey } from '../crypto/kdf';
import type { KdfParams } from '../crypto/kdf';
import { tryUnwrap } from '../crypto/wrap';
import type { WrappedKey } from '../crypto/wrap';
import { parseOuter } from '../vault/serialize';
import { SyncAuthFailedError } from '../errors';

/**
 * Reconstruct runtime KdfParams from a WrappedKey's per-wrap kdf field (DC-3).
 * Decodes the base64 salt back to bytes using the ORIGINAL variant (decision 27 /
 * Pitfall D — must match the ORIGINAL variant used by wrapKey to encode it).
 * Mirrors the private `wrappedKdfParams` helper in vault.ts — kept local to avoid
 * exposing vault.ts internals on the public API surface.
 */
async function resolveKdfParams(wrapped: WrappedKey): Promise<KdfParams> {
  const sodium = await getSodium();
  return {
    algorithm: 2,
    opsLimit: wrapped.kdf.opsLimit,
    memLimit: wrapped.kdf.memLimit,
    salt: sodium.from_base64(wrapped.kdf.salt, sodium.base64_variants.ORIGINAL),
  };
}

/**
 * SYNC-05 auth check: prove that the master password supplied by A also unlocks B's
 * vault. Called after B's full encrypted vault blob arrives over the Noise IK channel
 * and BEFORE any merge operation (D-05 step 3).
 *
 * Algorithm:
 *   1. parseOuter(bBlobBytes) — validate B's envelope (throws VaultCorruptError on
 *      malformed input; propagated as-is to the caller).
 *   2. Read bDoc.wrappedKeys['master'] — absent → SyncAuthFailedError.
 *   3. Re-derive an Argon2id key using B's OWN KDF params (B's salt, B's opsLimit,
 *      B's memLimit — NOT A's params, since each vault has a unique salt per DC-3).
 *   4. tryUnwrap(bMasterWrap, derivedKey) → null (MAC failure) → SyncAuthFailedError.
 *   5. memzero the derived key in a `finally` on EVERY exit path (T-10-16).
 *   6. Return the 32-byte B vault key. CALLER OWNS its lifecycle + secureWipe (Phase 11).
 *
 * @param masterPassword  The master password as a UTF-8 encoded byte array (never logged,
 *                        never persisted, never sent over IPC — D-03 / T-10-15).
 * @param bBlobBytes      B's full encrypted vault bytes received over the IK channel
 *                        (Rust shuttled only ciphertext; parsing validates the envelope).
 * @returns               B's 32-byte vault key on success. Caller MUST secureWipe it
 *                        after use (Phase 11 SAFE-04).
 * @throws {VaultCorruptError}    if bBlobBytes is not a valid VaultDocumentV1 envelope.
 * @throws {SyncAuthFailedError}  if the master password does not match B's vault, or if
 *                                B's vault has no `master` wrap.
 */
export async function authCheckBlobAndGetBKey(
  masterPassword: Uint8Array,
  bBlobBytes: Uint8Array,
): Promise<Uint8Array> {
  // Await sodium to ensure WASM is initialized before any crypto operation.
  const sodium = await getSodium();

  // Step 1: Parse and validate B's outer vault envelope. Throws VaultCorruptError on any
  // structural problem (bad JSON, missing format/version/wrappedKeys/data/meta).
  // We propagate VaultCorruptError as-is — it is already a typed, fail-closed error.
  const bDoc = parseOuter(bBlobBytes);

  // Step 2: Read B's master wrap. An absent master wrap means B's vault is structurally
  // invalid for our purposes — fail closed with SyncAuthFailedError (not VaultCorruptError,
  // since parseOuter already accepted the envelope; missing master is a sync-level concern).
  //
  // NOTE (defense-in-depth): in practice, parseOuter (step 1 above, serialize.ts lines
  // 83-88) is the PRIMARY gate for a missing wrappedKeys.master — it throws VaultCorruptError
  // before returning, so this guard is unreachable for any normally-parsed blob. It is
  // retained as defense-in-depth for a future caller that pre-parses the doc and bypasses
  // parseOuter's check.
  const bMasterWrap = bDoc.wrappedKeys['master'];
  if (bMasterWrap === undefined) {
    throw new SyncAuthFailedError('peer vault has no master wrap');
  }

  // Step 3: Re-derive Argon2id using B's OWN KDF params (B's salt, opsLimit, memLimit).
  // B's params MUST be used — not A's. Each vault has a unique salt (DC-3 per-wrap params).
  // Resolve the runtime KdfParams from the stored base64 salt (ORIGINAL variant, Pitfall D).
  const bKdfParams = await resolveKdfParams(bMasterWrap);
  const derivedKey = await deriveKey(masterPassword, bKdfParams);

  // Step 4 + Step 5 (combined try/finally):
  // Attempt to unwrap B's vault key. memzero the transient derived key on EVERY exit —
  // whether tryUnwrap succeeds, returns null, or throws (e.g. KdfResourceError) (T-10-16).
  let bVaultKey: Uint8Array | null;
  try {
    bVaultKey = await tryUnwrap(bMasterWrap, derivedKey);
  } finally {
    // Zeroize the transient Argon2id key on every exit (T-10-16 / SEC-09 / WR-02).
    // This runs before the null-check below, ensuring the key is wiped even on success
    // (the bVaultKey is the unwrapped content, distinct from the derivedKey).
    sodium.memzero(derivedKey);
    // Also wipe the decoded salt bytes produced by resolveKdfParams — they are no longer
    // needed after derivation completes.
    sodium.memzero(bKdfParams.salt);
  }

  // Step 6: Evaluate the tryUnwrap result.
  // null = AEAD MAC failure = the master passwords differ → SYNC-05 typed error.
  // A non-null result is B's vault key — return it; the caller owns the lifecycle (Phase 11).
  if (bVaultKey === null) {
    throw new SyncAuthFailedError(
      'peer vault uses a different master password — ensure both vaults share the same password',
    );
  }

  // Return B's 32-byte vault key. CALLER MUST secureWipe it after use (Phase 11 SAFE-04).
  // Phase 10 does not merge or re-seal — it just proves the same-password gate and returns
  // the key so Phase 11 can perform the re-seal step.
  return bVaultKey;
}
