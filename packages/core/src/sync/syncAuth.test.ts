// packages/core/src/sync/syncAuth.test.ts
//
// SYNC-05 Vitest suite for authCheckBlobAndGetBKey (Phase 10, Plan 04).
//
// IMPORTANT: These tests run under the core Vitest runner (NOT the desktop browser suite).
// No @tauri-apps/*, no Svelte, no Math.random (CLAUDE.md crypto rules).
//
// Test coverage (per 10-04-PLAN.md Task 2 acceptance criteria):
//   (1) correct password  → resolves to Uint8Array of length 32 (B's vault key)
//   (2) wrong password    → rejects with SyncAuthFailedError (SYNC-05)
//   (3) blob missing 'master' wrap → rejects with SyncAuthFailedError
//   (4) structurally corrupt bytes → rejects (VaultCorruptError from parseOuter)
//
// Fixture strategy: build a real B blob via createVault + saveVault using the kdfParams
// test seam (floor params: 256 MiB / 3 ops) to keep runtime reasonable while exercising
// real Argon2id. This mirrors the pattern in vault.test.ts / round-trip.test.ts.
//
// Filter: `pnpm --filter @cryptiq/core test -- sync-auth` selects this file (describe
// block prefix "sync-auth" matches the filter).

import { describe, it, expect, beforeAll } from 'vitest';
import { createVault, saveVault } from '../vault/vault';

import { getSodium } from '../crypto/sodium';
import { authCheckBlobAndGetBKey } from './syncAuth';
import { SyncAuthFailedError } from '../errors';
import { VaultCorruptError } from '../errors';

// ---------------------------------------------------------------------------
// Constants and helpers — floor params to keep Argon2id fast in CI (real KDF,
// just not calibrated). NEVER use Math.random near secrets (CLAUDE.md rule).
// ---------------------------------------------------------------------------

const FLOOR_OPS = 3;
const FLOOR_MEM = 268_435_456; // 256 MiB

function pw(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

async function floorParams() {
  const sodium = await getSodium();
  return {
    algorithm: 2 as const,
    opsLimit: FLOOR_OPS,
    memLimit: FLOOR_MEM,
    salt: sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES),
  };
}

// ---------------------------------------------------------------------------
// Shared fixture: B's sealed vault blob under B_PASSWORD.
// Built once in beforeAll for the suite to avoid repeated Argon2id calls.
// ---------------------------------------------------------------------------

const B_PASSWORD = 'correct-horse-battery-staple-B';
const WRONG_PASSWORD = 'this-is-definitely-wrong!#$%';

let bBlobBytes: Uint8Array;
// FIX 6a: capture B's REAL vault key before saveVault so test (1) can byte-compare
// authCheckBlobAndGetBKey's return value against the key that was actually produced
// by createVault. A defensive .slice() is taken so the reference is immutable even
// if createVault's internals or a caller later zeroize the original buffer.
let bRealKey: Uint8Array;

beforeAll(async () => {
  // Create a real VaultDocumentV1 for "B" under B_PASSWORD using the test seam.
  const created = await createVault({
    masterPassword: pw(B_PASSWORD),
    withRecoveryKey: false,
    kdfParams: await floorParams(),
  });
  // Capture a defensive copy of B's real vault key BEFORE saveVault — saveVault
  // does NOT wipe the caller's vaultKey (vault.ts:saveVault only calls encryptInner +
  // serializeOuter; the caller owns the key lifecycle).
  bRealKey = created.vaultKey.slice();
  // saveVault re-seals the entries (with a fresh nonce) and returns serialized bytes.
  bBlobBytes = await saveVault(created.vault, created.vaultKey);
}, 120_000); // Argon2id at floor params takes ~1–3s; 120s is ample for beforeAll

// ---------------------------------------------------------------------------
// describe block — prefixed "sync-auth" so `-- sync-auth` filter selects it.
// ---------------------------------------------------------------------------

describe('sync-auth: authCheckBlobAndGetBKey (SYNC-05)', () => {
  // -------------------------------------------------------------------------
  // Test 1: correct password → 32-byte B vault key that byte-equals B's real key
  //
  // FIX 6a: assert that authCheckBlobAndGetBKey returns B's ACTUAL vault key, not
  // just any 32-byte value. We compare against bRealKey (captured in beforeAll before
  // saveVault) using libsodium's constant-time memcmp (never a byte-loop with early
  // exit — SEC-09 / CLAUDE.md). An implementation that returned the transient Argon2id
  // derived key instead of the unwrapped vault key would fail this assertion even
  // though the derived key is also 32 non-zero bytes.
  // -------------------------------------------------------------------------
  it('(1) correct password resolves to a Uint8Array of length 32', async () => {
    const bKey = await authCheckBlobAndGetBKey(pw(B_PASSWORD), bBlobBytes);
    expect(bKey).toBeInstanceOf(Uint8Array);
    expect(bKey.length).toBe(32);
    // Byte-equality against B's real vault key (constant-time, matches CLAUDE.md rule
    // prohibiting early-exit comparisons on secret material).
    const sodium = await getSodium();
    expect(bKey.length).toBe(bRealKey.length); // memcmp requires equal lengths
    expect(sodium.memcmp(bKey, bRealKey)).toBe(true);
  }, 60_000);

  // -------------------------------------------------------------------------
  // Test 2: wrong password → SyncAuthFailedError (SYNC-05)
  // -------------------------------------------------------------------------
  it('(2) wrong password rejects with SyncAuthFailedError', async () => {
    await expect(
      authCheckBlobAndGetBKey(pw(WRONG_PASSWORD), bBlobBytes),
    ).rejects.toBeInstanceOf(SyncAuthFailedError);
  }, 60_000);

  it('(2) wrong password SyncAuthFailedError has stable code SYNC_AUTH_FAILED', async () => {
    let thrown: SyncAuthFailedError | null = null;
    try {
      await authCheckBlobAndGetBKey(pw(WRONG_PASSWORD), bBlobBytes);
    } catch (err) {
      thrown = err as SyncAuthFailedError;
    }
    expect(thrown).not.toBeNull();
    expect(thrown?.code).toBe('SYNC_AUTH_FAILED');
  }, 60_000);

  // -------------------------------------------------------------------------
  // Test 3: blob with the 'master' wrap surgically removed → VaultCorruptError
  //
  // FIX 6b: parseOuter in serialize.ts (lines 83-88) is the PRIMARY fail-closed gate
  // for a missing master wrap — it checks for wrappedKeys.master BEFORE returning the
  // parsed doc and throws VaultCorruptError("wrappedKeys.master is required") when it
  // is absent. Because parseOuter runs as the FIRST step in authCheckBlobAndGetBKey
  // (before any KDF or tryUnwrap), a blob with no master wrap NEVER reaches the
  // guard inside syncAuth.ts (line 93-95). The real thrown type is VaultCorruptError.
  //
  // The `bMasterWrap === undefined` guard inside syncAuth.ts IS intentional
  // defense-in-depth for a future parseOuter change or a pre-parsed doc path
  // that bypasses parseOuter's check — but it is unreachable for any blob processed
  // via the normal authCheckBlobAndGetBKey path.
  //
  // This test asserts the ACTUAL observable behavior precisely, not an "accept either"
  // approximation.
  // -------------------------------------------------------------------------
  it('(3) blob missing master wrap rejects with VaultCorruptError (parseOuter is the primary gate)', async () => {
    // Surgically remove the master wrap from an otherwise valid vault document.
    const text = new TextDecoder().decode(bBlobBytes);
    const doc = JSON.parse(text) as Record<string, unknown>;
    const wrappedKeys = doc.wrappedKeys as Record<string, unknown>;
    delete wrappedKeys['master'];
    const noMasterBlob = new TextEncoder().encode(JSON.stringify(doc));

    // parseOuter is the gate — it throws VaultCorruptError before any crypto runs.
    await expect(
      authCheckBlobAndGetBKey(pw(B_PASSWORD), noMasterBlob),
    ).rejects.toBeInstanceOf(VaultCorruptError);
  }, 60_000);

  // -------------------------------------------------------------------------
  // Test 4: structurally corrupt bytes → rejects (VaultCorruptError from parseOuter)
  // -------------------------------------------------------------------------
  it('(4) corrupt bytes reject (VaultCorruptError or SyncAuthFailedError)', async () => {
    const corrupt = new Uint8Array([0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd]);
    await expect(
      authCheckBlobAndGetBKey(pw(B_PASSWORD), corrupt),
    ).rejects.toBeInstanceOf(VaultCorruptError);
  }, 60_000);

  it('(4) corrupt JSON (valid UTF-8 but not valid vault JSON) rejects with VaultCorruptError', async () => {
    const corrupt = new TextEncoder().encode('{"format":"not-a-vault","version":1}');
    await expect(
      authCheckBlobAndGetBKey(pw(B_PASSWORD), corrupt),
    ).rejects.toBeInstanceOf(VaultCorruptError);
  }, 60_000);

  // -------------------------------------------------------------------------
  // Additional property: correct password → key is non-zero (not all zeros)
  // This checks that we are not getting the zero-buffer OOM sentinel (Pitfall A).
  // -------------------------------------------------------------------------
  it('(1-extra) the returned 32-byte key is not all-zeros (not an OOM sentinel)', async () => {
    const bKey = await authCheckBlobAndGetBKey(pw(B_PASSWORD), bBlobBytes);
    const isAllZero = bKey.every((b) => b === 0);
    expect(isAllZero).toBe(false);
  }, 60_000);
});
