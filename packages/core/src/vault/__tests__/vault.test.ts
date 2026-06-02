// packages/core/src/vault/__tests__/vault.test.ts
//
// Phase 5 — Plan 05-01 (Task 2): AUTH-10 / AUTH-11 core assertions.
//
// Requirements covered:
//   AUTH-10 — changeMasterPassword re-wraps master key; entries blob (data.ciphertext)
//             untouched; recovery wrap (wrappedKeys.recovery) untouched.
//   AUTH-11 — changeMasterPassword always re-derives Argon2id; the call NEVER
//             completes in < 100ms (no cached plaintext / shortcut path).
//
// These are ADDITIVE tests on top of the existing round-trip.test.ts. They do NOT
// re-test the full round-trip contract (that lives in round-trip.test.ts), but focus
// on the two Phase-5 invariants: timing >= 100ms and recovery-wrap byte-equality.
//
// Test seam: all tests use floor kdf params (256 MiB / 3 ops) so the suite stays fast
// while still exercising real Argon2id (no mocked derive). This is the SAME seam used
// throughout the existing vault test suite.
//
// Note on timing: 100ms is a minimum FLOOR (P5-02, ROADMAP SC5 "never < 100ms").
// With real Argon2id at floor params on modern hardware the call takes ~1–3s; the
// floor assert just verifies the shortcut/cache path is absent.

import { describe, it, expect } from 'vitest';
import { createVault, saveVault, changeMasterPassword } from '../vault';
import { getSodium } from '../../crypto/sodium';

// ---------------------------------------------------------------------------
// Helpers — mirrored from round-trip.test.ts (same seam)
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
// AUTH-10: data ciphertext + recovery wrap are byte-identical after master change
// ---------------------------------------------------------------------------

describe('changeMasterPassword — AUTH-10 envelope invariants', () => {
  it('data.ciphertext is byte-identical before and after master change (VAULT-02 envelope)', async () => {
    const oldPw = pw('old-master-passphrase!');
    const newPw = pw('new-master-passphrase-much-longer!');
    const created = await createVault({
      masterPassword: oldPw,
      withRecoveryKey: false,
      kdfParams: await floorParams(),
    });

    // Capture data ciphertext BEFORE master change.
    const dataBefore = created.vault.doc.data.ciphertext;

    await changeMasterPassword(created.vault, created.vaultKey, {
      currentPassword: oldPw,
      newPassword: newPw,
      kdfParams: await floorParams(),
    });

    // VAULT-02: re-wrapping the master key MUST NOT re-encrypt the data blob.
    expect(created.vault.doc.data.ciphertext).toBe(dataBefore);
  }, 60_000);

  it('wrappedKeys.recovery is byte-identical before and after master change (AUTH-10)', async () => {
    // Create a vault WITH a recovery key — this is the precondition for the
    // recovery-wrap-untouched assertion.
    const oldPw = pw('old-password-with-recovery');
    const newPw = pw('new-password-after-recovery-check');
    const created = await createVault({
      masterPassword: oldPw,
      withRecoveryKey: true,
      kdfParams: await floorParams(),
    });

    // The recovery wrap must exist for this test to be meaningful.
    expect(created.vault.doc.wrappedKeys.recovery).toBeDefined();

    // Snapshot the recovery wrap BEFORE master change.
    // JSON.stringify is safe here — the wrap is a plain serializable object.
    const recoveryBefore = JSON.stringify(created.vault.doc.wrappedKeys.recovery);

    await changeMasterPassword(created.vault, created.vaultKey, {
      currentPassword: oldPw,
      newPassword: newPw,
      kdfParams: await floorParams(),
    });

    // AUTH-10 (and P5-10 "your recovery key still works" guarantee): changing the master
    // key MUST leave the recovery wrap untouched — byte-for-byte identical.
    const recoveryAfter = JSON.stringify(created.vault.doc.wrappedKeys.recovery);
    expect(recoveryAfter).toBe(recoveryBefore);
  }, 60_000);

  it('data.nonce is byte-identical before and after master change (fresh nonce only on saveVault)', async () => {
    // Verifies that changeMasterPassword does NOT call saveVault / re-encrypt the blob.
    const oldPw = pw('old-password-nonce-check');
    const newPw = pw('new-password-nonce-check');
    const created = await createVault({
      masterPassword: oldPw,
      withRecoveryKey: false,
      kdfParams: await floorParams(),
    });
    const nonceBefore = created.vault.doc.data.nonce;

    await changeMasterPassword(created.vault, created.vaultKey, {
      currentPassword: oldPw,
      newPassword: newPw,
      kdfParams: await floorParams(),
    });

    expect(created.vault.doc.data.nonce).toBe(nonceBefore);
  }, 60_000);

  it('saveVault after master change produces a valid re-serialization (sanity)', async () => {
    // Confirms the mutated doc is still serializable (no torn state from changeMasterPassword).
    const oldPw = pw('old-pass-sanity');
    const newPw = pw('new-pass-sanity-check');
    const created = await createVault({
      masterPassword: oldPw,
      withRecoveryKey: false,
      kdfParams: await floorParams(),
    });

    await changeMasterPassword(created.vault, created.vaultKey, {
      currentPassword: oldPw,
      newPassword: newPw,
      kdfParams: await floorParams(),
    });

    // saveVault must not throw.
    const bytes = await saveVault(created.vault, created.vaultKey);
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBeGreaterThan(0);
  }, 60_000);
});

// ---------------------------------------------------------------------------
// AUTH-11: changeMasterPassword always re-derives; never < 100ms (SC5)
// ---------------------------------------------------------------------------

describe('changeMasterPassword — AUTH-11 re-derive timing (>= 100ms)', () => {
  it('changeMasterPassword takes >= 100ms end-to-end (ROADMAP SC5, AUTH-11)', async () => {
    // This assert catches any shortcut / caching path that would skip Argon2id.
    // With real Argon2id at floor params, the call takes ~1–3s on modern hardware;
    // we only require >= 100ms so this test stays fast even on slow CI runners
    // while still ruling out a sub-100ms fast-path.
    const oldPw = pw('timing-test-old-password');
    const newPw = pw('timing-test-new-password-longer');
    const created = await createVault({
      masterPassword: oldPw,
      withRecoveryKey: false,
      kdfParams: await floorParams(),
    });

    const t0 = performance.now();
    await changeMasterPassword(created.vault, created.vaultKey, {
      currentPassword: oldPw,
      newPassword: newPw,
      kdfParams: await floorParams(),
    });
    const elapsed = performance.now() - t0;

    expect(elapsed).toBeGreaterThanOrEqual(100);
  }, 60_000);
});
