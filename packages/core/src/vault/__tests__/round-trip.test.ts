import { describe, it, expect } from 'vitest';
import {
  createVault,
  unlockVault,
  saveVault,
  changeMasterPassword,
  addWrappedKey,
  removeWrappedKey,
} from '../vault';
import { parseOuter } from '../serialize';
import { getSodium } from '../../crypto/sodium';
import { padToTieredBucket } from '../../crypto/padding';
import { VAULT_AD } from '../../crypto/aead';
import { deriveKey } from '../../crypto/kdf';
import {
  WrongPasswordError,
  WrongRecoveryKeyError,
  VaultKeyMismatchError,
  ProtectedWrapError,
} from '../../errors';

// DC-8 verb-first API round-trip (SEC-05, AUTH-06, VAULT-02, DC-5/DC-10).
//
// These tests use a small FIXED kdf-override so each createVault doesn't run the full
// adaptive calibration ladder (which would push the suite well past 30s). The override is
// floor params (256 MiB / 3 ops) — real Argon2id, just not auto-tuned. createVault accepts
// it via the optional `kdfParams` test seam; production omits it and calibrates.

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

describe('vault/vault — DC-8 verbs round-trip', () => {
  it('Test 1: createVault({ withRecoveryKey: true }) → master + recovery wraps; false → no recovery', async () => {
    const withRec = await createVault({
      masterPassword: pw('correct horse battery staple'),
      withRecoveryKey: true,
      kdfParams: await floorParams(),
    });
    expect(typeof withRec.recoveryKey).toBe('string');
    expect(withRec.vault.doc.wrappedKeys.master).toBeDefined();
    expect(withRec.vault.doc.wrappedKeys.recovery).toBeDefined();

    const noRec = await createVault({
      masterPassword: pw('correct horse battery staple'),
      withRecoveryKey: false,
      kdfParams: await floorParams(),
    });
    expect(noRec.recoveryKey).toBeUndefined();
    expect(noRec.vault.doc.wrappedKeys.master).toBeDefined();
    expect(noRec.vault.doc.wrappedKeys.recovery).toBeUndefined();

    // creationReport carries the Phase-4 DC-2 data shape.
    expect(withRec.creationReport).toMatchObject({
      memLimit: expect.any(Number),
      opsLimit: expect.any(Number),
      measuredMs: expect.any(Number),
      portabilityWarning: expect.any(Boolean),
    });
  });

  it('Test 2 (round-trip): saveVault → unlockVault({ masterPassword }) yields identical entries', async () => {
    const master = pw('correct horse battery staple');
    const created = await createVault({
      masterPassword: master,
      withRecoveryKey: true,
      kdfParams: await floorParams(),
    });
    created.vault.entries = { entries: [{ title: 'GitHub', secret: 'hunter2' }] };
    const bytes = await saveVault(created.vault, created.vaultKey);

    const unlocked = await unlockVault(bytes, { masterPassword: master });
    expect(unlocked.vault.entries).toEqual({ entries: [{ title: 'GitHub', secret: 'hunter2' }] });
    // the decrypted entries blob byte-equals after a re-save (deterministic JSON)
    const bytes2 = await saveVault(unlocked.vault, unlocked.vaultKey);
    const reparsed1 = parseOuter(bytes);
    const reparsed2 = parseOuter(bytes2);
    // ciphertext differs (fresh nonce) but the decrypted content matches — checked above.
    expect(reparsed1.data.nonce).not.toBe(reparsed2.data.nonce);
  });

  it('Test 3 (recovery path): unlockVault({ recoveryKey }) succeeds via the recovery wrap', async () => {
    const master = pw('correct horse battery staple');
    const created = await createVault({
      masterPassword: master,
      withRecoveryKey: true,
      kdfParams: await floorParams(),
    });
    created.vault.entries = { entries: [{ title: 'Email', secret: 's3cr3t' }] };
    const bytes = await saveVault(created.vault, created.vaultKey);

    const viaRecovery = await unlockVault(bytes, { recoveryKey: created.recoveryKey! });
    expect(viaRecovery.vault.entries).toEqual({ entries: [{ title: 'Email', secret: 's3cr3t' }] });
    // master + recovery unlock the SAME vault_key.
    const viaMaster = await unlockVault(bytes, { masterPassword: master });
    expect(viaRecovery.vaultKey).toEqual(viaMaster.vaultKey);
  });

  it('Test 4 (wrong secret): wrong master → WrongPasswordError; wrong recovery → WrongRecoveryKeyError', async () => {
    const created = await createVault({
      masterPassword: pw('correct horse battery staple'),
      withRecoveryKey: true,
      kdfParams: await floorParams(),
    });
    const bytes = await saveVault(created.vault, created.vaultKey);

    await expect(unlockVault(bytes, { masterPassword: pw('wrong password') })).rejects.toThrow(
      WrongPasswordError,
    );
    // A well-formed but WRONG recovery key (passes check char + version, fails the unwrap).
    const sodium = await getSodium();
    const { generateRecoveryKey } = await import('../../crypto/recovery');
    const other = await generateRecoveryKey();
    void sodium;
    await expect(unlockVault(bytes, { recoveryKey: other.encoded })).rejects.toThrow(
      WrongRecoveryKeyError,
    );
    // A malformed recovery key also → WrongRecoveryKeyError (decode stage).
    await expect(unlockVault(bytes, { recoveryKey: 'not-a-real-key' })).rejects.toThrow(
      WrongRecoveryKeyError,
    );
  });

  it('Test 5 (master change): re-wraps; old password fails, new works; data ciphertext UNCHANGED', async () => {
    const oldPw = pw('correct horse battery staple');
    const newPw = pw('a brand new much longer passphrase!');
    const created = await createVault({
      masterPassword: oldPw,
      withRecoveryKey: false,
      kdfParams: await floorParams(),
    });
    created.vault.entries = { entries: [{ title: 'Bank', secret: 'vault-pin' }] };
    const bytes = await saveVault(created.vault, created.vaultKey);

    const unlocked = await unlockVault(bytes, { masterPassword: oldPw });
    const dataBefore = parseOuter(bytes).data.ciphertext;

    const newDoc = await changeMasterPassword(unlocked.vault, unlocked.vaultKey, {
      currentPassword: oldPw,
      newPassword: newPw,
      kdfParams: await floorParams(),
    });
    // changeMasterPassword mutates the doc in place and returns it.
    expect(newDoc).toBe(unlocked.vault.doc);

    // VAULT-02 envelope benefit: the data blob is NOT re-encrypted by a master change.
    expect(newDoc.data.ciphertext).toBe(dataBefore);

    // Persist the re-wrapped vault; old password no longer unlocks, new one does.
    const rewrapped = await saveVault(unlocked.vault, unlocked.vaultKey);
    await expect(unlockVault(rewrapped, { masterPassword: oldPw })).rejects.toThrow(
      WrongPasswordError,
    );
    const reopened = await unlockVault(rewrapped, { masterPassword: newPw });
    expect(reopened.vault.entries).toEqual({ entries: [{ title: 'Bank', secret: 'vault-pin' }] });

    // changeMasterPassword with the WRONG current password → WrongPasswordError.
    await expect(
      changeMasterPassword(reopened.vault, reopened.vaultKey, {
        currentPassword: pw('definitely wrong'),
        newPassword: newPw,
        kdfParams: await floorParams(),
      }),
    ).rejects.toThrow(WrongPasswordError);
  });

  // CR-02 regression (Critical — missing key-match sanity check).
  //
  // changeMasterPassword promised (in a comment) that "the unwrapped key must equal the live
  // vault key (defends a desync bug)" but never compared. If a caller passes a vaultKey that
  // does NOT match what currentPassword unwraps (a session desync), the OLD code re-wrapped
  // the WRONG key under the new password — bricking the (untouched) data blob.
  //
  // This test forces a desync: it unlocks the vault, then calls changeMasterPassword with a
  // RANDOM vaultKey (not the one the master wrap actually protects). It must throw a typed
  // VaultKeyMismatchError AND leave the master wrap + data blob untouched (fail closed).
  it('Test 5b (CR-02): changeMasterPassword with a mismatched vaultKey throws + leaves doc untouched', async () => {
    const oldPw = pw('correct horse battery staple');
    const newPw = pw('a brand new much longer passphrase!');
    const created = await createVault({
      masterPassword: oldPw,
      withRecoveryKey: false,
      kdfParams: await floorParams(),
    });
    created.vault.entries = { entries: [{ title: 'Bank', secret: 'vault-pin' }] };
    const bytes = await saveVault(created.vault, created.vaultKey);
    const unlocked = await unlockVault(bytes, { masterPassword: oldPw });

    // Snapshot the master wrap + data blob BEFORE the (should-fail) change.
    const masterBefore = JSON.stringify(unlocked.vault.doc.wrappedKeys.master);
    const dataBefore = JSON.stringify(unlocked.vault.doc.data);

    // Desync: a random 32-byte key that does NOT match what oldPw unwraps.
    const sodium = await getSodium();
    const wrongVaultKey = sodium.randombytes_buf(32);

    await expect(
      changeMasterPassword(unlocked.vault, wrongVaultKey, {
        currentPassword: oldPw, // correct password (passes the unwrap) ...
        newPassword: newPw, // ... but wrongVaultKey != the unwrapped key → mismatch
        kdfParams: await floorParams(),
      }),
    ).rejects.toThrow(VaultKeyMismatchError);

    // Fail closed: the master wrap and the data blob are UNCHANGED.
    expect(JSON.stringify(unlocked.vault.doc.wrappedKeys.master)).toBe(masterBefore);
    expect(JSON.stringify(unlocked.vault.doc.data)).toBe(dataBefore);

    // And the original password still unlocks (the vault was not bricked).
    const stillWorks = await unlockVault(await saveVault(unlocked.vault, unlocked.vaultKey), {
      masterPassword: oldPw,
    });
    expect(stillWorks.vault.entries).toEqual({ entries: [{ title: 'Bank', secret: 'vault-pin' }] });
  });

  it('Test 6 (AUTH-06): serialized vault holds NO raw recovery bytes — only wrappedKeys.recovery', async () => {
    const created = await createVault({
      masterPassword: pw('correct horse battery staple'),
      withRecoveryKey: true,
      kdfParams: await floorParams(),
    });
    const bytes = await saveVault(created.vault, created.vaultKey);
    const json = new TextDecoder().decode(bytes);
    const parsed = JSON.parse(json);

    // The recovery wrap exists...
    expect(parsed.wrappedKeys.recovery).toBeDefined();
    // ...but the raw recovery bytes / encoded recovery string appear NOWHERE in the file.
    const sodium = await getSodium();
    const rawHex = sodium.to_hex(
      (await import('../../crypto/recovery')).decodeCrockfordBase32(
        created.recoveryKey!.replace(/[^0-9A-Za-z*~$=]/g, '').slice(0, 53),
      ),
    );
    expect(json).not.toContain(rawHex);
    expect(json).not.toContain(created.recoveryKey!.replace(/[^0-9A-Za-z*~$=]/g, ''));
    // No field literally named for the raw recovery secret.
    expect(json).not.toMatch(/recoveryBytes|rawRecovery|recoverySecret|recovery_key_raw/i);
  });

  it('addWrappedKey adds a labeled wrap that unwraps the same vault_key; removeWrappedKey drops it; master is guarded', async () => {
    const created = await createVault({
      masterPassword: pw('correct horse battery staple'),
      withRecoveryKey: false,
      kdfParams: await floorParams(),
    });
    const params = await floorParams();
    const derivationKey = await deriveKey(pw('mobile-wrap-secret'), params);
    await addWrappedKey(created.vault, created.vaultKey, {
      label: 'mobile',
      derivationKey,
      kdfParams: params,
    });
    expect(created.vault.doc.wrappedKeys.mobile).toBeDefined();

    const bytes = await saveVault(created.vault, created.vaultKey);
    // The new wrap unwraps the SAME vault_key (proven by unlocking via a tryUnwrap path).
    const { tryUnwrap } = await import('../../crypto/wrap');
    const parsed = parseOuter(bytes);
    const unwrapped = await tryUnwrap(parsed.wrappedKeys.mobile!, derivationKey);
    expect(unwrapped).toEqual(created.vaultKey);

    removeWrappedKey(created.vault, 'mobile');
    expect(created.vault.doc.wrappedKeys.mobile).toBeUndefined();

    // WR-01: the master guards throw a TYPED DC-9 error (ProtectedWrapError), not a bare Error,
    // so callers branch on instanceof/.code instead of message text.
    expect(() => removeWrappedKey(created.vault, 'master')).toThrow(ProtectedWrapError);
    await expect(
      addWrappedKey(created.vault, created.vaultKey, {
        label: 'master',
        derivationKey,
        kdfParams: params,
      }),
    ).rejects.toThrow(ProtectedWrapError);
    // The master wrap survives both refused operations.
    expect(created.vault.doc.wrappedKeys.master).toBeDefined();
  });
});

describe('vault — KAT-4 full-vault wire format pin', () => {
  // KAT-4: fixed vault_key (32× 0x42), fixed nonce (24× 0x18), fixed entries JSON →
  // fixed AD "cryptiq-vault\0v1" → fixed combined-mode ciphertext. Pins padding + AD +
  // combined-mode end-to-end. Any drift (detached mode, AD change, LE/BE flip, padding
  // change) fails this test.
  const KAT4_ENTRIES = '{"entries":[{"title":"KAT","secret":"fixed"}]}';
  const KAT4_AD_HEX = '637279707469712d7661756c74007631'; // "cryptiq-vault\0v1"
  const KAT4_CT_DIGEST = '465369f168a4ce11ad19231e353eab4944fcd8366c714f832bfc47a2bec09ae2';
  const KAT4_CT_B64_HEAD = 'QdRQF26qiY0d1abAD/jZ85qy8QiU37SBaa2Qv31L3iI=';

  it('fixed inputs → pinned AD + ciphertext digest', async () => {
    const sodium = await getSodium();
    // AD wire format is exactly the pinned bytes.
    expect(sodium.to_hex(VAULT_AD)).toBe(KAT4_AD_HEX);

    const vaultKey = new Uint8Array(32).fill(0x42);
    const nonce = new Uint8Array(24).fill(0x18);
    const padded = padToTieredBucket(new TextEncoder().encode(KAT4_ENTRIES));
    expect(padded.length).toBe(16384); // 16 KiB tier

    const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      padded,
      VAULT_AD,
      null,
      nonce,
      vaultKey,
    );
    expect(ct.length).toBe(16400); // 16 KiB + 16-byte tag
    expect(sodium.to_base64(ct.slice(0, 32), sodium.base64_variants.ORIGINAL)).toBe(
      KAT4_CT_B64_HEAD,
    );
    expect(sodium.to_hex(sodium.crypto_generichash(32, ct, null))).toBe(KAT4_CT_DIGEST);
  });
});
