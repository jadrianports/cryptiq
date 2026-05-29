import { describe, it, expect, beforeAll } from 'vitest';
import { createVault, unlockVault, saveVault } from '../vault';
import type { UnlockedVault } from '../vault';
import { getSodium } from '../../crypto/sodium';
import type { KdfParams } from '../../crypto/kdf';
import {
  WrongPasswordError,
  WrongRecoveryKeyError,
  VaultCorruptError,
  UnknownVaultVersionError,
} from '../../errors';

// DC-11 SINGLE-BYTE TAMPER REGIONS (SEC-06, SEC-08, TEST-02).
//
// CONTRACT: every byte region of an attacker-mutated vault file, when flipped by exactly
// one byte, must surface a SPECIFIC DC-9 TYPED error — never an unhandled crash, never a
// bare/generic Error, and never partial data (SEC-08 fail-closed). Each test below clones
// the freshly-created vault bytes, mutates ONE byte inside the targeted JSON field, and
// asserts the exact typed error class the unlock code path produces for that region.
//
// THE 9 PRIMARY REGIONS + 2 RECOVERY-WRAP REGIONS (RESEARCH "Nine Tamper Regions"):
//   1. header.format         → VaultCorruptError       (foreign-file discriminator, T-02-11)
//   2. header.version        → UnknownVaultVersionError (VAULT-07 refuse-unknown)
//   3. master.kdf.salt       → WrongPasswordError       (different derived key → unwrap null)
//   4. master.kdf.opsLimit   → WrongPasswordError       (different derived key → unwrap null)
//   5. master.kdf.memLimit   → WrongPasswordError       (different derived key → unwrap null)
//   6. master.nonce          → WrongPasswordError       (AEAD MAC fail on unwrap → null)
//   7. master.ciphertext     → WrongPasswordError       (AEAD MAC fail on unwrap → null)
//   8. data.nonce            → VaultCorruptError         (AEAD MAC fail on data decrypt)
//   9. data.ciphertext       → VaultCorruptError         (Poly1305 tag mismatch on data)
//  10. recovery.nonce        → WrongRecoveryKeyError     (AEAD MAC fail on recovery unwrap)
//  11. recovery.ciphertext   → WrongRecoveryKeyError     (AEAD MAC fail on recovery unwrap)
//
// DEVIATION NOTE (regions 4 & 5 — kdf.opsLimit / kdf.memLimit): a blind single-bit flip of
// a numeric param could push opsLimit below the Argon2id floor (>= 3) or memLimit below the
// 256 MiB floor, which would make libsodium REJECT the params and raise KdfResourceError
// (still a typed error, but not the DC-11 map's WrongPasswordError). Per the PLAN's explicit
// guidance ("CHANGE ops value / CHANGE mem value"), these two tests substitute a DIFFERENT
// VALID value (one tier up — still >= floor, still accepted by Argon2id) so the derived key
// differs and the master unwrap returns null → WrongPasswordError. This honours "mutate one
// field" while keeping the derive path valid; the failure is the intended fail-closed wrong-
// key branch, never a crash.
//
// A FIXED kdf-override (256 MiB / 3 ops floor) keeps each createVault snappy — real Argon2id,
// just not auto-tuned (calibration is exercised separately in kdf.test.ts).

const FLOOR_OPS = 3;
const FLOOR_MEM = 268_435_456; // 256 MiB
const MASTER_PW = 'correct horse battery staple tamper';
const KNOWN_ENTRIES = { entries: [{ title: 'GitHub', secret: 'hunter2' }] };

function pw(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

async function floorParams(): Promise<KdfParams> {
  const sodium = await getSodium();
  return {
    algorithm: 2,
    opsLimit: FLOOR_OPS,
    memLimit: FLOOR_MEM,
    salt: sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES),
  };
}

// BUDGET NOTE: the base vault (its master Argon2id derivation is the only expensive step) is
// built ONCE in beforeAll and the serialized bytes are reused — every test re-parses a fresh
// clone of those bytes and mutates one byte, so the suite pays a single create-derivation, not
// one per region. The recovery key is fixed across regions too. unlockVault still re-derives
// once per master-path region (that is the path under test), but the create cost is amortized.
let BASE_BYTES: Uint8Array;
let RECOVERY_KEY: string;

beforeAll(async () => {
  const created = await createVault({
    masterPassword: pw(MASTER_PW),
    withRecoveryKey: true,
    kdfParams: await floorParams(),
  });
  // Mutate the plain-data UnlockedVault then seal a known entry so the data blob is real.
  const vault: UnlockedVault = created.vault;
  vault.entries = KNOWN_ENTRIES;
  BASE_BYTES = await saveVault(vault, created.vaultKey);
  RECOVERY_KEY = created.recoveryKey!;
});

/** A fresh copy of the base vault bytes + the (fixed) recovery key for each region test. */
function buildVaultBytes(): { bytes: Uint8Array; recoveryKey: string } {
  return { bytes: BASE_BYTES.slice(), recoveryKey: RECOVERY_KEY };
}

/** Parse → mutate the outer JSON object → re-serialize to bytes (2-space indent + newline). */
function reserialize(obj: Record<string, unknown>): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(obj, null, 2) + '\n');
}

function parseOuterJson(bytes: Uint8Array): Record<string, unknown> {
  return JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;
}

/**
 * Flip exactly ONE byte inside a base64 field: decode (ORIGINAL variant, decision 27) →
 * XOR one byte → re-encode (ORIGINAL). Returns the mutated base64 string. The XOR guarantees
 * a genuine single-byte change (never a no-op).
 */
async function flipBase64Byte(b64: string, index = 0): Promise<string> {
  const sodium = await getSodium();
  const bytes = sodium.from_base64(b64, sodium.base64_variants.ORIGINAL);
  bytes[index] = bytes[index]! ^ 0x01;
  return sodium.to_base64(bytes, sodium.base64_variants.ORIGINAL);
}

describe('vault/tamper — single-byte mutations surface a typed error, never a crash (DC-11)', () => {
  it('region 1: header.format corrupted → VaultCorruptError', async () => {
    const { bytes } = buildVaultBytes();
    const obj = parseOuterJson(bytes);
    // Flip one character of the format discriminator (foreign-file confusion, T-02-11).
    obj.format = 'cryptiq-vaulu';
    await expect(unlockVault(reserialize(obj), { masterPassword: pw(MASTER_PW) })).rejects.toThrow(
      VaultCorruptError,
    );
  });

  it('region 2: header.version → unknown value → UnknownVaultVersionError', async () => {
    const { bytes } = buildVaultBytes();
    const obj = parseOuterJson(bytes);
    obj.version = 2; // unknown to this build → refuse, never guess (VAULT-07)
    await expect(unlockVault(reserialize(obj), { masterPassword: pw(MASTER_PW) })).rejects.toThrow(
      UnknownVaultVersionError,
    );
  });

  it('region 3: master.kdf.salt single-byte flip → WrongPasswordError', async () => {
    const { bytes } = buildVaultBytes();
    const obj = parseOuterJson(bytes);
    const master = (obj.wrappedKeys as Record<string, { kdf: { salt: string } }>).master!;
    master.kdf.salt = await flipBase64Byte(master.kdf.salt);
    // A different salt → a different derived key → master unwrap returns null (no crash).
    const err = await unlockVault(reserialize(obj), { masterPassword: pw(MASTER_PW) }).catch(
      (e) => e as unknown,
    );
    expect(err).toBeInstanceOf(WrongPasswordError);
    expect((err as WrongPasswordError).code).toBe('WRONG_PASSWORD');
  });

  it('region 4: master.kdf.opsLimit changed (still >= floor) → WrongPasswordError', async () => {
    const { bytes } = buildVaultBytes();
    const obj = parseOuterJson(bytes);
    const master = (obj.wrappedKeys as Record<string, { kdf: { opsLimit: number } }>).master!;
    // Change to a DIFFERENT valid value (one op above the floor) — see DEVIATION NOTE.
    expect(master.kdf.opsLimit).toBe(FLOOR_OPS);
    master.kdf.opsLimit = FLOOR_OPS + 1;
    await expect(unlockVault(reserialize(obj), { masterPassword: pw(MASTER_PW) })).rejects.toThrow(
      WrongPasswordError,
    );
  });

  it('region 5: master.kdf.memLimit changed (still >= floor) → WrongPasswordError', async () => {
    const { bytes } = buildVaultBytes();
    const obj = parseOuterJson(bytes);
    const master = (obj.wrappedKeys as Record<string, { kdf: { memLimit: number } }>).master!;
    // Change to a DIFFERENT valid value (next memory tier up) — see DEVIATION NOTE.
    expect(master.kdf.memLimit).toBe(FLOOR_MEM);
    master.kdf.memLimit = 384 * 1024 * 1024; // 384 MiB — still >= floor, accepted by Argon2id
    await expect(unlockVault(reserialize(obj), { masterPassword: pw(MASTER_PW) })).rejects.toThrow(
      WrongPasswordError,
    );
  });

  it('region 6: master.nonce single-byte flip → WrongPasswordError', async () => {
    const { bytes } = buildVaultBytes();
    const obj = parseOuterJson(bytes);
    const master = (obj.wrappedKeys as Record<string, { nonce: string }>).master!;
    master.nonce = await flipBase64Byte(master.nonce);
    // Wrong nonce → AEAD MAC fail on the master unwrap → tryUnwrap returns null.
    await expect(unlockVault(reserialize(obj), { masterPassword: pw(MASTER_PW) })).rejects.toThrow(
      WrongPasswordError,
    );
  });

  it('region 7: master.ciphertext single-byte flip → WrongPasswordError', async () => {
    const { bytes } = buildVaultBytes();
    const obj = parseOuterJson(bytes);
    const master = (obj.wrappedKeys as Record<string, { ciphertext: string }>).master!;
    master.ciphertext = await flipBase64Byte(master.ciphertext);
    // Tampered wrap ciphertext → Poly1305 tag mismatch on unwrap → null → WrongPasswordError.
    await expect(unlockVault(reserialize(obj), { masterPassword: pw(MASTER_PW) })).rejects.toThrow(
      WrongPasswordError,
    );
  });

  it('region 8: data.nonce single-byte flip → VaultCorruptError', async () => {
    const { bytes } = buildVaultBytes();
    const obj = parseOuterJson(bytes);
    const data = obj.data as { nonce: string; ciphertext: string };
    data.nonce = await flipBase64Byte(data.nonce);
    // Wrong nonce → AEAD MAC fail on the DATA decrypt → fail-closed VaultCorruptError.
    await expect(unlockVault(reserialize(obj), { masterPassword: pw(MASTER_PW) })).rejects.toThrow(
      VaultCorruptError,
    );
  });

  it('region 9: data.ciphertext single-byte flip → VaultCorruptError', async () => {
    const { bytes } = buildVaultBytes();
    const obj = parseOuterJson(bytes);
    const data = obj.data as { nonce: string; ciphertext: string };
    data.ciphertext = await flipBase64Byte(data.ciphertext);
    // Poly1305 tag mismatch on the data blob → fail-closed VaultCorruptError (no partial data).
    const err = await unlockVault(reserialize(obj), { masterPassword: pw(MASTER_PW) }).catch(
      (e) => e as unknown,
    );
    expect(err).toBeInstanceOf(VaultCorruptError);
    expect((err as VaultCorruptError).code).toBe('VAULT_CORRUPT');
  });

  it('region 10 (recovery): recovery.nonce single-byte flip → WrongRecoveryKeyError', async () => {
    const { bytes, recoveryKey } = buildVaultBytes();
    const obj = parseOuterJson(bytes);
    const recovery = (obj.wrappedKeys as Record<string, { nonce: string }>).recovery!;
    recovery.nonce = await flipBase64Byte(recovery.nonce);
    // Unlock via the recovery key: wrong nonce → AEAD MAC fail on recovery unwrap → null.
    await expect(unlockVault(reserialize(obj), { recoveryKey })).rejects.toThrow(
      WrongRecoveryKeyError,
    );
  });

  it('region 11 (recovery): recovery.ciphertext single-byte flip → WrongRecoveryKeyError', async () => {
    const { bytes, recoveryKey } = buildVaultBytes();
    const obj = parseOuterJson(bytes);
    const recovery = (obj.wrappedKeys as Record<string, { ciphertext: string }>).recovery!;
    recovery.ciphertext = await flipBase64Byte(recovery.ciphertext);
    const err = await unlockVault(reserialize(obj), { recoveryKey }).catch((e) => e as unknown);
    expect(err).toBeInstanceOf(WrongRecoveryKeyError);
    expect((err as WrongRecoveryKeyError).code).toBe('WRONG_RECOVERY_KEY');
  });
});
