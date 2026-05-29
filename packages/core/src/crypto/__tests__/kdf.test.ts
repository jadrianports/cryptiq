import { describe, it, expect } from 'vitest';
import { calibrateArgon2id, deriveKey, FLOOR_OPS, FLOOR_MEM, type KdfParams } from '../kdf';
import { KdfResourceError } from '../../errors';
import { getSodium } from '../sodium';

// Plan 02-01 Task 3 — DC-1 adaptive Argon2id calibration + deriveKey (SEC-03, SEC-08, SEC-09).
//
// KAT-1 pins the Argon2id WIRE OUTPUT: fixed password + fixed salt + floor params →
// fixed 32-byte hex. Captured once on the first green run, then locked. Any future
// libsodium bump that changes the derived bytes (it must NOT) trips this test.
const KAT1_PASSWORD = new TextEncoder().encode('correct horse battery staple');
// Deterministic 16-byte salt (NOT random — KATs are reproducible by construction).
const KAT1_SALT = new Uint8Array([
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
]);
const KAT1_PARAMS: KdfParams = {
  algorithm: 2,
  opsLimit: FLOOR_OPS,
  memLimit: FLOOR_MEM,
  salt: KAT1_SALT,
};
// Locked Argon2id output for the inputs above (XChaCha20-Poly1305 KAT lands in Wave 2).
const KAT1_EXPECTED_HEX = 'aad608b5866cef907f47d5cae529ed01a91301c92c5d5fef46e1a65e394e5742';

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

describe('crypto/kdf — calibrateArgon2id()', () => {
  it('returns params at or above the 256 MiB / 3 ops floor, algorithm 2', async () => {
    const { params, measuredMs, portabilityWarning } = await calibrateArgon2id();
    expect(params.opsLimit).toBeGreaterThanOrEqual(3);
    expect(params.memLimit).toBeGreaterThanOrEqual(268_435_456);
    expect(params.algorithm).toBe(2);
    expect(measuredMs).toBeGreaterThan(0);
    expect(typeof portabilityWarning).toBe('boolean');
  });

  it('produces a fresh 16-byte salt and a positive measurement', async () => {
    const { params, measuredMs } = await calibrateArgon2id();
    expect(params.salt).toBeInstanceOf(Uint8Array);
    expect(params.salt.length).toBe(16);
    expect(measuredMs).toBeGreaterThan(0);
  });

  it('sets portabilityWarning iff memLimit exceeds 512 MiB (DC-2)', async () => {
    const { params, portabilityWarning } = await calibrateArgon2id();
    expect(portabilityWarning).toBe(params.memLimit > 512 * 1024 * 1024);
  });
});

describe('crypto/kdf — deriveKey()', () => {
  it('KAT-1: fixed password + salt + floor params → locked 32-byte hex', async () => {
    const key = await deriveKey(KAT1_PASSWORD, KAT1_PARAMS);
    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.length).toBe(32);
    expect(toHex(key)).toBe(KAT1_EXPECTED_HEX);
  });

  it('surfaces KdfResourceError on the OOM paths (thrown error AND zero-buffer)', async () => {
    const sodium = await getSodium();

    // Path 1 — thrown Error from crypto_pwhash (params far below the library minimum
    // for memLimit force libsodium to throw). deriveKey must wrap it as KdfResourceError.
    const badParams: KdfParams = {
      algorithm: 2,
      opsLimit: 0, // below crypto_pwhash_OPSLIMIT_MIN → libsodium throws
      memLimit: 1, // below crypto_pwhash_MEMLIMIT_MIN → libsodium throws
      salt: KAT1_SALT,
    };
    await expect(deriveKey(KAT1_PASSWORD, badParams)).rejects.toBeInstanceOf(KdfResourceError);

    // Path 2 — zero-filled buffer (libsodium.js #235 restricted-environment OOM).
    // Monkeypatch crypto_pwhash to return all-zeros; deriveKey's .some(b=>b!==0) guard
    // must reject it as KdfResourceError (a zero buffer is NEVER accepted as a key).
    const original = sodium.crypto_pwhash;
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (sodium as any).crypto_pwhash = (outlen: number) => new Uint8Array(outlen); // all zeros
      await expect(deriveKey(KAT1_PASSWORD, KAT1_PARAMS)).rejects.toBeInstanceOf(KdfResourceError);
    } finally {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (sodium as any).crypto_pwhash = original;
    }
  });
});
