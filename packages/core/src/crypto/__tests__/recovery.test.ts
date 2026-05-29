import { describe, it, expect } from 'vitest';
import {
  encodeCrockfordBase32,
  decodeCrockfordBase32,
  crockfordCheckChar,
  generateRecoveryKey,
  decodeRecoveryKey,
  toRecoveryWrapKey,
} from '../recovery';
import { getSodium } from '../sodium';
import { WrongRecoveryKeyError } from '../../errors';

// DC-7 — Crockford Base32 recovery key (AUTH-05, AUTH-06).
//
// The canonical contract is the unambiguous 54-char string (53 base32 + 1 check char).
// Dash grouping for DISPLAY is a Phase-4 UI concern (RESEARCH A6/Q3) and is NOT a crypto
// invariant — normalization strips all non-alphanumerics, so any grouping decodes.

// KAT-3 — fixed 33-byte input [0x01, 0x00..0x1F] under domain "cryptiq-recovery-v1".
// Pins the BLAKE2b recovery wrap-key wire format. Recomputing this hex requires the exact
// 16-byte domain + 5-bit Crockford bucketing — any drift fails this test.
const KAT3_INPUT = new Uint8Array(33);
KAT3_INPUT[0] = 0x01;
for (let i = 0; i < 32; i++) KAT3_INPUT[i + 1] = i;
const KAT3_WRAPKEY_HEX = '496b95ff00a01634daad5817ce75670eeb53eb1a1dcab15bf00f1cde9a6dda81';
const KAT3_BASE32 = '040020G30G2GC1R81450P30D1R7H048J2CA1A5GQ30CHM6RW3MF1Y';
const KAT3_CHECKCHAR = 'J';

describe('crypto/recovery — Crockford Base32 + check char + version byte (DC-7)', () => {
  it('Test 1: generateRecoveryKey() returns 33 rawBytes (v0x01), 54-char encoded, 32-byte wrapKey', async () => {
    const { rawBytes, encoded, wrapKey } = await generateRecoveryKey();
    expect(rawBytes.length).toBe(33);
    expect(rawBytes[0]).toBe(0x01);
    expect(wrapKey.length).toBe(32);
    // Stripping non-alphanumerics from the displayed form yields exactly 54 chars.
    const flat = encoded.replace(/[^0-9A-Za-z*~$=]/g, '');
    expect(flat.length).toBe(54);
    // 53 base32 + 1 check char.
    expect(flat.slice(0, 53)).toBe(encodeCrockfordBase32(rawBytes));
    expect(flat[53]).toBe(crockfordCheckChar(rawBytes));
  });

  it('Test 2: encodeCrockfordBase32 uses only the alphabet 0-9 A-Z minus I/L/O/U', async () => {
    const sodium = await getSodium();
    // Exercise many random inputs; the output must never contain I, L, O, or U.
    for (let n = 0; n < 64; n++) {
      const bytes = sodium.randombytes_buf(33);
      const out = encodeCrockfordBase32(bytes);
      expect(out).toMatch(/^[0123456789ABCDEFGHJKMNPQRSTVWXYZ]+$/);
      expect(out).not.toMatch(/[ILOU]/);
    }
  });

  it('Test 3: decodeRecoveryKey round-trips through dashes/spaces/lowercase (normalization)', async () => {
    const { rawBytes, encoded } = await generateRecoveryKey();
    // 1) exact encoded form decodes
    expect(await decodeRecoveryKey(encoded)).toEqual(rawBytes);
    // 2) flat form decodes
    const flat = encoded.replace(/[^0-9A-Za-z*~$=]/g, '');
    expect(await decodeRecoveryKey(flat)).toEqual(rawBytes);
    // 3) lowercase + arbitrary dashes/spaces decodes (normalization is dash-agnostic)
    const messy =
      flat
        .toLowerCase()
        .replace(/(.{4})/g, '$1-') // re-group with DIFFERENT grouping than display
        .replace(/-$/, '') + '   '; // trailing spaces too
    expect(await decodeRecoveryKey(messy)).toEqual(rawBytes);
  });

  it('Test 4: a check-char typo throws WrongRecoveryKeyError mentioning the check character', async () => {
    const { encoded } = await generateRecoveryKey();
    const flat = encoded.replace(/[^0-9A-Za-z*~$=]/g, '');
    // Corrupt ONLY the check char (last char) to a different valid symbol.
    const lastChar = flat[53]!;
    const wrongCheck = lastChar === '0' ? '1' : '0';
    const tampered = flat.slice(0, 53) + wrongCheck;
    await expect(decodeRecoveryKey(tampered)).rejects.toThrow(WrongRecoveryKeyError);
    await expect(decodeRecoveryKey(tampered)).rejects.toThrow(/check/i);
  });

  it('Test 5: a forged version byte (!= 0x01) throws WrongRecoveryKeyError mentioning version', async () => {
    const sodium = await getSodium();
    // Build a valid-shaped key with version 0x02, recompute base32 + the MATCHING check char
    // so we pass the check-char gate and reach the version gate.
    const forged = new Uint8Array(33);
    forged[0] = 0x02;
    forged.set(sodium.randombytes_buf(32), 1);
    const flat = encodeCrockfordBase32(forged) + crockfordCheckChar(forged);
    await expect(decodeRecoveryKey(flat)).rejects.toThrow(WrongRecoveryKeyError);
    await expect(decodeRecoveryKey(flat)).rejects.toThrow(/version/i);
  });

  it('Test 6 (KAT-3): toRecoveryWrapKey(fixed 33 bytes) matches the pinned BLAKE2b hex', async () => {
    const sodium = await getSodium();
    const wrapKey = await toRecoveryWrapKey(KAT3_INPUT);
    expect(wrapKey.length).toBe(32);
    expect(sodium.to_hex(wrapKey)).toBe(KAT3_WRAPKEY_HEX);
    // Pin the base32 + check char of the same fixed input (encode KAT).
    expect(encodeCrockfordBase32(KAT3_INPUT)).toBe(KAT3_BASE32);
    expect(crockfordCheckChar(KAT3_INPUT)).toBe(KAT3_CHECKCHAR);
  });

  it('decodeCrockfordBase32 is the exact inverse of encodeCrockfordBase32 for 33-byte inputs', async () => {
    const sodium = await getSodium();
    for (let n = 0; n < 16; n++) {
      const bytes = sodium.randombytes_buf(33);
      expect(decodeCrockfordBase32(encodeCrockfordBase32(bytes))).toEqual(bytes);
    }
  });

  it('decodeRecoveryKey rejects a string of the wrong normalized length', async () => {
    await expect(decodeRecoveryKey('TOO-SHORT')).rejects.toThrow(WrongRecoveryKeyError);
  });

  // CR-01 regression (Critical — recovery-key lockout, ~1/37 silent data loss).
  //
  // The Crockford check alphabet includes 'U' at index 36 (payload bigint mod 37 === 36).
  // The OLD decode applied the look-alike substitution U→V to the ENTIRE normalized string,
  // including the trailing check char — so a legitimate 'U' check char was rewritten to 'V'
  // and the check comparison threw WrongRecoveryKeyError for a verbatim-correct key.
  //
  // This test DETERMINISTICALLY constructs a 33-byte payload whose crockfordCheckChar === 'U'
  // (version byte 0x01 + a 32-byte tail searched so the 264-bit value ≡ 36 mod 37), then
  // asserts the canonical encoded string round-trips back to those exact bytes. The search is
  // bounded and cheap (only the last tail byte is varied; ~1/37 hit rate → found in <37 tries).
  it('CR-01: a recovery key whose check char is U round-trips losslessly (deterministic)', async () => {
    // Build a payload [0x01, 0x00..0x1E, b] and vary the final byte b until check char === 'U'.
    const payload = new Uint8Array(33);
    payload[0] = 0x01;
    for (let i = 1; i < 32; i++) payload[i] = i; // fixed body
    let found = false;
    for (let b = 0; b <= 0xff; b++) {
      payload[32] = b;
      if (crockfordCheckChar(payload) === 'U') {
        found = true;
        break;
      }
    }
    expect(found).toBe(true); // a U-check payload MUST be reachable by varying one byte

    // The canonical encoded form ends in 'U' (the check char).
    const flat = encodeCrockfordBase32(payload) + crockfordCheckChar(payload);
    expect(flat.length).toBe(54);
    expect(flat[53]).toBe('U');

    // The defect: decoding this verbatim-correct key must return the SAME bytes, not throw.
    const decoded = await decodeRecoveryKey(flat);
    expect(decoded).toEqual(payload);
  });

  // CR-01 statistical backstop: every real generated key decodes losslessly. With enough
  // samples a U-check key (≈1/37) appears, so this also fails on the old code over a batch.
  it('CR-01: a batch of generated recovery keys all decode back to their rawBytes', async () => {
    for (let n = 0; n < 200; n++) {
      const { rawBytes, encoded } = await generateRecoveryKey();
      expect(await decodeRecoveryKey(encoded)).toEqual(rawBytes);
    }
  });
});
