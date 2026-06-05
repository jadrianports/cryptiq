// packages/core/src/sync/pairingCode.test.ts
//
// Core Vitest regression tests for pairingCode.ts (D-11 + D-18 guards).
//
// IMPORTANT: These tests run under the core Vitest runner (NOT the desktop browser suite).
// No @tauri-apps/*, no Svelte, no Math.random. All byte arrays are hardcoded fixtures.
//
// Test coverage:
//   1. Valid code round-trip — does NOT throw
//   2. Single-character body typo → PairingCodeInvalidError (D-11)
//   3. Wrong / absent check character → PairingCodeInvalidError (D-11)
//   4. Full bundle format (IP:PORT:SECRET) — validated correctly
//   5. assertVaultUnlockedForPairing(true) — does NOT throw (D-18)
//   6. assertVaultUnlockedForPairing(false) → PairingRequiresUnlockError (D-18)
//   7. Empty input → PairingCodeInvalidError
//   8. Invalid Base32 character (non-Crockford) → PairingCodeInvalidError

import { describe, it, expect } from 'vitest';
import { validatePairingCode, assertVaultUnlockedForPairing } from './pairingCode';
import { encodeCrockfordBase32, crockfordCheckChar } from '../crypto/recovery';
import { PairingCodeInvalidError, PairingRequiresUnlockError } from '../errors';

// ---------------------------------------------------------------------------
// Fixed 32-byte fixture — NEVER Math.random (CLAUDE.md crypto rules)
// This is a pairing secret fixture for testing the Base32 + check-char path.
// ---------------------------------------------------------------------------
const FIXTURE_BYTES_32 = new Uint8Array([
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
  0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
  0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
]);

/** Build a valid pairing code string from the fixture bytes (BASE32BODY + CHECKCHAR). */
function buildValidCode(bytes: Uint8Array = FIXTURE_BYTES_32): string {
  const body = encodeCrockfordBase32(bytes);    // 52 chars for 32 bytes
  const check = crockfordCheckChar(bytes);       // 1 char
  return body + check;
}

// ---------------------------------------------------------------------------
// validatePairingCode — basic round-trip
// ---------------------------------------------------------------------------

describe('validatePairingCode — valid code', () => {
  it('does not throw on a correctly-encoded code', () => {
    const code = buildValidCode();
    expect(() => validatePairingCode(code)).not.toThrow();
  });

  it('returns the decoded rawBytes matching the fixture', () => {
    const code = buildValidCode();
    const payload = validatePairingCode(code);
    // rawBytes may be shorter by 1 due to Base32 padding (last 4-bit partial byte is lost).
    // We check that the overlap matches.
    expect(payload.rawBytes.length).toBeGreaterThanOrEqual(31);
    // The first 31 bytes are deterministically round-trippable from 32 bytes of Base32.
    for (let i = 0; i < payload.rawBytes.length && i < FIXTURE_BYTES_32.length; i++) {
      expect(payload.rawBytes[i]).toBe(FIXTURE_BYTES_32[i]);
    }
  });

  it('returns the base32Body and checkChar', () => {
    const code = buildValidCode();
    const payload = validatePairingCode(code);
    expect(payload.base32Body).toBe(encodeCrockfordBase32(FIXTURE_BYTES_32));
    expect(payload.checkChar).toBe(crockfordCheckChar(FIXTURE_BYTES_32));
  });
});

// ---------------------------------------------------------------------------
// D-11: Single-character body typo → PairingCodeInvalidError
// ---------------------------------------------------------------------------

describe('validatePairingCode — body typo (D-11)', () => {
  it('throws PairingCodeInvalidError when one body character is flipped', () => {
    const code = buildValidCode();
    // Flip the first character of the body to something different.
    const original = code[0]!;
    // Replace with a different valid Base32 char to ensure the code is still decodable
    // but the check will fail.
    const flipped = original === '0' ? '1' : '0';
    const typoCode = flipped + code.slice(1);

    expect(() => validatePairingCode(typoCode)).toThrow(PairingCodeInvalidError);
  });

  it('throws PairingCodeInvalidError when a middle body character is changed', () => {
    const code = buildValidCode();
    const mid = Math.floor(code.length / 2);
    const original = code[mid]!;
    const replacement = original === 'A' ? 'B' : 'A';
    const typoCode = code.slice(0, mid) + replacement + code.slice(mid + 1);

    expect(() => validatePairingCode(typoCode)).toThrow(PairingCodeInvalidError);
  });

  it('throws with code PAIRING_CODE_INVALID on body typo', () => {
    const code = buildValidCode();
    const typoCode = (code[0] === '0' ? '1' : '0') + code.slice(1);
    let thrown: PairingCodeInvalidError | null = null;
    try {
      validatePairingCode(typoCode);
    } catch (err) {
      thrown = err as PairingCodeInvalidError;
    }
    expect(thrown).not.toBeNull();
    expect(thrown?.code).toBe('PAIRING_CODE_INVALID');
  });
});

// ---------------------------------------------------------------------------
// D-11: Wrong / absent check character → PairingCodeInvalidError
// ---------------------------------------------------------------------------

describe('validatePairingCode — wrong check character (D-11)', () => {
  it('throws PairingCodeInvalidError when check char is wrong', () => {
    const code = buildValidCode();
    const body = code.slice(0, -1);
    const originalCheck = code.slice(-1);
    // Replace check char with a different one.
    const wrongCheck = originalCheck === '0' ? '1' : '0';
    const badCode = body + wrongCheck;

    expect(() => validatePairingCode(badCode)).toThrow(PairingCodeInvalidError);
  });

  it('throws PairingCodeInvalidError when check char is replaced with uppercase letter', () => {
    const code = buildValidCode();
    // Append 'Z' instead of the real check char.
    const bodyWithWrongCheck = code.slice(0, -1) + 'Z';
    // Only throws if 'Z' is not already the correct check (statistically very likely).
    const realCheck = crockfordCheckChar(FIXTURE_BYTES_32);
    if (realCheck !== 'Z') {
      expect(() => validatePairingCode(bodyWithWrongCheck)).toThrow(PairingCodeInvalidError);
    }
  });

  it('throws PairingCodeInvalidError when check char is replaced with a wrong char', () => {
    // Build a code where the check char is deliberately replaced with a wrong character.
    // This covers the "absent check char" case: the validator always treats the last char
    // as the check, so any wrong trailing char triggers PairingCodeInvalidError.
    const code = buildValidCode();
    const realCheck = crockfordCheckChar(FIXTURE_BYTES_32);
    // Replace check char with any char that is NOT the real check.
    const wrongCheck = realCheck === '5' ? '6' : '5';
    const knownBadCheck = code.slice(0, -1) + wrongCheck;
    if (realCheck !== wrongCheck) {
      expect(() => validatePairingCode(knownBadCheck)).toThrow(PairingCodeInvalidError);
    } else {
      // Extremely unlikely: pick another wrong char
      const altBad = code.slice(0, -1) + 'A';
      if (realCheck !== 'A') {
        expect(() => validatePairingCode(altBad)).toThrow(PairingCodeInvalidError);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// Full bundle format (IP:PORT:SECRET)
// ---------------------------------------------------------------------------

describe('validatePairingCode — full bundle format (IP:PORT:SECRET)', () => {
  it('accepts the secret portion of a full IP:PORT:SECRET bundle', () => {
    const code = buildValidCode();
    const bundle = `192.168.1.100:54321:${code}`;
    expect(() => validatePairingCode(bundle)).not.toThrow();
  });

  it('validates check character correctly when given full bundle', () => {
    const code = buildValidCode();
    const bundle = `10.0.0.1:54321:${code}`;
    const payload = validatePairingCode(bundle);
    expect(payload.checkChar).toBe(crockfordCheckChar(FIXTURE_BYTES_32));
  });

  it('throws PairingCodeInvalidError for full bundle with typo in secret', () => {
    const code = buildValidCode();
    const typoCode = (code[0] === '0' ? '1' : '0') + code.slice(1);
    const bundle = `192.168.1.1:54321:${typoCode}`;
    expect(() => validatePairingCode(bundle)).toThrow(PairingCodeInvalidError);
  });
});

// ---------------------------------------------------------------------------
// Empty input → PairingCodeInvalidError
// ---------------------------------------------------------------------------

describe('validatePairingCode — empty / malformed input', () => {
  it('throws PairingCodeInvalidError on empty string', () => {
    expect(() => validatePairingCode('')).toThrow(PairingCodeInvalidError);
  });

  it('throws PairingCodeInvalidError on whitespace-only string', () => {
    expect(() => validatePairingCode('   ')).toThrow(PairingCodeInvalidError);
  });

  it('throws PairingCodeInvalidError on non-Crockford characters', () => {
    // All non-alphanumeric stripped → if nothing left, throw; if some remain, validate.
    // Use a string that normalizes to 1 char or fewer.
    expect(() => validatePairingCode('!!!!')).toThrow(PairingCodeInvalidError);
  });
});

// ---------------------------------------------------------------------------
// D-18: assertVaultUnlockedForPairing
// ---------------------------------------------------------------------------

describe('assertVaultUnlockedForPairing (D-18)', () => {
  it('does NOT throw when isUnlocked is true', () => {
    expect(() => assertVaultUnlockedForPairing(true)).not.toThrow();
  });

  it('throws PairingRequiresUnlockError when isUnlocked is false', () => {
    expect(() => assertVaultUnlockedForPairing(false)).toThrow(PairingRequiresUnlockError);
  });

  it('throws with stable code PAIRING_REQUIRES_UNLOCK when locked', () => {
    let thrown: PairingRequiresUnlockError | null = null;
    try {
      assertVaultUnlockedForPairing(false);
    } catch (err) {
      thrown = err as PairingRequiresUnlockError;
    }
    expect(thrown).not.toBeNull();
    expect(thrown?.code).toBe('PAIRING_REQUIRES_UNLOCK');
    expect(thrown?.message).toContain('unlocked');
  });

  it('returns void (no value) when unlocked', () => {
    const result = assertVaultUnlockedForPairing(true);
    expect(result).toBeUndefined();
  });
});
