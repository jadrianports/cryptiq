// packages/core/src/crypto/recovery.ts
//
// DC-7 RECOVERY KEY — hand-rolled Crockford Base32 + check char + version byte, plus the
// BLAKE2b-derived recovery wrap-key (AUTH-05, AUTH-06).
//
// WHY HAND-ROLLED (not an npm package): the only Crockford Base32 package on npm has
// ~4,776 weekly downloads / 5 GitHub stars / Snyk "inactive". This is ENCODING (not
// crypto) — ~50 lines, fully unit-tested — so a fragile dependency on the encoding layer
// of a security project is the wrong trade. The actual crypto (BLAKE2b) is libsodium.
//
// THE RECOVERY KEY STRING:
//   raw = [0x01 version byte] + [32 random CSPRNG bytes]                 (33 bytes)
//   encoded = encodeCrockfordBase32(raw)  (53 chars)  + crockfordCheckChar(raw) (1 char)
//           = an unambiguous 54-char string  ← THE PHASE-2 CRYPTO CONTRACT.
//
//   DC-7 DISPLAY DASH GROUPING IS A PHASE-4 (UI) CONCERN — NOT A CRYPTO INVARIANT.
//   The DC-7 spec's "10 groups of 5, dashed" (= 50 chars) is internally inconsistent with
//   the 53 base32 chars the math actually produces (33 bytes × 8 / 5 = 52.8 → 53). See
//   RESEARCH Open Question 3 + Assumption A6. This module emits a best-effort dashed form
//   for readability, but the canonical value is the FLAT 54-char string. decodeRecoveryKey
//   normalization STRIPS all non-alphanumerics, so ANY reasonable grouping decodes. Do NOT
//   hard-code a specific (wrong) grouping as a crypto invariant — the exact display dashing
//   is decided in Phase 4 against the flat string this module guarantees.
//
// NORMALIZATION ON DECODE (DC-7): uppercase → strip non-[0-9A-Z*~$=] → split off the trailing
//   check char → map look-alikes ONLY on the 53-char base32 BODY (I/L→1, O→0, U→V; the body
//   alphabet contains none of these, so this only fixes transcription typos). The check char
//   is normalized for I/L→1, O→0 but NOT U→V: the 37-symbol check alphabet legitimately
//   includes 'U' (index 36), so U→V on the check position would corrupt ~1/37 valid keys
//   (CR-01). The check char is verified BEFORE the key bytes are trusted (so a transcription
//   typo yields "looks like one character is wrong" rather than a generic "wrong recovery
//   key"). The version byte is verified AFTER decode (a key from a FUTURE format version is a
//   different, recognizable failure).
//
// BLAKE2b RECOVERY WRAP-KEY (Claude's discretion, CONTEXT DC-7 + Open Question 2 / A1):
//   toRecoveryWrapKey(raw) = crypto_generichash(32, raw, domain16) where domain16 is the
//   16-byte truncate/pad of "cryptiq-recovery-v1". VERIFIED empirically: libsodium's
//   crypto_generichash_KEYBYTES_MIN === 16, so a 16-byte key is the exact minimum and a
//   valid domain-separation input; the hash is deterministic and domain-separated. The
//   resulting 32-byte key wraps the vault_key via wrap.ts (DC-5 generic tryUnwrap path).
//
// SEC-09 / AUTH-06 CALLER CONTRACT: the wrapKey is derived from `rawBytes` BEFORE any
//   memzero. The raw recovery bytes are NEVER persisted — only the resulting
//   wrappedKeys.recovery is stored (vault.ts enforces this). Callers must NOT memzero
//   rawBytes before the wrapKey has been used to wrap the vault_key.
//
// Source: RESEARCH Pattern 5 (encode/decode/check-char/wrap-key reference impl), CONTEXT
//   DC-7, RESEARCH Open Question 2/3 + Assumptions A1/A6, crockford.com/base32.html.

import { getSodium } from './sodium';
import { WrongRecoveryKeyError } from '../errors';

/** Crockford Base32 encoding alphabet — 32 symbols, NO look-alikes I, L, O, U. */
const ENCODE_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
/** Check-char alphabet — 37 symbols (mod 37): the 32 above + `*`, `~`, `$`, `=`, `U`. */
const CHECK_ALPHABET = ENCODE_ALPHABET + '*~$=U';

/** Recovery-key format version. Verified AFTER decode (forward-compat gate). */
const RECOVERY_KEY_VERSION = 0x01;

/** BLAKE2b domain-separation string (Claude's discretion). Truncate/pad to 16 bytes. */
const RECOVERY_DOMAIN = new TextEncoder().encode('cryptiq-recovery-v1');

/** Normalized recovery-key length: 53 base32 chars + 1 check char. */
const ENCODED_LENGTH = 54;
const BASE32_LENGTH = 53;

/**
 * Encode raw bytes to Crockford Base32 (5-bit big-endian bucketing). For a 33-byte input
 * this yields 53 chars (the last char carries 1 bit of real data + 4 zero-pad bits).
 */
export function encodeCrockfordBase32(bytes: Uint8Array): string {
  let result = '';
  let buffer = 0;
  let bitsLeft = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bitsLeft += 8;
    while (bitsLeft >= 5) {
      bitsLeft -= 5;
      result += ENCODE_ALPHABET[(buffer >> bitsLeft) & 0x1f];
    }
  }
  if (bitsLeft > 0) {
    result += ENCODE_ALPHABET[(buffer << (5 - bitsLeft)) & 0x1f];
  }
  return result;
}

/**
 * Decode a Crockford Base32 string back to bytes (exact inverse of encodeCrockfordBase32
 * for our 33-byte payload). The input MUST already be normalized to the encode alphabet
 * (uppercase, look-alikes mapped). Throws on an out-of-alphabet character.
 */
export function decodeCrockfordBase32(s: string): Uint8Array {
  const bytes: number[] = [];
  let buffer = 0;
  let bitsLeft = 0;
  for (const char of s) {
    const val = ENCODE_ALPHABET.indexOf(char);
    if (val < 0) {
      throw new WrongRecoveryKeyError(
        `Invalid Crockford Base32 character: ${JSON.stringify(char)}.`,
      );
    }
    buffer = (buffer << 5) | val;
    bitsLeft += 5;
    if (bitsLeft >= 8) {
      bitsLeft -= 8;
      bytes.push((buffer >> bitsLeft) & 0xff);
    }
  }
  return new Uint8Array(bytes);
}

/**
 * Crockford check character: the big-endian big-integer value of `bytes` mod 37, mapped
 * through CHECK_ALPHABET. BigInt avoids overflow on the 33-byte (264-bit) input.
 */
export function crockfordCheckChar(bytes: Uint8Array): string {
  let mod = 0n;
  for (const b of bytes) {
    mod = (mod * 256n + BigInt(b)) % 37n;
  }
  return CHECK_ALPHABET[Number(mod)]!;
}

/**
 * Derive the 32-byte recovery wrap-key from the 33 raw recovery bytes via BLAKE2b
 * (crypto_generichash) keyed by the 16-byte domain string (domain separation, A1-verified).
 */
export async function toRecoveryWrapKey(rawBytes: Uint8Array): Promise<Uint8Array> {
  const sodium = await getSodium();
  // Pad/truncate the domain to exactly crypto_generichash_KEYBYTES_MIN (16) bytes.
  const domain = new Uint8Array(16);
  domain.set(RECOVERY_DOMAIN.subarray(0, 16));
  return sodium.crypto_generichash(32, rawBytes, domain);
}

/**
 * Generate a fresh recovery key. Returns:
 *  - `rawBytes`: 33 bytes = [0x01 version] + 32 CSPRNG bytes
 *  - `encoded`:  the displayable recovery string (flat 54 chars, best-effort dash grouping)
 *  - `wrapKey`:  the 32-byte BLAKE2b key used to wrap the vault_key (derived BEFORE any
 *                memzero — AUTH-06: rawBytes are never persisted, only wrappedKeys.recovery)
 */
export async function generateRecoveryKey(): Promise<{
  rawBytes: Uint8Array;
  encoded: string;
  wrapKey: Uint8Array;
}> {
  const sodium = await getSodium();
  const rawBytes = new Uint8Array(33);
  rawBytes[0] = RECOVERY_KEY_VERSION;
  rawBytes.set(sodium.randombytes_buf(32), 1);

  const base32Part = encodeCrockfordBase32(rawBytes); // 53 chars
  const checkChar = crockfordCheckChar(rawBytes); // 1 char
  const flat = base32Part + checkChar; // 54 chars — the canonical contract

  const wrapKey = await toRecoveryWrapKey(rawBytes);
  return { rawBytes, encoded: groupForDisplay(flat), wrapKey };
}

/**
 * Best-effort DISPLAY grouping (5-char groups joined by dashes). This is COSMETIC only —
 * the canonical value is the flat 54-char string and decodeRecoveryKey ignores all dashes
 * (RESEARCH A6/Q3). Phase 4 owns the final display format; do not treat this grouping as a
 * crypto invariant.
 */
function groupForDisplay(flat: string): string {
  const groups: string[] = [];
  for (let i = 0; i < flat.length; i += 5) {
    groups.push(flat.slice(i, i + 5));
  }
  return groups.join('-');
}

/**
 * Decode a (possibly human-transcribed) recovery key string back to its 33 raw bytes.
 *
 * Normalization (DC-7): uppercase → strip every non-[0-9A-Z*~$=] char (dash-agnostic) →
 * map Crockford look-alikes I/L→1, O→0, U→V. Then:
 *   1. assert normalized length === 54 (else WrongRecoveryKeyError)
 *   2. split 53 base32 chars + 1 check char
 *   3. decode the base32 → 33 bytes
 *   4. verify the check char BEFORE trusting the key (typo → "one character is wrong")
 *   5. verify the version byte AFTER decode (mismatch → "different version")
 *
 * Throws WrongRecoveryKeyError on any malformed/wrong-version input (DC-9 typed error).
 */
export async function decodeRecoveryKey(input: string): Promise<Uint8Array> {
  // Uppercase + strip separators FIRST, but do NOT yet map look-alikes. The U→V map must
  // not touch the trailing check char: the 37-symbol CHECK_ALPHABET legitimately contains
  // 'U' (index 36 = payload mod 37 === 36), so rewriting a correct 'U' check char to 'V'
  // would throw WrongRecoveryKeyError on a verbatim-correct key (~1/37 keys — CR-01).
  const stripped = input.toUpperCase().replace(/[^0-9A-Z*~$=]/g, '');

  if (stripped.length !== ENCODED_LENGTH) {
    throw new WrongRecoveryKeyError(
      `Recovery key must be ${ENCODED_LENGTH} characters after normalization (got ${stripped.length}).`,
    );
  }

  // Look-alike mapping applies ONLY to the 53-char base32 BODY. The encode alphabet has no
  // I/L/O/U, so on a verbatim key this is a no-op; it only fixes human transcription typos
  // (e.g. writing O for 0). Crucially U→V here is safe because the body can never contain U.
  const base32Part = stripped
    .slice(0, BASE32_LENGTH)
    .replace(/[IL]/g, '1')
    .replace(/O/g, '0')
    .replace(/U/g, 'V');
  // The CHECK char: uppercase already applied; map only the look-alikes that are NOT valid
  // check symbols (I/L→1, O→0). Do NOT rewrite U→V — 'U' IS a valid check symbol (index 36).
  const checkChar = stripped[BASE32_LENGTH]!.replace(/[IL]/g, '1').replace(/O/g, '0');
  const rawBytes = decodeCrockfordBase32(base32Part);

  // (4) Check char BEFORE trusting the key material.
  const expectedCheck = crockfordCheckChar(rawBytes);
  if (checkChar !== expectedCheck) {
    throw new WrongRecoveryKeyError(
      'Recovery key check character does not match — looks like one character is wrong.',
    );
  }

  // (5) Version byte AFTER decode (forward-compat gate).
  if (rawBytes[0] !== RECOVERY_KEY_VERSION) {
    throw new WrongRecoveryKeyError(
      `Recovery key version 0x${rawBytes[0]?.toString(16).padStart(2, '0')} is not recognized — recovery key from a different version.`,
    );
  }

  return rawBytes;
}
