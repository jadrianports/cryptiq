// packages/core/src/crypto/aead.ts
//
// COMBINED MODE ONLY — never use _detached variants in this codebase (Pitfall 10).
// Reason: combined mode stores tag+ciphertext as ONE blob (one base64 field in the
// vault JSON). The _detached variants store the 16-byte Poly1305 tag separately;
// mixing the two produces silently incompatible wire formats and decrypt failures.
// There is NO call to any crypto_aead_*_detached function anywhere in core.
//
// XChaCha20-Poly1305 IETF AEAD (SEC-04, SEC-06, SEC-08):
//   - 256-bit key, 192-bit (24-byte) nonce, 128-bit (16-byte) auth tag.
//   - The 24-byte nonce is large enough that a FRESH random nonce per encryption has a
//     negligible collision probability — Cryptiq generates one via randombytes_buf on
//     EVERY sealData call (SEC-04; never reuse a nonce under the same key).
//   - Associated data (AD) is authenticated but NOT encrypted. The data blob binds the
//     vault file-format version into AD via VAULT_AD, so a version-downgrade attack
//     fails the MAC (SEC-06). Wrapped keys use NO AD (see wrap.ts).
//   - openData FAILS CLOSED: any auth/tag failure throws VaultCorruptError and never
//     returns partial plaintext (SEC-08).
//
// Source: RESEARCH Pattern 3 (verified libsodium AEAD API + constants), Pattern 8 (AD
// wire format), PITFALLS Pitfall 10 (combined-only) + Pitfall C (AD null-byte separator).

import { getSodium } from './sodium';
import { VaultCorruptError } from '../errors';

// AD wire format locked by ARCHITECTURE.md §10 step 5 + RESEARCH Pattern 8 — pinned in
// KAT-2. The `\0` is a LITERAL null byte separator (Pitfall C — NOT a hyphen):
//   "cryptiq-vault" (13 bytes) + 0x00 (1 byte) + "v1" (2 bytes) = 16 bytes.
export const VAULT_AD: Uint8Array = new TextEncoder().encode('cryptiq-vault\0v1');

/**
 * Seal `plaintext` under `key` with XChaCha20-Poly1305 IETF (combined mode). Generates
 * a FRESH random 24-byte nonce per call (SEC-04 — never reuse a nonce under one key).
 *
 * @param additionalData authenticated-but-not-encrypted bytes; defaults to VAULT_AD,
 *   which binds the vault file-format version (SEC-06). Pass other AD for non-vault uses.
 * @returns `{ ciphertext, nonce }` where `ciphertext.length === plaintext.length + 16`.
 */
export async function sealData(
  plaintext: Uint8Array,
  key: Uint8Array,
  additionalData: Uint8Array = VAULT_AD,
): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array }> {
  const sodium = await getSodium();
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    additionalData,
    null, // nsec — always null for this construction
    nonce,
    key,
  );
  return { ciphertext, nonce };
}

/**
 * Open `ciphertext` (sealed by sealData) under `key` + `nonce`. The `additionalData`
 * MUST match what was sealed (defaults to VAULT_AD). FAILS CLOSED: any authentication
 * failure — tampered ciphertext, wrong key, wrong nonce, or mismatched AD (e.g. a
 * version downgrade) — throws VaultCorruptError and never returns partial data (SEC-08).
 */
export async function openData(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  key: Uint8Array,
  additionalData: Uint8Array = VAULT_AD,
): Promise<Uint8Array> {
  const sodium = await getSodium();
  try {
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null, // nsec — always null
      ciphertext,
      additionalData,
      nonce,
      key,
    );
  } catch {
    throw new VaultCorruptError('AEAD authentication failed — ciphertext may be tampered.');
  }
}
