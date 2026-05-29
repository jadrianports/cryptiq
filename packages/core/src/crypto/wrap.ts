// packages/core/src/crypto/wrap.ts
//
// Envelope key-wrapping: the random 32-byte vault_key is sealed under a derivation key
// (Argon2id-stretched master password, or a BLAKE2b-derived recovery key) using
// XChaCha20-Poly1305 IETF COMBINED MODE — the same primitive as aead.ts, but with NO
// associated data. Wrapping is key-only and NOT version-bound; the DATA blob is what
// binds the file-format version via VAULT_AD (see aead.ts). Do not pass VAULT_AD here.
//
// DC-3 — PER-WRAP KDF PARAMS (Pitfall B trap): the Argon2id `{opsLimit, memLimit, salt,
//   algorithm}` live INSIDE each WrappedKey object, NEVER at a vault top level. This is
//   the v2.5 forward-compat shape: a future mobile wrap can store weaker (mobile-safe)
//   Argon2id params from the desktop wrap, both unwrapping the SAME vault_key. If you
//   ever feel tempted to hoist `kdf` to the vault document top level — DON'T. The plan
//   doc (cryptiq-plans/03-vault-file-format.md) shows a top-level kdf; DC-3 supersedes it.
//
// DC-5 — GENERIC tryUnwrap: core has NO unlockWithMaster()/unlockWithRecovery() split.
//   tryUnwrap(wrappedKey, derivationKey) just unwraps whatever (label, key) the caller
//   hands it: returns the vault_key on the right derivation key, `null` on the wrong one
//   (MAC failure is a NORMAL branch, not an error — the unlock UI tries each wrap).
//
// Base64 (Pitfall D): every byte field uses sodium.to_base64 / sodium.from_base64 with
//   an EXPLICIT, pinned variant — sodium.base64_variants.ORIGINAL (STANDARD alphabet
//   WITH padding, the `+`/`/`/`=` set). This matches the plan/RESEARCH wire-format spec.
//   libsodium's DEFAULT is URLSAFE_NO_PADDING, so the variant MUST be passed on every
//   encode AND decode — never rely on the default. Never mix variants within a field.
//
// Source: RESEARCH Pattern 4 (tryUnwrap) + Pattern 7 (WrappedKeyV1 shape) + CONTEXT
// DC-3/DC-4/DC-5 + PITFALLS Pitfall B (per-wrap kdf) + Pitfall D (base64 variant).

import { getSodium } from './sodium';
import type { KdfParams } from './kdf';

/**
 * A vault_key wrapped under one derivation key. DC-3: the KDF params that describe how
 * the derivation key was produced live INSIDE this object (NOT at the vault top level),
 * so each wrap (master / recovery / future mobile) can carry its own params.
 */
export interface WrappedKey {
  /** base64, 24-byte XChaCha20-Poly1305 nonce. */
  nonce: string;
  /** base64, combined-mode ciphertext (vault_key length + 16-byte tag). */
  ciphertext: string;
  /** DC-3: per-wrap Argon2id params. NEVER hoist to a vault top level (Pitfall B). */
  kdf: {
    opsLimit: number;
    memLimit: number;
    /** base64, 16-byte Argon2id salt. */
    salt: string;
    algorithm: 2; // crypto_pwhash_ALG_ARGON2ID13
  };
}

/**
 * Wrap `vaultKey` under an already-derived 32-byte `derivationKey`, recording the
 * `kdfParams` that produced that derivation key into the per-wrap `kdf` field (DC-3).
 * Uses XChaCha20-Poly1305 combined mode with a fresh random 24-byte nonce and NO AD
 * (wrapping is key-only — distinct from the version-bound data blob).
 */
export async function wrapKey(
  vaultKey: Uint8Array,
  derivationKey: Uint8Array,
  kdfParams: KdfParams,
): Promise<WrappedKey> {
  const sodium = await getSodium();
  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    vaultKey,
    null, // NO associated data — wrap is key-only, not version-bound
    null, // nsec — always null
    nonce,
    derivationKey,
  );
  return {
    nonce: sodium.to_base64(nonce, sodium.base64_variants.ORIGINAL),
    ciphertext: sodium.to_base64(ciphertext, sodium.base64_variants.ORIGINAL),
    kdf: {
      opsLimit: kdfParams.opsLimit,
      memLimit: kdfParams.memLimit,
      salt: sodium.to_base64(kdfParams.salt, sodium.base64_variants.ORIGINAL),
      algorithm: 2,
    },
  };
}

/**
 * DC-5 generic unwrap: attempt to recover the vault_key from `wrappedKey` using an
 * already-derived 32-byte `derivationKey`. Returns the vault_key on success, or `null`
 * on a MAC failure (the WRONG derivation key — a normal branch, NOT an error). This is
 * the ONLY unwrap code path in core; the unlock flow decides which wrap to try first.
 */
export async function tryUnwrap(
  wrappedKey: WrappedKey,
  derivationKey: Uint8Array,
): Promise<Uint8Array | null> {
  const sodium = await getSodium();
  const nonce = sodium.from_base64(wrappedKey.nonce, sodium.base64_variants.ORIGINAL);
  const ciphertext = sodium.from_base64(wrappedKey.ciphertext, sodium.base64_variants.ORIGINAL);
  try {
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null, // nsec — always null
      ciphertext,
      null, // NO associated data — must match wrapKey
      nonce,
      derivationKey,
    );
  } catch {
    return null; // wrong derivation key — normal branch per DC-5, not an error
  }
}
