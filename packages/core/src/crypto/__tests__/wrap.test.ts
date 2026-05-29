import { describe, it, expect } from 'vitest';
import { getSodium } from '../sodium';
import { wrapKey, tryUnwrap } from '../wrap';
import type { KdfParams } from '../kdf';

// Wave 2 — DC-5 generic tryUnwrap + wrapKey + WrappedKey (DC-3 per-wrap kdf) tests
// (SEC-05). The vault key is wrapped under a derivation key using XChaCha20-Poly1305
// combined mode with NO associated data (key-only; the data blob is what binds the
// version via VAULT_AD). tryUnwrap returns the vault key on the RIGHT derivation key
// and `null` (not a throw) on the WRONG one — wrong key is a normal branch per DC-5.

// Fixed Argon2id params to attach to the WrappedKey.kdf field (DC-3 per-wrap params).
// These describe how a master password WOULD be stretched into the derivation key;
// wrap/tryUnwrap themselves take an already-derived 32-byte derivation key.
async function fixedKdfParams(): Promise<KdfParams> {
  const sodium = await getSodium();
  return {
    algorithm: 2,
    opsLimit: 3,
    memLimit: 268_435_456,
    salt: sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES),
  };
}

describe('crypto/wrap — DC-5 generic tryUnwrap + wrapKey', () => {
  it('wrapKey returns a WrappedKey with base64 nonce, base64 ciphertext, and a per-wrap kdf object', async () => {
    const sodium = await getSodium();
    const vaultKey = sodium.randombytes_buf(32);
    const derivationKey = sodium.randombytes_buf(32);
    const kdf = await fixedKdfParams();

    const wrapped = await wrapKey(vaultKey, derivationKey, kdf);

    // base64 strings round-trip back to bytes.
    expect(typeof wrapped.nonce).toBe('string');
    expect(typeof wrapped.ciphertext).toBe('string');
    expect(sodium.from_base64(wrapped.nonce, sodium.base64_variants.ORIGINAL).length).toBe(24);
    expect(sodium.from_base64(wrapped.ciphertext, sodium.base64_variants.ORIGINAL).length).toBe(
      32 + 16,
    ); // key + ABYTES

    // DC-3: kdf params live INSIDE the WrappedKey (salt base64-encoded), algorithm 2.
    expect(wrapped.kdf.opsLimit).toBe(kdf.opsLimit);
    expect(wrapped.kdf.memLimit).toBe(kdf.memLimit);
    expect(wrapped.kdf.algorithm).toBe(2);
    expect(typeof wrapped.kdf.salt).toBe('string');
    expect(
      Array.from(sodium.from_base64(wrapped.kdf.salt, sodium.base64_variants.ORIGINAL)),
    ).toEqual(Array.from(kdf.salt));
  });

  it('tryUnwrap with the CORRECT derivation key returns the original 32-byte vault key', async () => {
    const sodium = await getSodium();
    const vaultKey = sodium.randombytes_buf(32);
    const derivationKey = sodium.randombytes_buf(32);
    const wrapped = await wrapKey(vaultKey, derivationKey, await fixedKdfParams());

    const unwrapped = await tryUnwrap(wrapped, derivationKey);
    expect(unwrapped).not.toBeNull();
    expect(Array.from(unwrapped!)).toEqual(Array.from(vaultKey));
  });

  it('tryUnwrap with the WRONG derivation key returns null (not a throw) — DC-5 normal branch', async () => {
    const sodium = await getSodium();
    const vaultKey = sodium.randombytes_buf(32);
    const derivationKey = sodium.randombytes_buf(32);
    const wrongKey = sodium.randombytes_buf(32);
    const wrapped = await wrapKey(vaultKey, derivationKey, await fixedKdfParams());

    const result = await tryUnwrap(wrapped, wrongKey);
    expect(result).toBeNull();
  });

  it('round-trips a freshly random 32-byte vault key through wrap -> tryUnwrap losslessly', async () => {
    const sodium = await getSodium();
    for (let i = 0; i < 5; i++) {
      const vaultKey = sodium.randombytes_buf(32);
      const derivationKey = sodium.randombytes_buf(32);
      const wrapped = await wrapKey(vaultKey, derivationKey, await fixedKdfParams());
      const unwrapped = await tryUnwrap(wrapped, derivationKey);
      expect(unwrapped).not.toBeNull();
      expect(Array.from(unwrapped!)).toEqual(Array.from(vaultKey));
    }
  });

  it('wrap uses NO associated data — distinct from the data blob which uses VAULT_AD', async () => {
    // A wrapped key sealed with no AD must decrypt under the raw primitive with no AD,
    // and must FAIL if anyone tries to decrypt it with VAULT_AD (proving wrap != data AD).
    const sodium = await getSodium();
    const vaultKey = sodium.randombytes_buf(32);
    const derivationKey = sodium.randombytes_buf(32);
    const wrapped = await wrapKey(vaultKey, derivationKey, await fixedKdfParams());

    const nonce = sodium.from_base64(wrapped.nonce, sodium.base64_variants.ORIGINAL);
    const ciphertext = sodium.from_base64(wrapped.ciphertext, sodium.base64_variants.ORIGINAL);

    // No-AD decrypt succeeds.
    const ok = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      ciphertext,
      null,
      nonce,
      derivationKey,
    );
    expect(Array.from(ok)).toEqual(Array.from(vaultKey));

    // Decrypting the wrap WITH VAULT_AD must throw (wrap was sealed with null AD).
    const vaultAd = new TextEncoder().encode('cryptiq-vault\0v1');
    expect(() =>
      sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        ciphertext,
        vaultAd,
        nonce,
        derivationKey,
      ),
    ).toThrow();
  });
});
