import { describe, it, expect } from 'vitest';
import { getSodium } from '../sodium';
import { sealData, openData, VAULT_AD } from '../aead';
import { VaultCorruptError } from '../../errors';

// Wave 2 — XChaCha20-Poly1305 IETF COMBINED-MODE seal/open tests (SEC-04, SEC-06, SEC-08).
//
// KAT-2 pins two wire-format invariants:
//   1. VAULT_AD === UTF-8 bytes of "cryptiq-vault\0v1" (16 bytes, null-byte separator —
//      NOT a hyphen; Pitfall C). Hard-coded expected byte array below.
//   2. Sealing a fixed plaintext under a fixed key + fixed nonce yields a fixed
//      ciphertext hex. Because sealData() generates a fresh random nonce internally,
//      the KAT calls the raw combined-mode primitive directly with the pinned nonce to
//      assert the wire bytes, and separately asserts sealData()'s nonce is fresh/random.

const ABYTES = 16;
const NPUBBYTES = 24;

// "cryptiq-vault" (13) + 0x00 (1) + "v1" (2) = 16 bytes.
const EXPECTED_VAULT_AD = [99, 114, 121, 112, 116, 105, 113, 45, 118, 97, 117, 108, 116, 0, 118, 49];

// Fixed inputs for the KAT-2 ciphertext pin (combined mode, VAULT_AD).
const KAT2_KEY = new Uint8Array(32).fill(0x42); // 32 bytes of 0x42
const KAT2_NONCE = new Uint8Array(24).fill(0x18); // 24 bytes of 0x18
const KAT2_PLAINTEXT = new TextEncoder().encode('cryptiq-kat-2');
// Captured on first green run and locked (KAT-2 wire-format pin).
const KAT2_EXPECTED_HEX =
  '0ca6296761e19dce02c6bb884ee45c895697dc11d774c6f0ad9a09d076';

function toHex(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

describe('crypto/aead — XChaCha20-Poly1305 combined mode', () => {
  it('sealData returns a 24-byte nonce and ciphertext = plaintext.length + 16 (ABYTES)', async () => {
    const key = new Uint8Array(32).fill(7);
    const plaintext = new TextEncoder().encode('hello vault');
    const { ciphertext, nonce } = await sealData(plaintext, key);
    expect(nonce.length).toBe(NPUBBYTES);
    expect(ciphertext.length).toBe(plaintext.length + ABYTES);
  });

  it('openData round-trips back to the exact plaintext bytes', async () => {
    const key = new Uint8Array(32).fill(7);
    const plaintext = new TextEncoder().encode('the quick brown fox éè');
    const { ciphertext, nonce } = await sealData(plaintext, key);
    const recovered = await openData(ciphertext, nonce, key);
    expect(Array.from(recovered)).toEqual(Array.from(plaintext));
  });

  it('two seals of the same plaintext+key produce DIFFERENT nonces (fresh random per call)', async () => {
    const key = new Uint8Array(32).fill(7);
    const plaintext = new TextEncoder().encode('same input every time');
    const a = await sealData(plaintext, key);
    const b = await sealData(plaintext, key);
    expect(toHex(a.nonce)).not.toBe(toHex(b.nonce));
    // Fresh nonce → different ciphertext too.
    expect(toHex(a.ciphertext)).not.toBe(toHex(b.ciphertext));
  });

  it('openData throws VaultCorruptError on a flipped ciphertext byte (never partial data)', async () => {
    const key = new Uint8Array(32).fill(7);
    const plaintext = new TextEncoder().encode('tamper me');
    const { ciphertext, nonce } = await sealData(plaintext, key);
    const tampered = Uint8Array.from(ciphertext);
    tampered[0] = (tampered[0]! ^ 0x01) & 0xff; // flip one bit
    await expect(openData(tampered, nonce, key)).rejects.toBeInstanceOf(VaultCorruptError);
  });

  it('openData throws VaultCorruptError with the WRONG AD (AD binding works)', async () => {
    const key = new Uint8Array(32).fill(7);
    const plaintext = new TextEncoder().encode('version-bound');
    const { ciphertext, nonce } = await sealData(plaintext, key); // sealed under VAULT_AD
    const wrongAd = new TextEncoder().encode('cryptiq-vault\0v2'); // downgrade/upgrade
    await expect(openData(ciphertext, nonce, key, wrongAd)).rejects.toBeInstanceOf(
      VaultCorruptError,
    );
  });

  it('KAT-2: VAULT_AD bytes are "cryptiq-vault\\0v1" and the fixed-input ciphertext hex is pinned', async () => {
    // Pin the AD byte sequence (Pitfall C — null byte, not hyphen).
    expect(Array.from(VAULT_AD)).toEqual(EXPECTED_VAULT_AD);

    // Pin the wire bytes: seal a fixed plaintext under a fixed key + fixed nonce with
    // VAULT_AD via the raw combined-mode primitive (sealData generates a random nonce,
    // so we exercise the same primitive sealData uses, with a deterministic nonce).
    const sodium = await getSodium();
    const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      KAT2_PLAINTEXT,
      VAULT_AD,
      null,
      KAT2_NONCE,
      KAT2_KEY,
    );
    expect(ct.length).toBe(KAT2_PLAINTEXT.length + ABYTES);
    expect(toHex(ct)).toBe(KAT2_EXPECTED_HEX);

    // And openData decrypts that fixed ciphertext back under VAULT_AD.
    const recovered = await openData(ct, KAT2_NONCE, KAT2_KEY);
    expect(Array.from(recovered)).toEqual(Array.from(KAT2_PLAINTEXT));
  });
});
