import { describe, it, expect } from 'vitest';
import { getSodium } from '../sodium';

// Plan 02-01 Task 2 — getSodium() ready-guard behavior (SEC-01, SEC-02).
// These prove Pitfall 3 is defended: constants/functions are only readable AFTER
// awaiting getSodium(), and the ready promise is memoized into a single instance.
describe('crypto/sodium — getSodium()', () => {
  it('resolves to an object exposing the core primitives we depend on', async () => {
    const sodium = await getSodium();
    expect(typeof sodium.randombytes_buf).toBe('function');
    expect(typeof sodium.crypto_pwhash).toBe('function');
    expect(typeof sodium.crypto_aead_xchacha20poly1305_ietf_encrypt).toBe('function');
    // crypto_pwhash_ALG_ARGON2ID13 is a numeric constant, not a function.
    expect(typeof sodium.crypto_pwhash_ALG_ARGON2ID13).toBe('number');
  });

  it('returns the SAME instance on repeated calls (memoized singleton)', async () => {
    const a = await getSodium();
    const b = await getSodium();
    expect(a).toBe(b);
  });

  it('exposes the verified Argon2id constants AFTER ready (ready-guard works)', async () => {
    const sodium = await getSodium();
    // If these were read from a top-level const before sodium.ready, they'd be
    // undefined (Pitfall 3). Reading them post-await proves the guard.
    expect(sodium.crypto_pwhash_SALTBYTES).toBe(16);
    expect(sodium.crypto_pwhash_ALG_ARGON2ID13).toBe(2);
  });
});
