// apps/extension/src/lib/associationCrypto.test.ts
//
// Pure Vitest (no fake-browser needed) covering the four Task 2 behaviors
// from 15-02-PLAN.md: round-trip, fresh-nonce-per-message, fail-closed on
// wrong key, and the 24-byte nonce-length contract.

import { describe, expect, it } from 'vitest';
import nacl from 'tweetnacl';
import { base64ToBytes, bytesToBase64, newNonce, openFromHost, sealForHost } from './associationCrypto';

describe('associationCrypto', () => {
  it('round-trips a UTF-8 JSON string via sealForHost -> openFromHost', () => {
    const host = nacl.box.keyPair();
    const ext = nacl.box.keyPair();

    const plaintext = JSON.stringify({ pairingToken: 'abc123', rpcType: 'match-origin' });
    const plaintextBytes = new TextEncoder().encode(plaintext);

    const sealed = sealForHost(plaintextBytes, host.publicKey, ext.secretKey);

    const opened = openFromHost(
      base64ToBytes(sealed.box),
      base64ToBytes(sealed.nonce),
      ext.publicKey,
      host.secretKey,
    );

    expect(opened).not.toBeNull();
    expect(new TextDecoder().decode(opened!)).toBe(plaintext);
  });

  it('produces a DIFFERENT nonce on two sequential seals of identical plaintext', () => {
    const host = nacl.box.keyPair();
    const ext = nacl.box.keyPair();
    const plaintextBytes = new TextEncoder().encode('same message both times');

    const first = sealForHost(plaintextBytes, host.publicKey, ext.secretKey);
    const second = sealForHost(plaintextBytes, host.publicKey, ext.secretKey);

    expect(first.nonce).not.toBe(second.nonce);
  });

  it('returns null (fails closed) when opened with the wrong peer public key', () => {
    const host = nacl.box.keyPair();
    const ext = nacl.box.keyPair();
    const wrongPeer = nacl.box.keyPair();

    const plaintextBytes = new TextEncoder().encode('secret payload');
    const sealed = sealForHost(plaintextBytes, host.publicKey, ext.secretKey);

    const opened = openFromHost(
      base64ToBytes(sealed.box),
      base64ToBytes(sealed.nonce),
      wrongPeer.publicKey, // wrong: should be ext.publicKey
      host.secretKey,
    );

    expect(opened).toBeNull();
  });

  it('generates a nonce that is exactly 24 bytes (nacl.box.nonceLength)', () => {
    const nonce = newNonce();
    expect(nonce.length).toBe(24);
    expect(nonce.length).toBe(nacl.box.nonceLength);
  });

  it('bytesToBase64 / base64ToBytes round-trip arbitrary bytes', () => {
    const original = nacl.randomBytes(32);
    const roundTripped = base64ToBytes(bytesToBase64(original));
    expect(roundTripped).toEqual(original);
  });
});
