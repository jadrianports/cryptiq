// apps/extension/src/lib/associationCrypto.ts
//
// Pure tweetnacl `crypto_box` (X25519-XSalsa20-Poly1305) seal/open for the
// extension's transport channel with the desktop app. This module is a pure
// utility: no chrome.*/browser.* import, no Svelte, no Tauri — it MUST be
// testable with plain Vitest (no fake-browser needed).
//
// Pitfall 3 (CRITICAL, per 15-RESEARCH.md / 15-PATTERNS.md): every message,
// in EITHER direction, gets a FRESH `nacl.randomBytes(24)` nonce generated
// at seal-time. NEVER a stored/incrementing counter — an MV3 service-worker
// restart wipes all in-memory state, so any counter would reset to 0 and
// reuse a nonce against the same peer key, which is a full break of
// XSalsa20-Poly1305's security guarantee (CLAUDE.md: "fresh nonce per
// encryption" is a non-negotiable crypto rule, and it applies here too even
// though this is transport crypto, not vault crypto).
//
// This is a TRANSPORT key only (T-15-06): this module derives no vault key
// and holds no vault secret — see associationStore.ts for where the keypair
// itself is persisted.

import nacl from 'tweetnacl';

/** Sealed message ready to cross the wire: both fields are base64 (RESEARCH §"Pattern 1"). */
export interface SealedMessage {
  nonce: string; // base64, nacl.box.nonceLength (24) bytes
  box: string; // base64 ciphertext, MAC included (nacl.box.overheadLength = 16 bytes overhead)
}

/**
 * Generate a fresh CSPRNG nonce for a single message. Callers must invoke
 * this immediately before every `sealForHost` call — never cache or reuse
 * the result across messages.
 */
export function newNonce(): Uint8Array {
  return nacl.randomBytes(nacl.box.nonceLength);
}

/** Encode raw bytes as base64 (ASCII-safe, works in any browser/SW context). */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/** Decode a base64 string back to raw bytes. */
export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Seal a plaintext message for the desktop app using a fresh nonce every
 * call. Returns the wire-ready `{ nonce, box }` base64 pair.
 */
export function sealForHost(
  plaintextBytes: Uint8Array,
  hostPublicKey: Uint8Array,
  ownSecretKey: Uint8Array,
): SealedMessage {
  const nonce = newNonce();
  const box = nacl.box(plaintextBytes, nonce, hostPublicKey, ownSecretKey);
  return {
    nonce: bytesToBase64(nonce),
    box: bytesToBase64(box),
  };
}

/**
 * Open a sealed message from the desktop app. Returns null (never partial
 * bytes, never a thrown exception exposing internals) if authentication
 * fails — the caller must fail closed on a null result.
 */
export function openFromHost(
  boxBytes: Uint8Array,
  nonce: Uint8Array,
  hostPublicKey: Uint8Array,
  ownSecretKey: Uint8Array,
): Uint8Array | null {
  return nacl.box.open(boxBytes, nonce, hostPublicKey, ownSecretKey);
}
