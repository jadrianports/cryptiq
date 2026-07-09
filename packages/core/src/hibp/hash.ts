// packages/core/src/hibp/hash.ts
//
// SHA-1 hashing for the HIBP k-anonymity lookup (D-01, D-02, D-03, SC-4).
//
// D-01: SHA-1 is computed HERE, client-side in JS/core — never in Rust. The full
// SHA-1 hash of the plaintext password is computed in this process; only the
// resulting 5-hex-char prefix (see kanon.ts `splitPrefixSuffix`) is ever passed
// across the JS -> Rust boundary. The plaintext password itself never crosses it.
//
// D-02: `libsodium-wrappers-sumo` does NOT expose SHA-1 (only crypto_hash_sha256/
// sha512 — libsodium omits SHA-1 by design). `@noble/hashes/legacy.js` is the
// sanctioned source, re-added as an EXPLICIT direct dependency in
// packages/core/package.json (D-02a: this re-adds the exact dep removed as unused
// in quick task 260710-2t0 / commit c64576e — a legitimate reversal, not churn;
// Phase 30 gives it a real use).
//
// D-03: SHA-1 here is the SOLE sanctioned exception to CLAUDE.md's libsodium-only
// rule, scoped EXCLUSIVELY to HIBP k-anonymity — NEVER for vault KDF/AEAD/
// key-wrap/recovery/password storage. libsodium-wrappers-sumo has no SHA-1
// (crypto_hash_sha256/sha512 only).
//
// Core purity: no @tauri-apps/*, svelte, node:fs, node:path imports. No
// console.*, no Math.random, no Date.now().

import { sha1 } from '@noble/hashes/legacy.js';
import { bytesToHex } from '@noble/hashes/utils.js';

/**
 * Computes the SHA-1 hash of `password` and returns it as UPPERCASE 40-char hex
 * (D-08: HIBP's own API returns uppercase suffixes, so the local hash is
 * uppercased here to match — see kanon.ts `matchesSuffix` for the case-insensitive
 * comparison guard that backstops this even if a caller normalizes differently).
 */
export function sha1Hex(password: string): string {
  const bytes = new TextEncoder().encode(password);
  return bytesToHex(sha1(bytes)).toUpperCase();
}
