// apps/desktop/src/lib/adapters/contentHash.ts
//
// P3-11 BACKUP DEDUP HELPER — content-change hash for TauriVaultStorageAdapter.
//
// Purpose: produce a stable string fingerprint of the decrypted entries so the
// adapter can decide whether to rotate a backup slot on each save. A fresh nonce
// is generated on EVERY encryption (SEC-04), meaning the on-disk file bytes differ
// on every save even for identical entries — dedup MUST be at the content level,
// never at the file-byte level.
//
// Approach chosen: FNV-1a (non-crypto) over a stable JSON string of the entries
// object. Rationale:
//   - This is a dedup SIGNAL, not a security boundary — crypto strength is not needed.
//   - FNV-1a is pure synchronous TS (no async, no getSodium() round-trip, no WASM).
//   - Zero new dependencies; no @cryptiq/core/internal import needed here.
//   - Deterministic: JSON.stringify on an object with a stable key order (the entries
//     array from InnerDoc) produces the same string for equal content across calls.
//
// Security note: the entries content is NEVER logged here (T-03-18). Only the hash
// fingerprint is stored in `lastSavedHash`; no plaintext entry data touches storage.

/**
 * FNV-1a 32-bit constants.
 * Source: https://www.isthe.com/chongo/tech/comp/fnv/#FNV-param
 */
const FNV_PRIME = 0x01000193;
const FNV_OFFSET_BASIS = 0x811c9dc5;

/**
 * Compute a hex string fingerprint of `entries` for backup dedup (P3-11).
 *
 * Hashes a stable JSON serialization of the entries object using FNV-1a 32-bit.
 * The result is an 8-char lowercase hex string (e.g. `"a3f2b1c0"`).
 *
 * Guarantees:
 *   - Same entries content → same hash (deterministic key-order via JSON.stringify).
 *   - Different entries content → near-certain different hash (collision probability
 *     ~1 in 2³² per pair — negligible for a dedup signal that manages 5 backup slots).
 *   - NEVER logs the entries content. NEVER calls getSodium(). NEVER throws.
 *
 * @param entries The decrypted entries object (InnerDoc or any JSON-serializable shape).
 * @returns An 8-char lowercase hex string fingerprint.
 */
export function hashEntriesContent(entries: object): string {
  const str = JSON.stringify(entries);
  let hash = FNV_OFFSET_BASIS;
  for (let i = 0; i < str.length; i++) {
    // XOR with the byte, then multiply by FNV prime (mod 2^32 via unsigned right shift).
    hash ^= str.charCodeAt(i);
    hash = (Math.imul(hash, FNV_PRIME)) >>> 0;
  }
  return hash.toString(16).padStart(8, '0');
}
