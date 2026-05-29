// packages/core/src/crypto/padding.ts
//
// DC-6 TIERED FILE-SIZE PADDING (VAULT-03, T-02-12 entry-count hiding).
//
// The encrypted entries blob is padded to a fixed bucket size BEFORE it is sealed, so
// that the on-disk vault file size leaks only a coarse tier — never the exact entry
// count. Two vaults with different numbers of entries that land in the same bucket
// multiple produce byte-identical padded sizes.
//
// Tier policy (the rounding granularity grows as the vault grows):
//   content length ≤ 256 KiB  → round up to a 16 KiB  bucket multiple
//   content length ≤ 1   MiB  → round up to a 64 KiB  bucket multiple
//   content length > 1   MiB  → round up to a 256 KiB bucket multiple
// ("content length" = the 4-byte prefix + the real JSON byte count.)
//
// LENGTH PREFIX — uint32 LITTLE-ENDIAN (Pitfall E): the first 4 bytes of the padded
// buffer are the real entries-JSON byte count written via DataView.setUint32(0, n, true).
// LITTLE-ENDIAN is mandatory — a big-endian prefix round-trips only inside a single
// implementation and silently breaks the moment a second reader (a migration test, a
// future mobile build) decodes it. Both setUint32 and getUint32 ALWAYS pass `true`.
// The endianness is pinned by a KAT in padding.test.ts.
//
// These are PURE synchronous functions — no sodium, no I/O. They are the encode/decode
// pair analog of config.ts's parse/serialize, operating on raw bytes.
//
// Source: RESEARCH Pattern 6 (reference impl + tier boundaries), CONTEXT DC-6,
// PITFALLS Pitfall E (uint32 LE vs BE).

const KiB = 1024;
const MiB = 1024 * KiB;

/**
 * Pick the rounding granularity for a given content length per the DC-6 tier policy.
 * `currentLen` is the 4-byte prefix + real JSON length (i.e. the minimum bytes needed).
 */
function bucketSize(currentLen: number): number {
  if (currentLen <= 256 * KiB) return 16 * KiB;
  if (currentLen <= 1 * MiB) return 64 * KiB;
  return 256 * KiB;
}

/**
 * Pad `jsonBytes` up to the next DC-6 tier bucket multiple, prefixed by a uint32 LE
 * length. Layout: `[uint32 LE realLen][...jsonBytes][...zero padding]`. The remainder
 * past the data stays zero-filled (Uint8Array is zero-initialized).
 */
export function padToTieredBucket(jsonBytes: Uint8Array): Uint8Array {
  const realLen = jsonBytes.length;
  const contentLen = 4 + realLen; // 4-byte LE prefix + the real data
  const bucket = bucketSize(contentLen);
  const totalLen = Math.ceil(contentLen / bucket) * bucket;

  const out = new Uint8Array(totalLen);
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  // uint32 LITTLE-ENDIAN length prefix — the real JSON byte count (NOT incl. the prefix).
  view.setUint32(0, realLen, /* littleEndian */ true);
  out.set(jsonBytes, 4);
  // bytes [4 + realLen .. totalLen) are already zero — that is the padding.

  return out;
}

/**
 * Reverse `padToTieredBucket`: read the uint32 LE prefix and slice back to exactly the
 * original bytes. Guards against a forged/truncated prefix (T-02-13): throws if the
 * buffer is too short to hold the prefix, or if the claimed length over-reads the buffer.
 */
export function unpad(padded: Uint8Array): Uint8Array {
  if (padded.length < 4) {
    throw new Error('Padded buffer too short to hold the 4-byte length prefix.');
  }
  const view = new DataView(padded.buffer, padded.byteOffset, padded.byteLength);
  const realLen = view.getUint32(0, /* littleEndian */ true);
  if (realLen + 4 > padded.length) {
    throw new Error(
      `Padding length prefix (${realLen}) exceeds available buffer (${padded.length - 4} bytes).`,
    );
  }
  return padded.slice(4, 4 + realLen);
}
