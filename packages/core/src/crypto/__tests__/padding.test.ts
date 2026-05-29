import { describe, it, expect } from 'vitest';
import { padToTieredBucket, unpad } from '../padding';

// Wave 3 — DC-6 tiered padding with the uint32 LE length prefix (VAULT-03).
//
// Tier policy (content length = 4-byte prefix + real JSON bytes):
//   ≤256 KiB total → round up to a 16 KiB bucket multiple
//   ≤1   MiB total → round up to a 64 KiB bucket multiple
//   >1   MiB total → round up to a 256 KiB bucket multiple
//
// The first 4 bytes of every padded buffer are a uint32 LITTLE-ENDIAN length prefix =
// the real entries-JSON byte count (Pitfall E — LE, never BE). The remainder past the
// data is zero-padding. unpad() reads the prefix and slices back to the exact bytes.
//
// Entry-count hiding (T-02-12): two vaults with DIFFERENT entry counts whose
// `4 + length` land in the same bucket multiple produce IDENTICAL padded sizes.

const KiB = 1024;

describe('crypto/padding — DC-6 tiered padding + uint32 LE prefix', () => {
  it('pads a tiny input up into the first 16 KiB tier; a 20 KiB input pads to 32 KiB', () => {
    // 10 bytes → contentLen 14 → first 16 KiB bucket = 16384.
    const tiny = padToTieredBucket(new Uint8Array(10));
    expect(tiny.length).toBe(16 * KiB);

    // 20 KiB of data → contentLen 20 KiB + 4 → still ≤256 KiB tier (16 KiB buckets) →
    // ceil((20 KiB + 4) / 16 KiB) * 16 KiB = 32 KiB.
    const twentyKiB = padToTieredBucket(new Uint8Array(20 * KiB));
    expect(twentyKiB.length).toBe(32 * KiB);
  });

  it('two DIFFERENT-length inputs in the SAME bucket multiple produce the SAME padded size (entry-count hiding)', () => {
    // Both 100 bytes and 5000 bytes land in the first 16 KiB bucket → 16384 each.
    const a = padToTieredBucket(new Uint8Array(100));
    const b = padToTieredBucket(new Uint8Array(5000));
    expect(a.length).toBe(b.length);
    expect(a.length).toBe(16 * KiB);

    // Both 17 KiB and 31 KiB (+4 prefix) land in the SECOND 16 KiB multiple → 32 KiB each.
    const c = padToTieredBucket(new Uint8Array(17 * KiB));
    const d = padToTieredBucket(new Uint8Array(31 * KiB - 4));
    expect(c.length).toBe(d.length);
    expect(c.length).toBe(32 * KiB);
  });

  it('unpad(padToTieredBucket(x)) byte-equals x across all three tiers', () => {
    const sodiumPseudo = (n: number): Uint8Array => {
      // Deterministic fill (NOT a CSPRNG — this is a test fixture, not key material).
      const out = new Uint8Array(n);
      for (let i = 0; i < n; i++) out[i] = (i * 31 + 7) & 0xff;
      return out;
    };

    // tier 1 (≤256 KiB), tier 2 (≤1 MiB), tier 3 (>1 MiB)
    const lengths = [
      1,
      10,
      16 * KiB - 4,
      200 * KiB,
      300 * KiB,
      700 * KiB,
      1024 * KiB,
      2 * 1024 * KiB,
    ];
    for (const len of lengths) {
      const original = sodiumPseudo(len);
      const padded = padToTieredBucket(original);
      const restored = unpad(padded);
      expect(restored.length).toBe(len);
      expect(Array.from(restored)).toEqual(Array.from(original));
    }
  });

  it('endianness KAT: the 4-byte prefix for a known length reads back little-endian against a checked-in byte array', () => {
    // Known length 0x01020304 = 16909060 bytes is impractical to allocate; instead use a
    // small data buffer and assert the literal prefix bytes for its real length.
    // realLen = 300 = 0x0000012C. Little-endian bytes: [0x2C, 0x01, 0x00, 0x00].
    const padded = padToTieredBucket(new Uint8Array(300));
    const prefix = Array.from(padded.subarray(0, 4));
    expect(prefix).toEqual([0x2c, 0x01, 0x00, 0x00]); // LE, not BE ([0x00,0x00,0x01,0x2c])

    // And it reads back as 300 via getUint32(0, true).
    const view = new DataView(padded.buffer, padded.byteOffset, padded.byteLength);
    expect(view.getUint32(0, true)).toBe(300);
    // Sanity: big-endian read would be wrong (proves the LE pin matters).
    expect(view.getUint32(0, false)).not.toBe(300);
  });

  it('unpad throws when the prefix claims a length exceeding the buffer (over-read guard, T-02-13)', () => {
    // Build a 16 KiB buffer but lie in the prefix: claim realLen = 1_000_000 (> buffer).
    const forged = new Uint8Array(16 * KiB);
    const view = new DataView(forged.buffer);
    view.setUint32(0, 1_000_000, true);
    expect(() => unpad(forged)).toThrow();

    // Also: a buffer too short to even hold the 4-byte prefix throws.
    expect(() => unpad(new Uint8Array(2))).toThrow();
  });
});
