// packages/core/src/entries/uuid.ts
//
// UUIDv4 formatter — pure bit-twiddling, no randomness.
// The caller supplies 16 CSPRNG bytes from `sodium.randombytes_buf(16)` (P3-03).
// This is a PURE FORMATTER: it sets the RFC-4122 version/variant nibbles and
// formats the result as the canonical 8-4-4-4-12 hex string.
//
// Why not `crypto.randomUUID()`? That bypasses the project-wide "all randomness
// via sodium.randombytes_*" convention (CLAUDE.md / GEN-03). Splitting the
// randomness source widens the audit surface for no benefit.
//
// Source: CONTEXT.md P3-03 + 03-RESEARCH Pattern 2 + RFC 4122 §4.4.

/**
 * Format 16 CSPRNG bytes as an RFC-4122 version-4 UUID string.
 *
 * Mutates `b` in place to set:
 *   - octet 6 bits 12–15: `0100` (version = 4)
 *   - octet 8 bits 6–7:   `10`   (variant = RFC 4122 / 10xx)
 *
 * Returns the canonical `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx` format.
 *
 * @param b 16 raw bytes from `sodium.randombytes_buf(16)`.
 *          MUST be a Uint8Array of exactly 16 bytes.
 */
export function uuidV4FromBytes(b: Uint8Array): string {
  // Set version = 4: keep lower nibble of octet 6, force upper nibble to 0x4
  b[6] = (b[6]! & 0x0f) | 0x40;
  // Set variant = 10xx: keep lower 6 bits of octet 8, force upper 2 bits to 10
  b[8] = (b[8]! & 0x3f) | 0x80;

  const hex = Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');

  // 8-4-4-4-12 grouping
  return (
    `${hex.slice(0, 8)}-` +
    `${hex.slice(8, 12)}-` +
    `${hex.slice(12, 16)}-` +
    `${hex.slice(16, 20)}-` +
    `${hex.slice(20, 32)}`
  );
}
