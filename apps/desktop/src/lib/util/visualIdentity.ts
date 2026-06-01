// apps/desktop/src/lib/util/visualIdentity.ts
//
// D-IDENTITY — deterministic visual identity derivation for entry tiles (UI-10).
//
// Produces a stable hue (0–359) and initial character for a given seed string
// (typically the entry title, falling back to username). The algorithm is
// FNV-1a 32-bit, matching EXACTLY the `hueFromLabel` function exported from
// VisualIdentity.svelte so list rows and detail headers always agree.
//
// Security notes:
//   - No Math.random — T-04-02 / project-wide ban. Hue is deterministic, not
//     random, and is presentational only (not a security boundary).
//   - No network — favicon fetch is an off-by-default Setting (UI-10); this
//     module is the always-available fallback.
//   - FNV-1a constants are from https://www.isthe.com/chongo/tech/comp/fnv/#FNV-param

/** FNV-1a 32-bit constants (same as contentHash.ts + VisualIdentity.svelte). */
const FNV_OFFSET_BASIS = 0x811c9dc5;
const FNV_PRIME = 0x01000193;

/**
 * Stable FNV-1a 32-bit hash → hue (0–359).
 *
 * The algorithm is BYTE-FOR-BYTE IDENTICAL to `hueFromLabel` in
 * `lib/components/VisualIdentity.svelte` so that both entry-list rows and the
 * detail-pane header derive the same hue for the same title.
 *
 * No Math.random. Deterministic. No network.
 *
 * @param seed  The entry title (or username) to derive the hue from.
 * @returns A hue in [0, 360) suitable for use in `hsl(hue ...)`.
 */
export function hueFor(seed: string): number {
  let h = FNV_OFFSET_BASIS;
  for (let i = 0; i < seed.length; i++) {
    h ^= seed.charCodeAt(i);
    h = Math.imul(h, FNV_PRIME);
  }
  return (h >>> 0) % 360;
}

/**
 * Derive a visual identity descriptor for an entry.
 *
 * @param seed  The entry title (or username).
 * @returns `{ hue, initial }` where:
 *   - `hue` is the FNV-1a derived hue (0–359) for the tile background.
 *   - `initial` is the first visible character of `seed`, uppercased.
 *     Falls back to `'?'` for empty/whitespace-only input.
 *
 * Usage in a template:
 *   style="background: hsl({id.hue} var(--identity-s) var(--identity-l));"
 */
export function identity(seed: string): { hue: number; initial: string } {
  return {
    hue: hueFor(seed),
    initial: (seed.trim()[0] ?? '?').toUpperCase(),
  };
}
