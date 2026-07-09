// packages/core/src/hibp/kanon.ts
//
// k-anonymity split + local suffix match (D-07, D-08, SC-3).
//
// `splitPrefixSuffix` divides a 40-char SHA-1 hex digest into the 5-char prefix
// (the ONLY part that ever leaves the device, D-01) and the 35-char suffix (which
// stays local and is matched here against the range response Rust shuttles back —
// D-07: Rust never parses/interprets the response, all logic lives in this module).
//
// `matchesSuffix` is the SC-3 GATE: both the target suffix and every parsed
// response-line suffix are normalized to UPPERCASE before comparing (D-08). HIBP's
// own API already returns uppercase suffixes, but a naive case-sensitive/
// case-mismatched comparison here would silently misreport a REAL breach as "not
// found" — exactly the false-negative class this phase exists to catch structurally.
//
// Core purity: no @tauri-apps/*, svelte, node:fs, node:path imports. No
// console.*, no Math.random, no Date.now().

/** Splits a 40-char SHA-1 hex digest into its 5-char prefix and 35-char suffix. */
export function splitPrefixSuffix(hex40: string): { prefix: string; suffix: string } {
  return { prefix: hex40.slice(0, 5), suffix: hex40.slice(5) };
}

/**
 * Returns true if `suffix` (case-insensitive) appears as the `SUFFIX:COUNT`
 * left-hand-side of any line in `responseLines` (D-08 GATE — both sides
 * uppercased before comparison).
 */
export function matchesSuffix(responseLines: string[], suffix: string): boolean {
  const target = suffix.toUpperCase();
  return responseLines.some((line) => {
    const [lineSuffix] = line.split(':');
    return lineSuffix?.toUpperCase() === target;
  });
}
