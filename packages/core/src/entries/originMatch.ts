// packages/core/src/entries/originMatch.ts
//
// FILL-03: pure eTLD+1 extraction wrapper around the bundled `tldts` Public Suffix
// List. D-02 lenient parse (bare host, full URL, or schemeless input all accepted),
// D-03 fail-closed (non-registrable input -> null, never a guessed match), D-04
// ASCII/punycode normalization via tldts internals (blocks unicode-homograph
// over-matching before comparison). Strings in, strings out — no IO, no Svelte,
// no Tauri (core purity, CLAUDE.md). `tldts` ships its PSL data as a bundled JS
// module (no network fetch) and has zero runtime dependencies, so it is imported
// directly here rather than funneled through a single-entry module — it is not a
// security primitive (unlike libsodium's `crypto/sodium.ts` gate).
//
// Source: 16-CONTEXT.md D-01..D-04, 16-RESEARCH.md Pattern 2.

import { getDomain } from 'tldts';

/**
 * Reduce a raw URL, bare host, or schemeless host string to its eTLD+1
 * registrable domain, using the bundled Public Suffix List.
 *
 * D-02: leniently accepts a bare host (`example.com`), a full URL
 * (`https://accounts.google.com/path`), or a URL missing a scheme
 * (`example.com:8080/path`) — the second case is retried with a dummy
 * `https://` scheme prepended.
 * D-03: IP addresses, `localhost`, `file://`/`chrome://`/`about:` schemes,
 * empty strings, and anything else with no real registrable domain return
 * `null` — never a guessed/partial match (fail closed).
 * D-04: `tldts` normalizes to ASCII/punycode internally before suffix
 * matching, so the returned string (when non-null) is always ASCII.
 */
export function registrableHost(rawUrlOrHost: string): string | null {
  if (!rawUrlOrHost || rawUrlOrHost.trim() === '') return null;

  // Try as-is first — tldts' parser accepts both bare hosts and full URLs.
  const direct = getDomain(rawUrlOrHost);
  if (direct !== null) return direct;

  // D-02: retry with a dummy scheme prepended for schemeless inputs tldts'
  // URL parser might reject without a protocol (e.g. "example.com:8080/path").
  try {
    return getDomain(`https://${rawUrlOrHost}`);
  } catch {
    return null;
  }
}
