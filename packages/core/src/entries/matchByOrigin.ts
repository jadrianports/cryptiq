// packages/core/src/entries/matchByOrigin.ts
//
// FILL-03 / BRIDGE-08: pure entries -> metadata-only origin matcher.
//
// `matchByOrigin` reduces a page origin and each candidate entry's `url` to
// their eTLD+1 registrable host (via `registrableHost`) and returns the
// entries whose host matches, as `EntryMatchMetadata` — a response shape that
// structurally cannot carry a `password` field (SC-1 / BRIDGE-08 wire-
// minimization guarantee; the type simply has no such field, so no dispatch
// path can leak one accidentally).
//
// D-03: a non-registrable `pageOrigin` (IP, localhost, file://, empty, …)
// yields an empty result set — fail closed, never a guessed match.
// D-02: candidate entries whose `url` is empty or unparseable are skipped
// (never matched) rather than excluded via a special-case error.
// Soft-deleted entries (`deletedAt !== null`) are excluded from candidates —
// a tombstone must never surface as a fillable match.
// D-08: results are ordered favorites-first, then `modifiedAt` descending.
//
// Phase 21 (D-10): an entry's `equivalentUrls` OR into the host predicate — a
// candidate matches when its primary `url` OR any `equivalentUrls[i]` reduces
// to the target's eTLD+1 via `registrableHost()`. Every candidate string
// (primary and each equivalent) passes through the SAME exact-eTLD+1
// comparator — never substring/startsWith — so cousin/typosquat lookalike
// domains remain rejected (T-21-02).
//
// `opts?` is a documented-but-unimplemented seam for the committed later-phase
// per-entry "exact host only" match-strictness toggle (16-CONTEXT.md Deferred
// Ideas / D-01) — accepting the parameter now avoids a signature-breaking
// change when that toggle lands; it does nothing yet.
//
// Bytes/strings in, plain objects out — no IO, no Svelte, no Tauri (core
// purity, CLAUDE.md).
//
// Source: 16-CONTEXT.md D-01/D-02/D-03/D-05/D-06/D-07/D-08, 16-PATTERNS.md.

import type { Entry } from './types';
import { registrableHost } from './originMatch';

/**
 * Metadata-only match result. Deliberately has NO `password` field — this is
 * a structural guarantee (SC-1 / BRIDGE-08), not a convention: the secret for
 * a specific `id` only ever crosses on the separate `fill-entry` RPC path.
 */
export interface EntryMatchMetadata {
  id: string;
  title: string;
  username: string;
  /** The eTLD+1 registrable domain both this entry and the page origin share. */
  domainHint: string;
}

/**
 * Options seam for the committed later-phase per-entry match-strictness
 * toggle (exact host vs. base-domain). Unimplemented this phase — reserved so
 * the signature does not need to change when that toggle lands.
 */
// Intentional forward-compat seam; see module header. Not `Record<string, never>`
// because a future strictness flag will be an actual named field, not an index
// signature.
export type MatchByOriginOptions = object;

/**
 * Wire shape for `matchByOrigin` (Phase 19 Plan 01 / CAP-01/CAP-04).
 *
 * `registrableDomain` is computed UNCONDITIONALLY — even when `candidates` is
 * empty (a brand-new site with zero saved entries, or a non-registrable
 * origin) — so callers needing only the page's own eTLD+1 (CAP-01's new-site
 * title default, CAP-04's never-save keying) never need a second PSL lookup.
 * `null` for a non-registrable origin (IP/localhost/file/empty), matching
 * D-03's fail-closed candidate behavior.
 */
export interface MatchByOriginResult {
  registrableDomain: string | null;
  candidates: EntryMatchMetadata[];
}

/**
 * Match vault entries against a page origin by eTLD+1 base domain, returning
 * metadata-only results ordered favorites-first then `modifiedAt` descending,
 * alongside the page's own registrable domain (unconditional — Phase 19
 * Pattern 2).
 */
export function matchByOrigin(
  entries: Entry[],
  pageOrigin: string,
  _opts?: MatchByOriginOptions,
): MatchByOriginResult {
  const targetHost = registrableHost(pageOrigin);
  if (targetHost === null) {
    // D-03: no registrable domain -> empty candidate set, fail closed. The
    // domain itself is still surfaced (null) so callers don't need a second check.
    return { registrableDomain: null, candidates: [] };
  }

  const candidates = entries
    .filter((e) => e.deletedAt === null) // tombstones never surface as matches
    .filter((e) => {
      // D-02: skip unparseable/empty urls. D-10: OR in equivalentUrls — every
      // candidate (primary url and each equivalent) goes through
      // registrableHost(), never substring/startsWith (T-21-02).
      if (registrableHost(e.url) === targetHost) return true;
      return (e.equivalentUrls ?? []).some((u) => registrableHost(u) === targetHost);
    })
    .sort((a, b) => {
      if (a.favorite !== b.favorite) return a.favorite ? -1 : 1; // D-08: favorites first
      return b.modifiedAt.localeCompare(a.modifiedAt); // D-08: modifiedAt descending
    })
    .map((e) => ({
      id: e.id,
      title: e.title,
      username: e.username,
      domainHint: targetHost,
    }));

  return { registrableDomain: targetHost, candidates };
}
