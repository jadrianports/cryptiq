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
 * Match vault entries against a page origin by eTLD+1 base domain, returning
 * metadata-only results ordered favorites-first then `modifiedAt` descending.
 */
export function matchByOrigin(
  entries: Entry[],
  pageOrigin: string,
  _opts?: MatchByOriginOptions,
): EntryMatchMetadata[] {
  const targetHost = registrableHost(pageOrigin);
  if (targetHost === null) return []; // D-03: no registrable domain -> empty set, fail closed

  return entries
    .filter((e) => e.deletedAt === null) // tombstones never surface as matches
    .filter((e) => registrableHost(e.url) === targetHost) // D-02: skip unparseable/empty urls
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
}
