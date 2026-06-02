// packages/core/src/import/map.ts
//
// Row mapping for the CSV import pipeline (IMPORT-08, P6-04).
//
// `mapRow` applies a format mapper to a raw CSV row and returns either a
// fully-populated `MappedRow` or a `{ malformed: true; reason }` result.
//
// IMPORT-08 / Pitfall 4 (verbatim inerting): CSV-injection characters
// (=/+/-/@ prefixes, tab-prefixed values) are stored EXACTLY as received —
// never prefixed with `'`. Cryptiq does not execute values as formulas, so
// the only correct approach is pass-through storage.
//
// Core purity: no @tauri-apps/*, svelte, node:fs, node:path imports.
// No console.*, no Math.random.

import type { ImportMapper } from './mappers';
import type { MappedRow } from './types';

/**
 * The type of a malformed-row result (P6-04).
 *
 * Returned instead of `MappedRow` when a row is structurally invalid (e.g.
 * missing a required title field). The caller collects these into the
 * `ImportResult.malformed` array — never silently drops them.
 */
export interface MalformedRow {
  malformed: true;
  reason: string;
}

/**
 * Apply `mapper` to a raw CSV row and produce a `MappedRow`.
 *
 * Returns `{ malformed: true; reason }` when the row cannot produce a valid
 * entry (currently: empty or whitespace-only `title`). For all other fields,
 * missing values are defaulted to `''`.
 *
 * CRITICAL (IMPORT-08 / Pitfall 4): The `password` and `notes` fields are
 * stored VERBATIM — this function MUST NOT prepend `'` to `=/+/-/@`-prefixed
 * values. Cryptiq never interprets them as formulas; pass-through is the
 * correct and only safe behaviour for an import path.
 *
 * @param rawRow   A `Record<string, string>` keyed by original CSV headers
 *                 (as produced by papaparse in header mode, or by the test
 *                 helpers that parse fixture CSVs).
 * @param mapper   The format mapper returned by `detectFormat()`.
 * @param rowIndex 0-based source row index for error reporting (optional;
 *                 defaults to 0 when omitted).
 * @returns        `MappedRow` on success, `MalformedRow` on failure.
 */
export function mapRow(
  rawRow: Record<string, string>,
  mapper: ImportMapper,
  rowIndex = 0,
): MappedRow | MalformedRow {
  const partial = mapper.map(rawRow);

  // Trim the title and validate it is non-empty (required field).
  const title = (partial.title ?? '').trim();
  if (title.length === 0) {
    return {
      malformed: true,
      reason: 'missing required title',
    };
  }

  // All remaining fields default to '' when absent/undefined.
  // IMPORT-08: password and notes are stored WITHOUT any mutation — no `'` prefix.
  return {
    title,
    url:      partial.url      ?? '',
    username: partial.username ?? '',
    password: partial.password ?? '', // VERBATIM — never prepend '
    notes:    partial.notes    ?? '', // VERBATIM — never prepend '
    sourceRowIndex: rowIndex,
  };
}
