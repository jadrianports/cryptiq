// packages/core/src/import/dedup.ts
//
// Duplicate detection for the CSV import pipeline (IMPORT-05, P6-03).
//
// `deduplicateRows` flags incoming CSV rows as duplicates when their
// `lowercase(url) + '::' + lowercase(username)` key matches any ACTIVE
// (deletedAt === null) entry in the existing vault. Tombstones (soft-deleted
// entries) are NOT counted as active and do NOT produce duplicate flags.
//
// Duplicates default to `action: 'skip'`. The desktop wizard (apps/desktop)
// may allow the user to flip individual rows to `action: 'import'` for a
// "import as new anyway" override (P6-03 — no field-level merge in v1).
//
// Mirrors the `listEntries` active-filter pattern in entries/crud.ts.
//
// Core purity: no @tauri-apps/*, svelte, node:fs, node:path imports.
// No console.*, no Math.random.

import type { Entry } from '../entries/types';
import type { MappedRow, DedupResult } from './types';

/**
 * Annotate each `MappedRow` with duplicate-detection metadata.
 *
 * A row is a duplicate if its `url::username` key (both lowercased) matches
 * an ACTIVE (`deletedAt === null`) entry in `existingEntries`. Tombstones
 * are excluded from the active set.
 *
 * @param rows            The mapped rows to check.
 * @param existingEntries The full entry array from the unlocked vault
 *                        (including tombstones — this function filters them).
 * @returns               An array of `DedupResult` in the same order as `rows`.
 */
export function deduplicateRows(
  rows: MappedRow[],
  existingEntries: Entry[],
): DedupResult[] {
  // Build a Set of `lowercase(url)::lowercase(username)` keys from ACTIVE entries only.
  const activeKeys = new Set<string>(
    existingEntries
      .filter((e) => e.deletedAt === null)
      .map((e) => `${e.url.toLowerCase()}::${e.username.toLowerCase()}`),
  );

  return rows.map((row): DedupResult => {
    const urlLower      = row.url.toLowerCase();
    const usernameLower = row.username.toLowerCase();

    // FIX 4: when both url AND username are empty, the key is '::' — a trivial
    // collision. An existing entry with url=''+username='' would add '::' to
    // activeKeys, causing every subsequent empty-keyed import row to be flagged as
    // a duplicate and skipped. This is incorrect: an empty url+username provides no
    // meaningful identity. Treat empty-keyed rows as non-duplicates (never skip them
    // based on a '::' key match).
    const isEmptyKey = urlLower === '' && usernameLower === '';
    const key = `${urlLower}::${usernameLower}`;
    const isDuplicate = !isEmptyKey && activeKeys.has(key);
    return {
      row,
      isDuplicate,
      // Default: duplicates → 'skip'; non-duplicates → 'import' (IMPORT-05 / P6-03)
      action: isDuplicate ? 'skip' : 'import',
    };
  });
}
