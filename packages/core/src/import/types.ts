// packages/core/src/import/types.ts
//
// Type definitions for the CSV import pipeline (P6-01 / IMPORT-05/06/08).
//
// Design notes:
//   - `MappedRow` is the output of `mapRow()`: all string fields defaulted to ''
//     and password/notes stored VERBATIM (IMPORT-08 — no inerting prefix).
//   - `DedupResult` wraps a MappedRow with duplicate-detection metadata.
//   - `ImportResult` summarises the final commit.
//   - `EntryInput` from entries/types is the output of `normalizeRow()`.
//
// Core purity: no @tauri-apps/*, svelte, node:fs, node:path imports.

import type { EntryInput } from '../entries/types';

// Re-export EntryInput so callers can import it from this module if desired.
export type { EntryInput };

/**
 * A single CSV row after header→field mapping.
 *
 * All string fields are guaranteed to be present (empty string when absent in the
 * source CSV). The `password` and `notes` fields are stored VERBATIM — IMPORT-08
 * forbids prepending a `'` prefix to `=/+/-/@`-prefixed values.
 */
export interface MappedRow {
  /** Entry title derived from the source format's name/title/url column. */
  title: string;
  url: string;
  username: string;
  /** Stored exactly as supplied — never prefixed with `'`. */
  password: string;
  /** Stored exactly as supplied — never prefixed with `'`. */
  notes: string;
  /** 0-based index of the original source row (for error reporting). */
  sourceRowIndex: number;
}

/** What to do with a duplicate row in the commit step (IMPORT-05 / P6-03). */
export type DuplicateAction = 'skip' | 'import';

/**
 * A `MappedRow` annotated with duplicate-detection results (IMPORT-05).
 *
 * `isDuplicate` is `true` when the row's lowercase `url::username` matches an
 * ACTIVE (`deletedAt === null`) entry in the existing vault. Duplicates default
 * to `action: 'skip'`; the desktop wizard may flip this to `'import'` when the
 * user explicitly overrides (P6-03 — no merge in v1).
 */
export interface DedupResult {
  row: MappedRow;
  isDuplicate: boolean;
  /** Default: `'skip'` for duplicates, `'import'` for non-duplicates. */
  action: DuplicateAction;
}

/**
 * Final summary returned after committing an import batch.
 *
 * `malformed` is populated by `mapRow` results that returned `{ malformed: true }`;
 * the import flow collects them into this array rather than silently dropping rows
 * (P6-04 — "import the good, report the skipped").
 */
export interface ImportResult {
  /** Number of entries successfully added to the vault. */
  committed: number;
  /** Number of rows skipped (duplicates with action='skip' + malformed rows). */
  skipped: number;
  /** Rows that could not be parsed: reason collected, never silently dropped. */
  malformed: Array<{ rowIndex: number; reason: string }>;
}
