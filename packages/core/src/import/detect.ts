// packages/core/src/import/detect.ts
//
// Format auto-detection for the CSV import pipeline (IMPORT-02/03).
//
// `detectFormat` is a pure function: it takes the raw headers from the first CSV
// row and returns the first matching ImportMapper, or null when no known format
// matches (which triggers the IMPORT-03 generic fallback column-mapping UI in
// apps/desktop).
//
// Mirrors the `evaluateLock` pure-function seam pattern in storage/lockLogic.ts
// (P3-08 precedent): all input is injected, no IO, no side effects.
//
// Core purity: no @tauri-apps/*, svelte, node:fs, node:path imports.
// No console.*, no Math.random.

import { ALL_MAPPERS, type ImportMapper } from './mappers';

/**
 * Detect the CSV export format from the given header row.
 *
 * Headers are passed as-is (raw strings from the CSV); each mapper normalizes
 * them internally (lowercase + trim) to avoid column-index matching (PITFALL 15).
 *
 * @param headers The header strings from the CSV's first data row.
 * @returns The matching `ImportMapper`, or `null` when no known format is
 *          detected (callers should show the IMPORT-03 generic column-map UI).
 */
export function detectFormat(headers: string[]): ImportMapper | null {
  for (const mapper of ALL_MAPPERS) {
    if (mapper.detect(headers)) {
      return mapper;
    }
  }
  return null;
}
