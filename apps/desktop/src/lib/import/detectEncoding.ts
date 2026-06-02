// apps/desktop/src/lib/import/detectEncoding.ts
//
// UTF-16 BOM detection for the CSV import pipeline (IMPORT-04).
//
// The import wizard reads the first 3 bytes of the user-selected File BEFORE
// passing the text to the papaparse worker. If a UTF-16 LE or BE BOM is found,
// the import is rejected with a "please re-export as UTF-8" message (IMPORT-04).
//
// BOM byte sequences (https://en.wikipedia.org/wiki/Byte_order_mark):
//   FF FE       → UTF-16 LE (little-endian)
//   FE FF       → UTF-16 BE (big-endian)
//   EF BB BF    → UTF-8 BOM (harmless; papaparse can handle; we report it)
//   (none)      → UTF-8 or ASCII (safe to parse)
//
// No Tauri/Svelte/node imports — this file is used from both the renderer
// main thread and (if needed) the worker context.

/**
 * The result of BOM detection on the first bytes of a file.
 *
 * utf-8        — No BOM; safe for papaparse to parse.
 * utf-8-bom    — UTF-8 BOM (EF BB BF); papaparse handles this; not rejected.
 * utf-16-le    — UTF-16 little-endian BOM (FF FE); REJECTED (IMPORT-04).
 * utf-16-be    — UTF-16 big-endian BOM (FE FF); REJECTED (IMPORT-04).
 */
export type EncodingResult =
  | { encoding: 'utf-8' }
  | { encoding: 'utf-8-bom' }
  | { encoding: 'utf-16-le' }
  | { encoding: 'utf-16-be' };

/**
 * Detect the byte-order mark in the first bytes of a file.
 *
 * Call with at least 3 bytes from the start of the file (e.g. from
 * `file.slice(0, 3).arrayBuffer()` → `new Uint8Array(buf)`).
 * If fewer than 2 bytes are provided the result is `{ encoding: 'utf-8' }`.
 *
 * @param bytes The first bytes of the file (at least 3 recommended).
 * @returns     An `EncodingResult` discriminating the BOM type.
 */
export function detectBom(bytes: Uint8Array): EncodingResult {
  // UTF-16 LE BOM: FF FE
  if (bytes[0] === 0xff && bytes[1] === 0xfe) {
    return { encoding: 'utf-16-le' };
  }
  // UTF-16 BE BOM: FE FF
  if (bytes[0] === 0xfe && bytes[1] === 0xff) {
    return { encoding: 'utf-16-be' };
  }
  // UTF-8 BOM: EF BB BF (harmless but reported so the caller can strip it)
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    return { encoding: 'utf-8-bom' };
  }
  // No BOM — assume UTF-8 / ASCII
  return { encoding: 'utf-8' };
}
