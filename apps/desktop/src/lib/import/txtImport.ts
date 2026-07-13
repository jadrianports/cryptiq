// apps/desktop/src/lib/import/txtImport.ts
//
// Svelte-free orchestration for the .txt import front door (IMPORT-09/10/11).
//
// Extracts the .txt sniff/tokenize/BOM-gate orchestration from ImportView.svelte's
// handleFileSelect into a testable helper — the component holds $state, this
// module holds the logic (mirrors sasCountdown.ts's "extract pure/orchestration
// logic out of a .svelte file" pattern, P12-07 precedent).
//
// Unlike packages/core (fully IO-free), this module DOES touch the browser File
// API (file.slice/file.text) — it is Svelte-free orchestration, not pure core
// logic, so it is NOT held to core's zero-IO purity rule.
//
// IMPORT-11 "no fast path" (D-03): this module deliberately never calls the
// CSV path's header-based auto-detect helper — that omission IS the literal
// mechanism that keeps .txt imports off the "confidently sniffed" fast path.
// The caller (ImportView.svelte) must always route a .txt selection to the
// column-map step, never straight to preview. See 32-RESEARCH.md Assumption
// A4 / Anti-Patterns.
//
// Sentinel errors (utf16-rejected / empty-file): thrown as plain Error objects
// with a fixed `.message` so the caller maps them to the EXISTING user-facing
// copy strings (ImportView.svelte owns that copy, not this module).

import { sniffFormat, tokenize, type SniffCandidate, type SniffFormat, type RaggedRow } from '@cryptiq/core';
import { detectBom } from './detectEncoding';

/** Result of reading + sniffing + tokenizing a user-selected .txt file. */
export interface ReadTxtFileResult {
  /**
   * The non-empty, non-blank text lines split from the file (caller stashes
   * these so a later pill-click can re-tokenize under a different format
   * without re-reading the file).
   */
  lines: string[];
  headers: string[];
  dataRows: string[][];
  raggedRows: RaggedRow[];
  candidates: SniffCandidate[];
  bestFormat: SniffFormat;
}

/**
 * Read + sniff + tokenize a user-selected .txt file.
 *
 * Flow: BOM gate (reuses `detectBom()` verbatim, same 3-byte-prefix check the
 * CSV path already performs) -> `file.text()` -> split into non-empty lines ->
 * `sniffFormat()` -> `tokenize()`.
 *
 * Throws `Error('utf16-rejected')` for a UTF-16 LE/BE BOM file and
 * `Error('empty-file')` for a whitespace/blank-only file — both are sentinels
 * the caller maps to the EXISTING copy strings, not error text shown directly.
 *
 * @param file The user-selected .txt File.
 */
export async function readTxtFile(file: File): Promise<ReadTxtFileResult> {
  const headerBuf = await file.slice(0, 3).arrayBuffer();
  const headerBytes = new Uint8Array(headerBuf);
  const bomResult = detectBom(headerBytes);

  if (bomResult.encoding === 'utf-16-le' || bomResult.encoding === 'utf-16-be') {
    throw new Error('utf16-rejected');
  }

  const text = await file.text();
  const lines = text.split(/\r?\n/).filter((l) => l.trim().length > 0);

  if (lines.length === 0) {
    throw new Error('empty-file');
  }

  const { candidates, bestFormat } = sniffFormat(lines);
  const { headers, dataRows, raggedRows } = tokenize(lines, bestFormat);

  return { lines, headers, dataRows, raggedRows, candidates, bestFormat };
}
