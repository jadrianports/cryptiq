// packages/core/src/import/__tests__/sniff.test.ts
//
// Fixture-driven unit suite for the .txt import sniffer/tokenizer (IMPORT-09/10).
//
// Requirements covered:
//   IMPORT-09 — sniffFormat() picks the lowest-variance eligible delimiter/format
//               across comma/tab/whitespace/kv-colon/kv-equals candidates
//   IMPORT-10 — tokenize() produces headers + dataRows/raggedRows feeding the
//               existing buildPreviewFromMapper() seam unchanged
//   D-02a     — a single `key: value`-per-line file classifies positional, never smart-key
//   SC-3      — injection-shaped values tokenize verbatim (IMPORT-08 carry-over)
//   SC-4      — ragged rows never silently padded/truncated
//
// Fixtures under __tests__/fixtures/ contain DUMMY passwords only (SEC-10).
// This suite is the Wave-0 RED for Task 1: it imports sniff.ts's stub bodies,
// so many assertions FAIL until Tasks 2-3 implement the real algorithm.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { sniffFormat, tokenize } from '../sniff';

const FIXTURES_DIR = join(__dirname, 'fixtures');

function readFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, name), 'utf-8');
}

/** Split raw file text into non-empty lines (mirrors the desktop txtImport.ts orchestration). */
function linesOf(text: string): string[] {
  return text.split(/\r?\n/).filter((l) => l.trim().length > 0);
}

// ---------------------------------------------------------------------------
// sniffFormat — IMPORT-09
// ---------------------------------------------------------------------------

describe('sniffFormat (IMPORT-09)', () => {
  it('picks comma for a comma-consistent positional file', () => {
    const lines = linesOf(readFixture('txt-positional-comma.txt'));
    const { bestFormat, candidates } = sniffFormat(lines);
    expect(bestFormat).toBe('comma');
    expect(candidates).toHaveLength(5);
  });

  it('picks tab for a tab-consistent positional file', () => {
    const lines = linesOf(readFixture('txt-positional-tab.txt'));
    const { bestFormat } = sniffFormat(lines);
    expect(bestFormat).toBe('tab');
  });

  it('picks whitespace for a column-aligned space-padded file', () => {
    const lines = linesOf(readFixture('txt-positional-whitespace.txt'));
    const { bestFormat } = sniffFormat(lines);
    expect(bestFormat).toBe('whitespace');
  });

  it('picks kv-equals for url=/user=/pass= self-labeling lines (reordered-key line included)', () => {
    const lines = linesOf(readFixture('txt-self-labeling-equals.txt'));
    const { bestFormat } = sniffFormat(lines);
    expect(bestFormat).toBe('kv-equals');
  });

  it('picks kv-colon for comma-separated key: value lines (multi-word value included)', () => {
    const lines = linesOf(readFixture('txt-self-labeling-colon.txt'));
    const { bestFormat } = sniffFormat(lines);
    expect(bestFormat).toBe('kv-colon');
  });

  it('D-02a: a single key: value pair per line classifies positional, never kv (both kv candidates ineligible)', () => {
    const lines = linesOf(readFixture('txt-single-keyvalue-per-line.txt'));
    const { bestFormat, candidates } = sniffFormat(lines);
    expect(bestFormat).not.toBe('kv-colon');
    expect(bestFormat).not.toBe('kv-equals');
    const kvColon = candidates.find((c) => c.format === 'kv-colon');
    const kvEquals = candidates.find((c) => c.format === 'kv-equals');
    expect(kvColon?.eligible).toBe(false);
    expect(kvEquals?.eligible).toBe(false);
  });

  it('never picks a delimiter that is absent from the file (Pitfall 1 — trivial zero-variance trap)', () => {
    const lines = linesOf(readFixture('txt-positional-comma.txt'));
    const { candidates } = sniffFormat(lines);
    const tab = candidates.find((c) => c.format === 'tab');
    expect(tab?.eligible).toBe(false);
  });

  it('always returns all 5 candidates with format/label/fieldCount/variance/eligible', () => {
    const lines = linesOf(readFixture('txt-positional-comma.txt'));
    const { candidates } = sniffFormat(lines);
    const formats = candidates.map((c) => c.format).sort();
    expect(formats).toEqual(['comma', 'kv-colon', 'kv-equals', 'tab', 'whitespace']);
    for (const c of candidates) {
      expect(typeof c.label).toBe('string');
      expect(typeof c.fieldCount).toBe('number');
      expect(typeof c.variance).toBe('number');
      expect(typeof c.eligible).toBe('boolean');
    }
  });

  it('falls back gracefully (no crash) on an empty/blank-only file', () => {
    const lines = linesOf(readFixture('txt-empty.txt'));
    expect(lines).toHaveLength(0);
    const { bestFormat, candidates } = sniffFormat(lines);
    expect(candidates).toHaveLength(5);
    expect(typeof bestFormat).toBe('string');
  });

  it('uses only anchored character-class regexes — no ReDoS-shaped `.+` before a fixed anchor (Pitfall 6)', () => {
    const src = readFileSync(join(__dirname, '..', 'sniff.ts'), 'utf-8');
    expect(src).not.toMatch(/\^\(\.\+\)/);
  });
});

// ---------------------------------------------------------------------------
// tokenize — IMPORT-09/10
// ---------------------------------------------------------------------------

describe('tokenize (IMPORT-09/10)', () => {
  it('positional: synthesizes Column N headers sized to the modal field count', () => {
    const lines = linesOf(readFixture('txt-positional-comma.txt'));
    const result = tokenize(lines, 'comma');
    expect(result.headers).toEqual(['Column 1', 'Column 2', 'Column 3']);
    expect(result.dataRows).toHaveLength(3);
    expect(result.dataRows[0]).toEqual(['Gmail', 'john', 'hunter2dummy']);
    expect(result.raggedRows).toHaveLength(0);
  });

  it('kv-equals: headers are the union of keys, rows projected BY KEY NAME (reordered line)', () => {
    const lines = linesOf(readFixture('txt-self-labeling-equals.txt'));
    const result = tokenize(lines, 'kv-equals');
    expect(result.headers).toEqual(['url', 'user', 'pass']);
    // Row 3 lists keys in a different order (user, pass, url) — must still project by name.
    expect(result.dataRows[2]).toEqual(['twitter.com', 'bob', 'dummytwitpass']);
    expect(result.raggedRows).toHaveLength(0);
  });

  it('kv-colon: multi-word colon value preserved whole; missing key on other rows -> ""', () => {
    const lines = linesOf(readFixture('txt-self-labeling-colon.txt'));
    const result = tokenize(lines, 'kv-colon');
    expect(result.headers).toEqual(['site', 'user', 'pass', 'notes']);
    // Row 3 (index 2) carries the multi-word notes value — not truncated at the first space.
    expect(result.dataRows[2]).toEqual(['Notes App', 'bob', 'dummytwitpass', 'this is a longer note']);
    // Rows 1 and 2 have no 'notes' token -> ''.
    expect(result.dataRows[0]?.[3]).toBe('');
    expect(result.dataRows[1]?.[3]).toBe('');
  });

  it('D-02a fixture tokenizes to positional Column 1/Column 2, not smart keys', () => {
    const lines = linesOf(readFixture('txt-single-keyvalue-per-line.txt'));
    const { bestFormat } = sniffFormat(lines);
    const result = tokenize(lines, bestFormat);
    expect(result.headers).toEqual(['Column 1', 'Column 2']);
    expect(result.dataRows[0]).toEqual(['Gmail:', 'hunter2dummy']);
  });

  it('ragged rows: short/long rows land in raggedRows with the locked reason string; well-formed rows unaffected', () => {
    const lines = linesOf(readFixture('txt-mixed-delimiters-ragged.txt'));
    const result = tokenize(lines, 'comma');
    expect(result.headers).toEqual(['Column 1', 'Column 2', 'Column 3']);
    expect(result.dataRows).toHaveLength(3);
    expect(result.raggedRows).toHaveLength(2);
    for (const r of result.raggedRows) {
      expect(r.reason).toBe("field count didn't match the detected column layout");
    }
    const raggedIndexes = result.raggedRows.map((r) => r.rowIndex).sort((a, b) => a - b);
    expect(raggedIndexes).toEqual([3, 4]);
  });

  it('IMPORT-08/SC-3: injection-shaped values (=/+/-/@) tokenize verbatim, no leading quote', () => {
    const lines = linesOf(readFixture('txt-injection-values.txt'));
    const result = tokenize(lines, 'comma');
    expect(result.dataRows[0]?.[2]).toBe("=cmd|' /c calc'!A0");
    expect(result.dataRows[1]?.[2]).toBe('+1234567890');
    expect(result.dataRows[2]?.[2]).toBe('-1+2+3');
    expect(result.dataRows[3]?.[2]).toBe('@SUM(1+2)');
    for (const row of result.dataRows) {
      expect(row[2]?.startsWith("'")).toBe(false);
    }
  });

  it('handles a UTF-8-BOM-prefixed file without crashing, still comma-tokenizes', () => {
    const lines = linesOf(readFixture('txt-utf8-bom.txt'));
    const { bestFormat } = sniffFormat(lines);
    expect(bestFormat).toBe('comma');
    const result = tokenize(lines, bestFormat);
    expect(result.dataRows).toHaveLength(2);
  });

  it('handles an empty/blank-only file gracefully (no crash, empty rows)', () => {
    const lines = linesOf(readFixture('txt-empty.txt'));
    const result = tokenize(lines, 'whitespace');
    expect(result.dataRows).toHaveLength(0);
    expect(result.raggedRows).toHaveLength(0);
  });
});
