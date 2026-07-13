// apps/desktop/src/lib/import/__tests__/txtImport.test.ts
//
// Unit tests for readTxtFile() — the .txt import orchestration helper
// (IMPORT-09/10/11, 32-02-PLAN.md Task 1).
//
// Covers:
//   - UTF-16 LE/BE BOM rejection (utf16-rejected sentinel)
//   - Whitespace/blank-only file rejection (empty-file sentinel)
//   - A UTF-8 (and UTF-8-BOM) .txt file returns { headers, dataRows, bestFormat }
//     via the sniffFormat()/tokenize() handoff
//   - The stashed `lines` are exposed for a later pill-click re-tokenize
//   - Structural proof: the module source never references detectFormat()
//     (IMPORT-11 "no fast path" at the helper tier)
//   - Barrel-only import: no deep '@cryptiq/core/src/...' import path
//
// Node environment (vitest.config.ts: environment: 'node'). No mocks required.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { readTxtFile } from '../txtImport';

const MODULE_SOURCE = readFileSync(join(__dirname, '../txtImport.ts'), 'utf-8');

function makeTxtFile(content: string, name = 'passwords.txt'): File {
  return new File([content], name, { type: 'text/plain' });
}

function makeUtf16File(bomBytes: number[]): File {
  const bytes = new Uint8Array([...bomBytes, 0x41, 0x00]);
  return new File([bytes], 'passwords.txt', { type: 'text/plain' });
}

describe('readTxtFile (IMPORT-09/10/11)', () => {
  it('rejects a UTF-16 LE BOM file with the utf16-rejected sentinel', async () => {
    const file = makeUtf16File([0xff, 0xfe]);
    await expect(readTxtFile(file)).rejects.toThrow('utf16-rejected');
  });

  it('rejects a UTF-16 BE BOM file with the utf16-rejected sentinel', async () => {
    const file = makeUtf16File([0xfe, 0xff]);
    await expect(readTxtFile(file)).rejects.toThrow('utf16-rejected');
  });

  it('rejects a whitespace/blank-only file with the empty-file sentinel', async () => {
    const file = makeTxtFile('   \n\n\t \n   \n');
    await expect(readTxtFile(file)).rejects.toThrow('empty-file');
  });

  it('reads a UTF-8 comma-separated .txt file and returns headers/dataRows/bestFormat', async () => {
    const file = makeTxtFile('Gmail,john,hunter2\nYahoo,jane,pass1\n');
    const result = await readTxtFile(file);

    expect(result.bestFormat).toBe('comma');
    expect(result.headers).toEqual(['Column 1', 'Column 2', 'Column 3']);
    expect(result.dataRows).toEqual([
      ['Gmail', 'john', 'hunter2'],
      ['Yahoo', 'jane', 'pass1'],
    ]);
    expect(result.raggedRows).toEqual([]);
    expect(result.candidates).toHaveLength(5);
  });

  it('reads a UTF-8-BOM .txt file without rejecting it', async () => {
    const bom = new Uint8Array([0xef, 0xbb, 0xbf]);
    const textBytes = new TextEncoder().encode('Gmail,john,hunter2\n');
    const bytes = new Uint8Array(bom.length + textBytes.length);
    bytes.set(bom, 0);
    bytes.set(textBytes, bom.length);
    const file = new File([bytes], 'passwords.txt', { type: 'text/plain' });

    const result = await readTxtFile(file);
    expect(result.bestFormat).toBe('comma');
  });

  it('exposes the split lines for the pill-click re-tokenize path', async () => {
    const file = makeTxtFile('Gmail,john,hunter2\nYahoo,jane,pass1\n');
    const result = await readTxtFile(file);
    expect(result.lines).toEqual(['Gmail,john,hunter2', 'Yahoo,jane,pass1']);
  });

  it('structural: the module source never references detectFormat (IMPORT-11 no-fast-path)', () => {
    expect(MODULE_SOURCE.includes('detectFormat')).toBe(false);
  });

  it('imports sniffFormat/tokenize from the @cryptiq/core barrel, never a deep path', () => {
    expect(MODULE_SOURCE.includes("from '@cryptiq/core'")).toBe(true);
    expect(MODULE_SOURCE.includes('@cryptiq/core/src')).toBe(false);
  });
});
