// apps/desktop/src/lib/import/__tests__/detectEncoding.test.ts
//
// GAP A (IMPORT-04 → COVERED): unit tests for detectBom().
//
// Covers all four encoding outcomes:
//   UTF-16 LE  — FF FE
//   UTF-16 BE  — FE FF
//   UTF-8 BOM  — EF BB BF
//   Plain UTF-8 — no BOM
//
// Node environment (vitest.config.ts: environment: 'node').
// No mocks required — detectBom is a pure function with no imports.

import { describe, it, expect } from 'vitest';
import { detectBom } from '../detectEncoding';

describe('detectBom (IMPORT-04)', () => {
  // ── UTF-16 LE ──────────────────────────────────────────────────────────────

  it('returns utf-16-le for FF FE (UTF-16 LE BOM)', () => {
    const bytes = new Uint8Array([0xff, 0xfe, 0x41, 0x00]); // FF FE A\0
    const result = detectBom(bytes);
    expect(result.encoding).toBe('utf-16-le');
  });

  it('returns utf-16-le for exactly 2 bytes FF FE', () => {
    const bytes = new Uint8Array([0xff, 0xfe]);
    const result = detectBom(bytes);
    expect(result.encoding).toBe('utf-16-le');
  });

  // ── UTF-16 BE ──────────────────────────────────────────────────────────────

  it('returns utf-16-be for FE FF (UTF-16 BE BOM)', () => {
    const bytes = new Uint8Array([0xfe, 0xff, 0x00, 0x41]); // FE FF \0A
    const result = detectBom(bytes);
    expect(result.encoding).toBe('utf-16-be');
  });

  it('returns utf-16-be for exactly 2 bytes FE FF', () => {
    const bytes = new Uint8Array([0xfe, 0xff]);
    const result = detectBom(bytes);
    expect(result.encoding).toBe('utf-16-be');
  });

  // ── UTF-8 BOM ─────────────────────────────────────────────────────────────

  it('returns utf-8-bom for EF BB BF (UTF-8 BOM)', () => {
    const bytes = new Uint8Array([0xef, 0xbb, 0xbf, 0x6e, 0x61, 0x6d, 0x65]); // BOM + "name"
    const result = detectBom(bytes);
    expect(result.encoding).toBe('utf-8-bom');
  });

  it('returns utf-8-bom for exactly 3 bytes EF BB BF', () => {
    const bytes = new Uint8Array([0xef, 0xbb, 0xbf]);
    const result = detectBom(bytes);
    expect(result.encoding).toBe('utf-8-bom');
  });

  it('EF BB FE is NOT a UTF-8 BOM (third byte differs) — falls through to utf-8', () => {
    const bytes = new Uint8Array([0xef, 0xbb, 0xfe]);
    const result = detectBom(bytes);
    expect(result.encoding).toBe('utf-8');
  });

  // ── Plain UTF-8 / ASCII ───────────────────────────────────────────────────

  it('returns utf-8 for plain ASCII content with no BOM', () => {
    // "name,url,username,password\n"
    const encoder = new TextEncoder();
    const bytes = encoder.encode('name,url,username,password\n');
    const result = detectBom(bytes.slice(0, 3));
    expect(result.encoding).toBe('utf-8');
  });

  it('returns utf-8 for a single byte', () => {
    const bytes = new Uint8Array([0x6e]); // 'n'
    const result = detectBom(bytes);
    expect(result.encoding).toBe('utf-8');
  });

  it('returns utf-8 for an empty Uint8Array', () => {
    const bytes = new Uint8Array([]);
    const result = detectBom(bytes);
    expect(result.encoding).toBe('utf-8');
  });

  it('returns utf-8 for a UTF-8 multi-byte sequence that is not a BOM', () => {
    // 3-byte UTF-8 sequence for U+2022 BULLET (E2 80 A2) — not a BOM
    const bytes = new Uint8Array([0xe2, 0x80, 0xa2]);
    const result = detectBom(bytes);
    expect(result.encoding).toBe('utf-8');
  });

  // ── Priority order (UTF-16 LE before UTF-8 BOM check) ─────────────────────
  // FF FE should be caught as UTF-16 LE even if a third byte matches BF.
  it('FF FE BF is utf-16-le, not utf-8-bom (UTF-16 LE check runs first)', () => {
    const bytes = new Uint8Array([0xff, 0xfe, 0xbf]);
    const result = detectBom(bytes);
    expect(result.encoding).toBe('utf-16-le');
  });
});
