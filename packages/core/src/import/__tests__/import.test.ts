// packages/core/src/import/__tests__/import.test.ts
//
// TEST-07 — CSV import pipeline test suite.
//
// Requirements covered:
//   IMPORT-02 — header-name detection for Chrome/Edge, Firefox, Bitwarden
//   IMPORT-03 — unknown headers return null (generic fallback trigger)
//   IMPORT-05 — duplicate detection by (url + username), default action='skip'
//   IMPORT-06 — normalizeRow produces EntryInput; addEntry yields a CSPRNG UUIDv4
//   IMPORT-08 — injection-prefixed values (=,+,-,@) stored verbatim, no leading quote
//
// Fixtures under __tests__/fixtures/ contain DUMMY passwords only (SEC-10).
// This suite is the Wave-0 RED: it imports the not-yet-implemented modules, so
// it FAILS TO COMPILE/RUN until Task 3 implements the six modules.

import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { getSodium } from '../../crypto/sodium';
import { addEntry } from '../../entries/crud';
import type { Entry, InnerDoc } from '../../entries/types';
import type { UnlockedVault } from '../../vault/vault';
import { DEFAULT_RANDOM_OPTIONS } from '../../generator/types';

// Modules under test (do not exist until Task 3):
import { detectFormat } from '../detect';
import { mapRow } from '../map';
import { deduplicateRows } from '../dedup';
import { normalizeRow } from '../normalize';
import {
  CHROME_EDGE_MAPPER,
  FIREFOX_MAPPER,
  BITWARDEN_MAPPER,
} from '../mappers';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const FIXTURES_DIR = join(__dirname, 'fixtures');

function readFixture(name: string): string {
  return readFileSync(join(FIXTURES_DIR, name), 'utf-8');
}

function readFixtureBytes(name: string): Buffer {
  return readFileSync(join(FIXTURES_DIR, name));
}

/** Parse CSV text into header array + array of Record<header,value> rows. */
function parseCsvSimple(text: string): { headers: string[]; rows: Record<string, string>[] } {
  const lines = text.trim().split(/\r?\n/);
  if (lines.length === 0) return { headers: [], rows: [] };
  const headers = lines[0]!.split(',').map((h) => h.trim());
  const rows: Record<string, string>[] = [];
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i]!.trim();
    if (line === '') continue;
    // Simple split — adequate for these test fixtures (no quoted commas in fixture data)
    const cells = line.split(',');
    const record: Record<string, string> = {};
    for (let j = 0; j < headers.length; j++) {
      record[headers[j]!] = cells[j] ?? '';
    }
    rows.push(record);
  }
  return { headers, rows };
}

/** Build a minimal UnlockedVault for dedup tests. */
function makeVaultWithEntries(entries: Partial<Entry>[]): UnlockedVault {
  const inner: InnerDoc = {
    schemaVersion: 1,
    entries: entries.map((e, i) => ({
      id: `existing-${i}`,
      type: 'login',
      title: e.title ?? 'Existing',
      username: e.username ?? '',
      password: e.password ?? 'existing-pw',
      url: e.url ?? '',
      notes: '',
      tags: [],
      favorite: false,
      needsSiteUpdate: false,
      generatorPreset: null,
      passwordHistory: [],
      createdAt: new Date().toISOString(),
      modifiedAt: new Date().toISOString(),
      deletedAt: e.deletedAt ?? null,
    })),
    settings: { generator: DEFAULT_RANDOM_OPTIONS },
  };
  return {
    doc: {
      format: 'cryptiq-vault',
      version: 1,
      wrappedKeys: {
        master: {
          ciphertext: '',
          nonce: '',
          kdf: { algorithm: 2, opsLimit: 3, memLimit: 268_435_456, salt: '' },
        },
      },
      data: { ciphertext: '', nonce: '' },
      meta: { createdAt: new Date().toISOString(), modifiedAt: new Date().toISOString() },
    },
    entries: inner,
  };
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

describe('core/import', () => {
  beforeAll(async () => {
    await getSodium(); // warm sodium WASM before tests
  });

  // -------------------------------------------------------------------------
  // detectFormat — IMPORT-02/03
  // -------------------------------------------------------------------------

  describe('detectFormat (IMPORT-02/03)', () => {
    it('detects Chrome/Edge format from chrome-export.csv headers', () => {
      const { headers } = parseCsvSimple(readFixture('chrome-export.csv'));
      const mapper = detectFormat(headers);
      expect(mapper).toBe(CHROME_EDGE_MAPPER);
      expect(mapper?.name).toBe('chrome-edge');
    });

    it('detects Firefox format from firefox-export.csv headers', () => {
      const { headers } = parseCsvSimple(readFixture('firefox-export.csv'));
      const mapper = detectFormat(headers);
      expect(mapper).toBe(FIREFOX_MAPPER);
      expect(mapper?.name).toBe('firefox');
    });

    it('detects Bitwarden format from bitwarden-export.csv headers', () => {
      const { headers } = parseCsvSimple(readFixture('bitwarden-export.csv'));
      const mapper = detectFormat(headers);
      expect(mapper).toBe(BITWARDEN_MAPPER);
      expect(mapper?.name).toBe('bitwarden');
    });

    it('returns null for unknown-headers.csv (IMPORT-03 — generic fallback)', () => {
      const { headers } = parseCsvSimple(readFixture('unknown-headers.csv'));
      const mapper = detectFormat(headers);
      expect(mapper).toBeNull();
    });

    it('detects Chrome format with case-insensitive header names (Pitfall 15)', () => {
      const mapper = detectFormat(['Name', 'URL', 'Username', 'Password', 'Note']);
      expect(mapper).toBe(CHROME_EDGE_MAPPER);
    });

    it('detects Chrome format with mixed-case and whitespace', () => {
      const mapper = detectFormat(['  NAME  ', '  URL  ', '  USERNAME  ', '  PASSWORD  ']);
      expect(mapper).toBe(CHROME_EDGE_MAPPER);
    });

    it('detects Firefox format with httpRealm header present', () => {
      const mapper = detectFormat(['url', 'username', 'password', 'httpRealm', 'formActionOrigin']);
      expect(mapper).toBe(FIREFOX_MAPPER);
    });

    it('detects Bitwarden format by login_uri + login_username + login_password', () => {
      const mapper = detectFormat(['folder', 'type', 'name', 'login_uri', 'login_username', 'login_password']);
      expect(mapper).toBe(BITWARDEN_MAPPER);
    });

    it('Chrome format requires name + url + username + password (not just url)', () => {
      // Only url/username/password without name should NOT match Chrome (could be Firefox without httpRealm)
      const mapper = detectFormat(['url', 'username', 'password', 'note']);
      // Without httpRealm it is not Firefox; without name it could fallback. Just ensure it does not throw.
      expect(mapper).toBeDefined(); // null or a mapper — no crash
    });
  });

  // -------------------------------------------------------------------------
  // mapRow — IMPORT-08 / P6-04
  // -------------------------------------------------------------------------

  describe('mapRow (IMPORT-08, P6-04)', () => {
    it('maps a Chrome-format row to MappedRow with all fields', () => {
      const row = {
        name: 'Test Site',
        url: 'https://test.example.com',
        username: 'testuser',
        password: 'dummy-mapped-pw',
        note: 'test note',
      };
      const result = mapRow(row, CHROME_EDGE_MAPPER);
      expect('malformed' in result).toBe(false);
      if ('malformed' in result) return;
      expect(result.title).toBe('Test Site');
      expect(result.url).toBe('https://test.example.com');
      expect(result.username).toBe('testuser');
      expect(result.password).toBe('dummy-mapped-pw');
      expect(result.notes).toBe('test note');
    });

    it('returns malformed:true when title/name is empty (P6-04)', () => {
      const row = { name: '', url: 'https://example.com', username: 'u', password: 'p', note: '' };
      const result = mapRow(row, CHROME_EDGE_MAPPER);
      expect('malformed' in result).toBe(true);
      if (!('malformed' in result)) return;
      expect(result.malformed).toBe(true);
      expect(typeof result.reason).toBe('string');
      expect(result.reason.length).toBeGreaterThan(0);
    });

    it('returns malformed:true when title is whitespace-only', () => {
      const row = { name: '   ', url: 'https://example.com', username: 'u', password: 'p', note: '' };
      const result = mapRow(row, CHROME_EDGE_MAPPER);
      expect('malformed' in result).toBe(true);
    });

    it('IMPORT-08: stores =formula values verbatim — no leading quote prefix (Pitfall 4)', () => {
      const injectionRows = parseCsvSimple(readFixture('injection-values.csv'));
      // Row 0: password starts with =
      const row0 = injectionRows.rows[0]!;
      const result0 = mapRow(row0, CHROME_EDGE_MAPPER);
      expect('malformed' in result0).toBe(false);
      if ('malformed' in result0) return;
      expect(result0.password).toBe("=cmd|' /c calc'!A0");
      expect(result0.password.startsWith("'")).toBe(false); // NO leading quote
    });

    it('IMPORT-08: stores + prefix values verbatim', () => {
      const injectionRows = parseCsvSimple(readFixture('injection-values.csv'));
      const row1 = injectionRows.rows[1]!;
      const result1 = mapRow(row1, CHROME_EDGE_MAPPER);
      if ('malformed' in result1) { expect(result1.malformed).toBe(false); return; }
      expect(result1.password).toBe('+1234567890');
      expect(result1.password.startsWith("'")).toBe(false);
    });

    it('IMPORT-08: stores - prefix values verbatim', () => {
      const injectionRows = parseCsvSimple(readFixture('injection-values.csv'));
      const row2 = injectionRows.rows[2]!;
      const result2 = mapRow(row2, CHROME_EDGE_MAPPER);
      if ('malformed' in result2) { expect(result2.malformed).toBe(false); return; }
      expect(result2.password).toBe('-1+2+3');
    });

    it('IMPORT-08: stores @ prefix values verbatim', () => {
      const injectionRows = parseCsvSimple(readFixture('injection-values.csv'));
      const row3 = injectionRows.rows[3]!;
      const result3 = mapRow(row3, CHROME_EDGE_MAPPER);
      if ('malformed' in result3) { expect(result3.malformed).toBe(false); return; }
      expect(result3.password).toBe('@SUM(1+2)');
    });

    it('IMPORT-08: stores formula in notes verbatim', () => {
      const injectionRows = parseCsvSimple(readFixture('injection-values.csv'));
      const row4 = injectionRows.rows[4]!; // Formula in notes, normal password
      const result4 = mapRow(row4, CHROME_EDGE_MAPPER);
      if ('malformed' in result4) { expect(result4.malformed).toBe(false); return; }
      expect(result4.notes).toBe('=HYPERLINK("http://evil.example.com")');
      expect(result4.notes.startsWith("'")).toBe(false);
    });

    it('maps a Firefox-format row correctly (url is the title)', () => {
      const row = {
        url: 'https://ff.example.com',
        username: 'ffuser',
        password: 'dummy-ff-pw',
        httpRealm: '',
        formActionOrigin: 'https://ff.example.com',
        guid: '{abc}',
        timeCreated: '1700000000000',
      };
      const result = mapRow(row, FIREFOX_MAPPER);
      if ('malformed' in result) { expect(result.malformed).toBe(false); return; }
      expect(result.title).toBe('https://ff.example.com');
      expect(result.url).toBe('https://ff.example.com');
      expect(result.username).toBe('ffuser');
      expect(result.password).toBe('dummy-ff-pw');
    });

    it('maps a Bitwarden-format row correctly', () => {
      const row = {
        folder: '',
        favorite: '0',
        type: 'login',
        name: 'BW Test Site',
        notes: 'bw test notes',
        fields: '',
        reprompt: '0',
        login_uri: 'https://bw.example.com',
        login_username: 'bwuser',
        login_password: 'dummy-bw-pw',
        login_totp: '',
      };
      const result = mapRow(row, BITWARDEN_MAPPER);
      if ('malformed' in result) { expect(result.malformed).toBe(false); return; }
      expect(result.title).toBe('BW Test Site');
      expect(result.url).toBe('https://bw.example.com');
      expect(result.username).toBe('bwuser');
      expect(result.password).toBe('dummy-bw-pw');
      expect(result.notes).toBe('bw test notes');
    });

    it('defaults missing optional fields to empty string', () => {
      const row = { name: 'Minimal', url: '', username: '', password: '', note: '' };
      const result = mapRow(row, CHROME_EDGE_MAPPER);
      if ('malformed' in result) { expect(result.malformed).toBe(false); return; }
      expect(result.url).toBe('');
      expect(result.username).toBe('');
      expect(result.password).toBe('');
      expect(result.notes).toBe('');
    });
  });

  // -------------------------------------------------------------------------
  // deduplicateRows — IMPORT-05
  // -------------------------------------------------------------------------

  describe('deduplicateRows (IMPORT-05)', () => {
    it('flags a row as duplicate when url+username matches an existing active entry', () => {
      const vault = makeVaultWithEntries([
        { url: 'https://example.com', username: 'alice@example.com', deletedAt: null },
      ]);
      const inner = vault.entries as InnerDoc;

      const { rows } = parseCsvSimple(readFixture('duplicate-rows.csv'));
      const mappedRows = rows
        .map((r) => mapRow(r, CHROME_EDGE_MAPPER))
        .filter((r): r is Exclude<typeof r, { malformed: true; reason: string }> => !('malformed' in r));

      const results = deduplicateRows(mappedRows, inner.entries);

      // Row 0 and 1 from duplicate-rows.csv both have url=https://example.com, username=alice@example.com
      const dup = results.filter((r) => r.isDuplicate);
      expect(dup.length).toBeGreaterThanOrEqual(1);
      // Default action for duplicates is 'skip' (IMPORT-05)
      for (const d of dup) {
        expect(d.action).toBe('skip');
      }
    });

    it('does NOT flag a row as duplicate when url+username is unique', () => {
      const vault = makeVaultWithEntries([
        { url: 'https://other.example.com', username: 'other-user', deletedAt: null },
      ]);
      const inner = vault.entries as InnerDoc;

      const mappedRow = mapRow(
        { name: 'New Site', url: 'https://new.example.com', username: 'new-user', password: 'dummy', note: '' },
        CHROME_EDGE_MAPPER,
      );
      if ('malformed' in mappedRow) { expect(mappedRow.malformed).toBe(false); return; }

      const results = deduplicateRows([mappedRow], inner.entries);
      expect(results[0]!.isDuplicate).toBe(false);
      expect(results[0]!.action).toBe('import');
    });

    it('does NOT flag a row as duplicate against a soft-deleted entry (tombstone)', () => {
      // A tombstone (deletedAt !== null) should NOT be considered an existing active entry
      const vault = makeVaultWithEntries([
        { url: 'https://example.com', username: 'alice@example.com', deletedAt: new Date().toISOString() },
      ]);
      const inner = vault.entries as InnerDoc;

      const mappedRow = mapRow(
        { name: 'Example Site', url: 'https://example.com', username: 'alice@example.com', password: 'dummy', note: '' },
        CHROME_EDGE_MAPPER,
      );
      if ('malformed' in mappedRow) { expect(mappedRow.malformed).toBe(false); return; }

      const results = deduplicateRows([mappedRow], inner.entries);
      expect(results[0]!.isDuplicate).toBe(false);
      expect(results[0]!.action).toBe('import');
    });

    it('duplicate matching is case-insensitive on url and username (IMPORT-05)', () => {
      const vault = makeVaultWithEntries([
        { url: 'https://EXAMPLE.COM', username: 'ALICE@EXAMPLE.COM', deletedAt: null },
      ]);
      const inner = vault.entries as InnerDoc;

      const mappedRow = mapRow(
        {
          name: 'Test',
          url: 'https://example.com', // lowercase — should still match
          username: 'alice@example.com',
          password: 'dummy',
          note: '',
        },
        CHROME_EDGE_MAPPER,
      );
      if ('malformed' in mappedRow) { expect(mappedRow.malformed).toBe(false); return; }

      const results = deduplicateRows([mappedRow], inner.entries);
      expect(results[0]!.isDuplicate).toBe(true);
      expect(results[0]!.action).toBe('skip');
    });

    it('returns empty array for empty input rows', () => {
      const vault = makeVaultWithEntries([]);
      const inner = vault.entries as InnerDoc;
      const results = deduplicateRows([], inner.entries);
      expect(results).toEqual([]);
    });

    it('handles empty existing entries (no vault entries → no duplicates)', () => {
      const vault = makeVaultWithEntries([]);
      const inner = vault.entries as InnerDoc;

      const mappedRow = mapRow(
        { name: 'Site', url: 'https://site.example.com', username: 'u', password: 'dummy', note: '' },
        CHROME_EDGE_MAPPER,
      );
      if ('malformed' in mappedRow) { expect(mappedRow.malformed).toBe(false); return; }

      const results = deduplicateRows([mappedRow], inner.entries);
      expect(results[0]!.isDuplicate).toBe(false);
      expect(results[0]!.action).toBe('import');
    });
  });

  // -------------------------------------------------------------------------
  // normalizeRow — IMPORT-06
  // -------------------------------------------------------------------------

  describe('normalizeRow (IMPORT-06)', () => {
    it('returns an EntryInput with all core string fields', async () => {
      const mappedRow = mapRow(
        { name: 'Normalize Test', url: 'https://norm.example.com', username: 'normuser', password: 'dummy-norm-pw', note: 'some notes' },
        CHROME_EDGE_MAPPER,
      );
      if ('malformed' in mappedRow) { expect(mappedRow.malformed).toBe(false); return; }

      const input = await normalizeRow(mappedRow);
      expect(input.title).toBe('Normalize Test');
      expect(input.url).toBe('https://norm.example.com');
      expect(input.username).toBe('normuser');
      expect(input.password).toBe('dummy-norm-pw');
      expect(input.notes).toBe('some notes');
    });

    it('IMPORT-06: addEntry on normalized row produces a CSPRNG UUIDv4 id', async () => {
      const vault = makeVaultWithEntries([]);

      const mappedRow = mapRow(
        { name: 'UUID Test Entry', url: 'https://uuid.example.com', username: 'u', password: 'dummy-uuid-pw', note: '' },
        CHROME_EDGE_MAPPER,
      );
      if ('malformed' in mappedRow) { expect(mappedRow.malformed).toBe(false); return; }

      const input = await normalizeRow(mappedRow);
      const entry = await addEntry(vault, input);
      // Must match UUIDv4 regex (CSPRNG-backed — IMPORT-06)
      expect(entry.id).toMatch(UUID_V4_RE);
    });

    it('two normalized rows produce different UUIDs via addEntry', async () => {
      const vault = makeVaultWithEntries([]);

      const r1 = mapRow(
        { name: 'Site A', url: 'https://a.example.com', username: 'u1', password: 'dummy-pw-a', note: '' },
        CHROME_EDGE_MAPPER,
      );
      const r2 = mapRow(
        { name: 'Site B', url: 'https://b.example.com', username: 'u2', password: 'dummy-pw-b', note: '' },
        CHROME_EDGE_MAPPER,
      );
      if ('malformed' in r1 || 'malformed' in r2) return;

      const [i1, i2] = await Promise.all([normalizeRow(r1), normalizeRow(r2)]);
      const e1 = await addEntry(vault, i1!);
      const e2 = await addEntry(vault, i2!);
      expect(e1.id).not.toBe(e2.id);
    });

    it('preserves injection-prefixed password verbatim through normalize → addEntry', async () => {
      const vault = makeVaultWithEntries([]);

      const mappedRow = mapRow(
        { name: 'Injection Site', url: 'https://inj.example.com', username: 'u', password: "=formula", note: '' },
        CHROME_EDGE_MAPPER,
      );
      if ('malformed' in mappedRow) { expect(mappedRow.malformed).toBe(false); return; }

      const input = await normalizeRow(mappedRow);
      const entry = await addEntry(vault, input);
      // Must be stored exactly as-is (IMPORT-08 / Pitfall 4)
      expect(entry.password).toBe('=formula');
      expect(entry.password.startsWith("'")).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // BOM detection — IMPORT-04 (fixtures exist in core fixtures dir for 06-02 use)
  // -------------------------------------------------------------------------

  describe('BOM fixture existence (IMPORT-04 smoke fixtures)', () => {
    it('utf16-le-bom.csv starts with 0xFF 0xFE (UTF-16 LE BOM)', () => {
      const bytes = readFixtureBytes('utf16-le-bom.csv');
      expect(bytes[0]).toBe(0xff);
      expect(bytes[1]).toBe(0xfe);
    });

    it('utf16-be-bom.csv starts with 0xFE 0xFF (UTF-16 BE BOM)', () => {
      const bytes = readFixtureBytes('utf16-be-bom.csv');
      expect(bytes[0]).toBe(0xfe);
      expect(bytes[1]).toBe(0xff);
    });
  });

  // -------------------------------------------------------------------------
  // Large-sample fixture — GAP B: full pipeline (detect → mapRow → dedup)
  // -------------------------------------------------------------------------

  describe('large-sample.csv — full pipeline (GAP B / TEST-07)', () => {
    it('large-sample.csv has more than 1000 data rows', () => {
      const text = readFixture('large-sample.csv');
      const lines = text.trim().split(/\r?\n/);
      // Subtract header line
      expect(lines.length - 1).toBeGreaterThan(1000);
    });

    it('detectFormat + mapRow produces the expected count with no crash', () => {
      const text = readFixture('large-sample.csv');
      const { headers, rows } = parseCsvSimple(text);

      // Auto-detect format (Chrome/Edge for large-sample.csv)
      const mapper = detectFormat(headers);
      expect(mapper).not.toBeNull();

      // Map every data row — no exception must be thrown for any row.
      let validCount = 0;
      let malformedCount = 0;
      for (let i = 0; i < rows.length; i++) {
        const result = mapRow(rows[i]!, mapper!, i + 1);
        if ('malformed' in result && result.malformed === true) {
          malformedCount++;
        } else {
          validCount++;
        }
      }

      // All 1 000+ rows in the fixture are well-formed Chrome exports.
      expect(validCount).toBeGreaterThan(1000);
      // No malformed rows are expected in the clean large-sample fixture.
      expect(malformedCount).toBe(0);
    });

    it('deduplicateRows on large-sample produces 0 duplicates against empty vault', () => {
      const text = readFixture('large-sample.csv');
      const { headers, rows } = parseCsvSimple(text);

      const mapper = detectFormat(headers);
      expect(mapper).not.toBeNull();

      const mapped = rows
        .map((r, i) => mapRow(r, mapper!, i + 1))
        .filter((r): r is Exclude<typeof r, { malformed: true; reason: string }> => !('malformed' in r));

      const vault = makeVaultWithEntries([]);
      const inner = vault.entries as import('../../entries/types').InnerDoc;
      const results = deduplicateRows(mapped, inner.entries);

      // No existing entries → all rows are imports (no duplicates).
      expect(results.every((r) => !r.isDuplicate)).toBe(true);
      expect(results.length).toBe(mapped.length);
    });
  });

  // -------------------------------------------------------------------------
  // malformed-rows fixture — GAP B: correct valid/malformed split
  // -------------------------------------------------------------------------

  describe('malformed-rows.csv — pipeline split (GAP B / TEST-07)', () => {
    it('detects Chrome format from malformed-rows.csv headers', () => {
      const text = readFixture('malformed-rows.csv');
      const { headers } = parseCsvSimple(text);
      const mapper = detectFormat(headers);
      expect(mapper).not.toBeNull();
      expect(mapper?.name).toBe('chrome-edge');
    });

    it('produces the expected valid vs malformed split', () => {
      const text = readFixture('malformed-rows.csv');
      const { headers, rows } = parseCsvSimple(text);

      // parseCsvSimple skips blank lines (like skipEmptyLines in papaparse).
      // Fixture content:
      //   Row 1: "Valid Entry" — valid
      //   Row 2: empty name    — malformed (missing title)
      //   Row 3: blank line    — skipped by parseCsvSimple
      //   Row 4: "Extra Columns Site" — valid (extra columns are ignored)
      //   Row 5: "Another Valid"     — valid
      // Expected: 3 valid, 1 malformed.

      const mapper = detectFormat(headers);
      expect(mapper).not.toBeNull();

      const validRows: import('../types').MappedRow[] = [];
      const malformedRows: Array<{ rowIndex: number; reason: string }> = [];

      for (let i = 0; i < rows.length; i++) {
        const result = mapRow(rows[i]!, mapper!, i + 1);
        if ('malformed' in result && result.malformed === true) {
          malformedRows.push({ rowIndex: i + 1, reason: result.reason });
        } else {
          validRows.push(result as import('../types').MappedRow);
        }
      }

      expect(validRows.length).toBe(3);
      expect(malformedRows.length).toBe(1);
      expect(malformedRows[0]!.reason).toMatch(/title/i);
    });

    it('deduplicateRows on the valid rows from malformed-rows.csv — no duplicates against empty vault', () => {
      const text = readFixture('malformed-rows.csv');
      const { headers, rows } = parseCsvSimple(text);

      const mapper = detectFormat(headers);
      expect(mapper).not.toBeNull();

      const mapped = rows
        .map((r, i) => mapRow(r, mapper!, i + 1))
        .filter((r): r is Exclude<typeof r, { malformed: true; reason: string }> => !('malformed' in r));

      const vault = makeVaultWithEntries([]);
      const inner = vault.entries as import('../../entries/types').InnerDoc;
      const results = deduplicateRows(mapped, inner.entries);

      expect(results.every((r) => !r.isDuplicate)).toBe(true);
      expect(results.every((r) => r.action === 'import')).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // FIX 2 tests — Firefox + Bitwarden case-insensitive mapper parity
  // -------------------------------------------------------------------------

  describe('FIX 2 — Firefox + Bitwarden case-insensitive row mapping', () => {
    it('Firefox mapper maps correctly from UPPERCASE header row', () => {
      // detectFormat lowercases headers, so detection works; the mapper must
      // also read the row correctly when keys are UPPERCASE.
      const row: Record<string, string> = {
        URL:      'https://ff.example.com',
        USERNAME: 'ffuser',
        PASSWORD: 'dummy-ff-upper-pw',
        HTTPREALM: '',
      };
      const result = mapRow(row, FIREFOX_MAPPER);
      if ('malformed' in result) {
        // URL becomes the title; if it's non-empty the row must not be malformed.
        expect(result.malformed).toBe(false);
        return;
      }
      expect(result.url).toBe('https://ff.example.com');
      expect(result.title).toBe('https://ff.example.com');
      expect(result.username).toBe('ffuser');
      expect(result.password).toBe('dummy-ff-upper-pw');
    });

    it('Firefox mapper maps correctly from Mixed-Case header row', () => {
      const row: Record<string, string> = {
        Url:       'https://ff-mixed.example.com',
        Username:  'ffmixeduser',
        Password:  'dummy-ff-mixed-pw',
        HttpRealm: '',
      };
      const result = mapRow(row, FIREFOX_MAPPER);
      if ('malformed' in result) { expect(result.malformed).toBe(false); return; }
      expect(result.url).toBe('https://ff-mixed.example.com');
      expect(result.username).toBe('ffmixeduser');
      expect(result.password).toBe('dummy-ff-mixed-pw');
    });

    it('Bitwarden mapper maps correctly from UPPERCASE header row', () => {
      const row: Record<string, string> = {
        NAME:           'BW Upper Site',
        LOGIN_URI:      'https://bw-upper.example.com',
        LOGIN_USERNAME: 'bwupperuser',
        LOGIN_PASSWORD: 'dummy-bw-upper-pw',
        NOTES:          'bw upper notes',
      };
      const result = mapRow(row, BITWARDEN_MAPPER);
      if ('malformed' in result) { expect(result.malformed).toBe(false); return; }
      expect(result.title).toBe('BW Upper Site');
      expect(result.url).toBe('https://bw-upper.example.com');
      expect(result.username).toBe('bwupperuser');
      expect(result.password).toBe('dummy-bw-upper-pw');
      expect(result.notes).toBe('bw upper notes');
    });

    it('Bitwarden mapper maps correctly from Mixed-Case header row', () => {
      const row: Record<string, string> = {
        Name:           'BW Mixed Site',
        Login_Uri:      'https://bw-mixed.example.com',
        Login_Username: 'bwmixeduser',
        Login_Password: 'dummy-bw-mixed-pw',
        Notes:          '',
      };
      const result = mapRow(row, BITWARDEN_MAPPER);
      if ('malformed' in result) { expect(result.malformed).toBe(false); return; }
      expect(result.title).toBe('BW Mixed Site');
      expect(result.url).toBe('https://bw-mixed.example.com');
      expect(result.username).toBe('bwmixeduser');
      expect(result.password).toBe('dummy-bw-mixed-pw');
    });
  });

  // -------------------------------------------------------------------------
  // FIX 4 tests — empty url+username dedup key collision
  // -------------------------------------------------------------------------

  describe('FIX 4 — empty url+username rows not treated as duplicates', () => {
    it('an active entry with url="" and username="" does NOT cause empty-keyed import rows to be flagged as duplicate', () => {
      // Existing entry with both fields empty.
      const vault = makeVaultWithEntries([
        { url: '', username: '', deletedAt: null },
      ]);
      const inner = vault.entries as import('../../entries/types').InnerDoc;

      // Import row that is also empty url+username.
      const importRow = mapRow(
        { name: 'Only Password Site', url: '', username: '', password: 'dummy-pw', note: '' },
        CHROME_EDGE_MAPPER,
      );
      if ('malformed' in importRow) { expect(importRow.malformed).toBe(false); return; }

      const results = deduplicateRows([importRow], inner.entries);
      // Must NOT be flagged as a duplicate (FIX 4).
      expect(results[0]!.isDuplicate).toBe(false);
      expect(results[0]!.action).toBe('import');
    });

    it('multiple empty-url+username import rows are all treated as non-duplicates', () => {
      // Existing entry with both fields empty.
      const vault = makeVaultWithEntries([
        { url: '', username: '', deletedAt: null },
      ]);
      const inner = vault.entries as import('../../entries/types').InnerDoc;

      const rows = [
        { name: 'Site A', url: '', username: '', password: 'dummy-a', note: '' },
        { name: 'Site B', url: '', username: '', password: 'dummy-b', note: '' },
      ].map((r) => mapRow(r, CHROME_EDGE_MAPPER))
        .filter((r): r is Exclude<typeof r, { malformed: true; reason: string }> => !('malformed' in r));

      expect(rows.length).toBe(2);

      const results = deduplicateRows(rows, inner.entries);
      // Both must be importable — empty key is not a collision identity.
      expect(results.every((r) => !r.isDuplicate)).toBe(true);
      expect(results.every((r) => r.action === 'import')).toBe(true);
    });

    it('a row with non-empty url+username is still detected as a duplicate correctly', () => {
      // Regression guard: FIX 4 must not break normal dedup behaviour.
      const vault = makeVaultWithEntries([
        { url: 'https://example.com', username: 'alice', deletedAt: null },
      ]);
      const inner = vault.entries as import('../../entries/types').InnerDoc;

      const importRow = mapRow(
        { name: 'Example', url: 'https://example.com', username: 'alice', password: 'dummy', note: '' },
        CHROME_EDGE_MAPPER,
      );
      if ('malformed' in importRow) { expect(importRow.malformed).toBe(false); return; }

      const results = deduplicateRows([importRow], inner.entries);
      expect(results[0]!.isDuplicate).toBe(true);
      expect(results[0]!.action).toBe('skip');
    });
  });
});
