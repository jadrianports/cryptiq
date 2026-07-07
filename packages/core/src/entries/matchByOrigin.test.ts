// packages/core/src/entries/matchByOrigin.test.ts
//
// matchByOrigin behavioral/ordering/no-password tests (FILL-03, BRIDGE-08,
// 16-CONTEXT.md D-01/D-02/D-03/D-05/D-06/D-08).
//
// Phase 19 Plan 01: matchByOrigin's return shape changed from a bare
// EntryMatchMetadata[] to { registrableDomain, candidates } (Pattern 2) — every
// assertion below reads `.candidates`, and dedicated cases pin
// registrableDomain's unconditional presence (CAP-01/CAP-04).

import { describe, it, expect } from 'vitest';
import type { Entry } from './types';
import { matchByOrigin } from './matchByOrigin';

let idCounter = 0;

/** Minimal Entry fixture builder — only fields matchByOrigin/ordering care about vary. */
function makeEntry(overrides: Partial<Entry> = {}): Entry {
  idCounter += 1;
  return {
    id: `entry-${idCounter}`,
    type: 'login',
    title: `Entry ${idCounter}`,
    username: `user${idCounter}`,
    password: `super-secret-${idCounter}`,
    url: 'example.com',
    notes: '',
    tags: [],
    favorite: false,
    needsSiteUpdate: false,
    generatorPreset: null,
    passwordHistory: [],
    createdAt: '2026-01-01T00:00:00.000Z',
    modifiedAt: '2026-01-01T00:00:00.000Z',
    deletedAt: null,
    ...overrides,
  };
}

describe('entries/matchByOrigin — origin-based metadata matcher (FILL-03, BRIDGE-08)', () => {
  it('matches a subdomain page origin against an entry stored with the bare base domain (D-01)', () => {
    const entries = [makeEntry({ url: 'example.com' })];
    const result = matchByOrigin(entries, 'https://accounts.example.com/login');
    expect(result.candidates).toHaveLength(1);
    expect(result.candidates[0]!.id).toBe(entries[0]!.id);
  });

  it('matches a www-prefixed entry url against a bare page origin (D-01)', () => {
    const entries = [makeEntry({ url: 'www.example.com' })];
    const result = matchByOrigin(entries, 'https://example.com');
    expect(result.candidates).toHaveLength(1);
  });

  it('returns an empty candidate set for a non-registrable page origin (D-03 fail closed)', () => {
    const entries = [makeEntry({ url: 'example.com' })];
    expect(matchByOrigin(entries, 'http://192.168.1.1').candidates).toEqual([]);
    expect(matchByOrigin(entries, 'http://localhost:5173').candidates).toEqual([]);
    expect(matchByOrigin(entries, '').candidates).toEqual([]);
  });

  it('excludes soft-deleted entries from match candidates', () => {
    const entries = [makeEntry({ url: 'example.com', deletedAt: '2026-02-01T00:00:00.000Z' })];
    expect(matchByOrigin(entries, 'https://example.com').candidates).toEqual([]);
  });

  it('skips an entry whose url is empty or unparseable (D-02)', () => {
    const entries = [
      makeEntry({ url: '' }),
      makeEntry({ url: 'not a url at all' }),
      makeEntry({ url: 'example.com' }), // the only real match
    ];
    const result = matchByOrigin(entries, 'https://example.com');
    expect(result.candidates).toHaveLength(1);
    expect(result.candidates[0]!.id).toBe(entries[2]!.id);
  });

  it('orders favorites first, then modifiedAt descending within each group (D-08)', () => {
    const older = makeEntry({
      url: 'example.com',
      favorite: false,
      modifiedAt: '2026-01-01T00:00:00.000Z',
      title: 'older-non-favorite',
    });
    const newer = makeEntry({
      url: 'example.com',
      favorite: false,
      modifiedAt: '2026-03-01T00:00:00.000Z',
      title: 'newer-non-favorite',
    });
    const favoriteOld = makeEntry({
      url: 'example.com',
      favorite: true,
      modifiedAt: '2025-06-01T00:00:00.000Z',
      title: 'favorite-old',
    });

    const result = matchByOrigin([older, newer, favoriteOld], 'https://example.com');

    expect(result.candidates.map((r) => r.title)).toEqual([
      'favorite-old',
      'newer-non-favorite',
      'older-non-favorite',
    ]);
  });

  it('returns metadata with id/title/username/domainHint and structurally no password field (SC-1/BRIDGE-08)', () => {
    const entries = [makeEntry({ url: 'example.com', title: 'Example', username: 'alice' })];
    const result = matchByOrigin(entries, 'https://example.com');
    expect(result.candidates).toHaveLength(1);
    const match = result.candidates[0]!;
    expect(match).toEqual({
      id: entries[0]!.id,
      title: 'Example',
      username: 'alice',
      domainHint: 'example.com',
    });
    expect(Object.keys(match)).not.toContain('password');
    expect('password' in match).toBe(false);
  });

  // ---------------------------------------------------------------------------
  // Phase 19 Plan 01 (Pattern 2): registrableDomain, unconditional presence
  // ---------------------------------------------------------------------------

  it('returns the registrableDomain for a matching origin', () => {
    const entries = [makeEntry({ url: 'example.com' })];
    const result = matchByOrigin(entries, 'https://accounts.example.com/login');
    expect(result.registrableDomain).toBe('example.com');
  });

  it('returns the registrableDomain even when there are zero candidates for a registrable origin (CAP-01/CAP-04)', () => {
    const entries: Entry[] = [];
    const result = matchByOrigin(entries, 'https://brand-new-site.com');
    expect(result.registrableDomain).toBe('brand-new-site.com');
    expect(result.candidates).toEqual([]);
  });

  it('returns registrableDomain: null and candidates: [] for a non-registrable origin', () => {
    const entries = [makeEntry({ url: 'example.com' })];
    expect(matchByOrigin(entries, 'http://192.168.1.1')).toEqual({
      registrableDomain: null,
      candidates: [],
    });
    expect(matchByOrigin(entries, 'http://localhost:5173')).toEqual({
      registrableDomain: null,
      candidates: [],
    });
    expect(matchByOrigin(entries, '')).toEqual({ registrableDomain: null, candidates: [] });
  });

  // ---------------------------------------------------------------------------
  // Phase 21 (URLS-02, D-10/D-11): equivalentUrls OR + typosquat rejection
  // ---------------------------------------------------------------------------

  it('matches a page origin via an equivalentUrls entry when the primary url differs (D-10)', () => {
    const entries = [makeEntry({ url: 'example.com', equivalentUrls: ['other-brand.com'] })];
    const result = matchByOrigin(entries, 'https://other-brand.com');
    expect(result.candidates).toHaveLength(1);
    expect(result.candidates[0]!.id).toBe(entries[0]!.id);
  });

  it('still matches the same entry via its primary url (equivalentUrls is additive, not a replacement) (D-10)', () => {
    const entries = [makeEntry({ url: 'example.com', equivalentUrls: ['other-brand.com'] })];
    const result = matchByOrigin(entries, 'https://example.com');
    expect(result.candidates).toHaveLength(1);
    expect(result.candidates[0]!.id).toBe(entries[0]!.id);
  });

  it('does NOT match a typosquat equivalentUrls entry against the real target domain (D-11)', () => {
    const entries = [makeEntry({ url: 'my-own-site.com', equivalentUrls: ['gooogle.com'] })];
    expect(matchByOrigin(entries, 'https://google.com').candidates).toEqual([]);
  });

  it('does NOT match a cousin-domain equivalentUrls entry against the real target domain (D-11, proves no substring)', () => {
    const entries = [
      makeEntry({ url: 'my-own-site.com', equivalentUrls: ['evil-google.com.attacker.net'] }),
    ];
    expect(matchByOrigin(entries, 'https://google.com').candidates).toEqual([]);
  });

  it('behaves exactly as before for an entry with no equivalentUrls field (regression guard for ?? [])', () => {
    const entries = [makeEntry({ url: 'example.com' })];
    const result = matchByOrigin(entries, 'https://example.com');
    expect(result.candidates).toHaveLength(1);
    expect(result.candidates[0]!.id).toBe(entries[0]!.id);
  });

  // ---------------------------------------------------------------------------
  // Phase 23 Task 3 (D-13/SC-5): secure-note exclusion guard
  // ---------------------------------------------------------------------------

  it('excludes a secure-note entry from match candidates even with a matching url (D-13/SC-5)', () => {
    const entries = [makeEntry({ url: 'example.com', type: 'secure-note' })];
    const result = matchByOrigin(entries, 'https://example.com');
    expect(result.candidates).toEqual([]);
  });

  it('still returns a matching login entry as a candidate (regression guard)', () => {
    const entries = [makeEntry({ url: 'example.com', type: 'login' })];
    const result = matchByOrigin(entries, 'https://example.com');
    expect(result.candidates).toHaveLength(1);
  });
});
