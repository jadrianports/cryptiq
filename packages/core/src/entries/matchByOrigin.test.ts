// packages/core/src/entries/matchByOrigin.test.ts
//
// matchByOrigin behavioral/ordering/no-password tests (FILL-03, BRIDGE-08,
// 16-CONTEXT.md D-01/D-02/D-03/D-05/D-06/D-08).

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
    const results = matchByOrigin(entries, 'https://accounts.example.com/login');
    expect(results).toHaveLength(1);
    expect(results[0]!.id).toBe(entries[0]!.id);
  });

  it('matches a www-prefixed entry url against a bare page origin (D-01)', () => {
    const entries = [makeEntry({ url: 'www.example.com' })];
    const results = matchByOrigin(entries, 'https://example.com');
    expect(results).toHaveLength(1);
  });

  it('returns an empty set for a non-registrable page origin (D-03 fail closed)', () => {
    const entries = [makeEntry({ url: 'example.com' })];
    expect(matchByOrigin(entries, 'http://192.168.1.1')).toEqual([]);
    expect(matchByOrigin(entries, 'http://localhost:5173')).toEqual([]);
    expect(matchByOrigin(entries, '')).toEqual([]);
  });

  it('excludes soft-deleted entries from match candidates', () => {
    const entries = [makeEntry({ url: 'example.com', deletedAt: '2026-02-01T00:00:00.000Z' })];
    expect(matchByOrigin(entries, 'https://example.com')).toEqual([]);
  });

  it('skips an entry whose url is empty or unparseable (D-02)', () => {
    const entries = [
      makeEntry({ url: '' }),
      makeEntry({ url: 'not a url at all' }),
      makeEntry({ url: 'example.com' }), // the only real match
    ];
    const results = matchByOrigin(entries, 'https://example.com');
    expect(results).toHaveLength(1);
    expect(results[0]!.id).toBe(entries[2]!.id);
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

    const results = matchByOrigin([older, newer, favoriteOld], 'https://example.com');

    expect(results.map((r) => r.title)).toEqual(['favorite-old', 'newer-non-favorite', 'older-non-favorite']);
  });

  it('returns metadata with id/title/username/domainHint and structurally no password field (SC-1/BRIDGE-08)', () => {
    const entries = [makeEntry({ url: 'example.com', title: 'Example', username: 'alice' })];
    const results = matchByOrigin(entries, 'https://example.com');
    expect(results).toHaveLength(1);
    const match = results[0]!;
    expect(match).toEqual({
      id: entries[0]!.id,
      title: 'Example',
      username: 'alice',
      domainHint: 'example.com',
    });
    expect(Object.keys(match)).not.toContain('password');
    expect('password' in match).toBe(false);
  });
});
