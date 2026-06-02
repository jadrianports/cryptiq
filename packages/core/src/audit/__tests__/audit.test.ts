// packages/core/src/audit/__tests__/audit.test.ts
//
// TEST-06 — Health audit engine suite.
//
// Requirements covered:
//   AUDIT-01 — runAudit is pure (no network, no zxcvbn import in core)
//   AUDIT-02 — Reused: entries sharing the same non-empty password both appear in `reused`
//   AUDIT-03 — Weak: entries with injected zxcvbn score ≤ 2 appear in `weak`
//               (core never calls zxcvbn — weakScores Map is hand-built here)
//   AUDIT-04 — Stale: entries whose derivePasswordAge > staleThresholdDays * 24*60*60*1000
//   AUDIT-05 — NeedsUpdate: entries with needsSiteUpdate === true appear in `needsUpdate`
//   TEST-06  — All four categories + tombstone exclusion
//
// IMPORTANT: weakScores is ALWAYS a hand-constructed Map in this suite.
// Never import or call zxcvbn here — that would break core purity.

import { describe, it, expect, beforeAll } from 'vitest';
import type { Entry } from '../../entries/types';
import { getSodium } from '../../crypto/sodium';
import { runAudit } from '../audit';

// ---------------------------------------------------------------------------
// Minimal entry builder
// ---------------------------------------------------------------------------

let _idCounter = 0;

/**
 * Build a minimal active Entry with overrides. Uses a simple counter for IDs
 * (no CSPRNG needed in test fixtures — IDs only need to be unique and stable).
 */
function makeEntry(overrides: Partial<Entry> = {}): Entry {
  const id = `test-entry-${++_idCounter}`;
  const now = new Date().toISOString();
  return {
    id,
    type: 'login',
    title: `Entry ${id}`,
    username: 'user',
    password: 'unique-password',
    url: 'https://example.com',
    notes: '',
    tags: [],
    favorite: false,
    needsSiteUpdate: false,
    generatorPreset: null,
    passwordHistory: [],
    createdAt: now,
    modifiedAt: now,
    deletedAt: null,
    ...overrides,
  };
}

/**
 * Build an entry whose password age is `ageDays` days old.
 * Sets passwordHistory[0].changedAt to the past timestamp so derivePasswordAge
 * returns approximately ageDays * 24 * 60 * 60 * 1000 ms.
 */
function makeEntryWithAge(ageDays: number, overrides: Partial<Entry> = {}): Entry {
  const ageMs = ageDays * 24 * 60 * 60 * 1000;
  const changedAt = new Date(Date.now() - ageMs).toISOString();
  return makeEntry({
    passwordHistory: [{ password: 'old-password', changedAt }],
    ...overrides,
  });
}

// ---------------------------------------------------------------------------
// beforeAll: warm sodium WASM (mirrors crud.test.ts structure)
// ---------------------------------------------------------------------------

beforeAll(async () => {
  await getSodium();
});

// ---------------------------------------------------------------------------
// describe('core/audit')
// ---------------------------------------------------------------------------

describe('core/audit', () => {
  // ---------------------------------------------------------------------------
  // runAudit - reused (AUDIT-02)
  // ---------------------------------------------------------------------------

  describe('runAudit - reused (AUDIT-02)', () => {
    it('returns both entries sharing the same non-empty password in reused[]', () => {
      const sharedPassword = 'shared-secret-abc';
      const e1 = makeEntry({ password: sharedPassword });
      const e2 = makeEntry({ password: sharedPassword });
      const e3 = makeEntry({ password: 'unique-pass-xyz' });

      const result = runAudit([e1, e2, e3], {
        weakScores: new Map(),
        staleThresholdDays: 365,
      });

      expect(result.reused).toHaveLength(2);
      const reusedIds = result.reused.map((e) => e.id);
      expect(reusedIds).toContain(e1.id);
      expect(reusedIds).toContain(e2.id);
      expect(result.reused.map((e) => e.id)).not.toContain(e3.id);
    });

    it('does NOT flag an entry with a unique password', () => {
      const e1 = makeEntry({ password: 'unique-one' });
      const e2 = makeEntry({ password: 'unique-two' });

      const result = runAudit([e1, e2], {
        weakScores: new Map(),
        staleThresholdDays: 365,
      });

      expect(result.reused).toHaveLength(0);
    });

    it('does NOT flag entries with empty password as reused', () => {
      // Empty passwords are not grouped (empty-string share is not a "reused password")
      const e1 = makeEntry({ password: '' });
      const e2 = makeEntry({ password: '' });

      const result = runAudit([e1, e2], {
        weakScores: new Map(),
        staleThresholdDays: 365,
      });

      expect(result.reused).toHaveLength(0);
    });

    it('flags all entries sharing a password when 3+ use the same value', () => {
      const shared = 'password123';
      const e1 = makeEntry({ password: shared });
      const e2 = makeEntry({ password: shared });
      const e3 = makeEntry({ password: shared });
      const e4 = makeEntry({ password: 'other' });

      const result = runAudit([e1, e2, e3, e4], {
        weakScores: new Map(),
        staleThresholdDays: 365,
      });

      expect(result.reused).toHaveLength(3);
      expect(result.reused.map((e) => e.id)).not.toContain(e4.id);
    });
  });

  // ---------------------------------------------------------------------------
  // runAudit - weak (injected score) (AUDIT-03)
  // ---------------------------------------------------------------------------

  describe('runAudit - weak (injected score) (AUDIT-03)', () => {
    it('flags an entry with injected score 0 as weak', () => {
      const e = makeEntry({ password: 'abc' });
      const weakScores = new Map([[e.id, 0]]);

      const result = runAudit([e], { weakScores, staleThresholdDays: 365 });

      expect(result.weak).toHaveLength(1);
      expect(result.weak[0]!.id).toBe(e.id);
    });

    it('flags an entry with injected score 1 as weak', () => {
      const e = makeEntry({ password: 'weak1' });
      const weakScores = new Map([[e.id, 1]]);

      const result = runAudit([e], { weakScores, staleThresholdDays: 365 });

      expect(result.weak[0]!.id).toBe(e.id);
    });

    it('flags an entry with injected score 2 as weak (boundary — score ≤ 2)', () => {
      const e = makeEntry({ password: 'weak2' });
      const weakScores = new Map([[e.id, 2]]);

      const result = runAudit([e], { weakScores, staleThresholdDays: 365 });

      expect(result.weak).toHaveLength(1);
      expect(result.weak[0]!.id).toBe(e.id);
    });

    it('does NOT flag an entry with injected score 3', () => {
      const e = makeEntry({ password: 'good3' });
      const weakScores = new Map([[e.id, 3]]);

      const result = runAudit([e], { weakScores, staleThresholdDays: 365 });

      expect(result.weak).toHaveLength(0);
    });

    it('does NOT flag an entry with injected score 4', () => {
      const e = makeEntry({ password: 'strong4' });
      const weakScores = new Map([[e.id, 4]]);

      const result = runAudit([e], { weakScores, staleThresholdDays: 365 });

      expect(result.weak).toHaveLength(0);
    });

    it('defaults absent scores to 4 (not weak) — P6-08 fail-safe', () => {
      // Entry is NOT in weakScores map → defaults to 4 → NOT weak
      const e = makeEntry({ password: 'unknown-strength' });
      const weakScores = new Map<string, number>(); // empty map

      const result = runAudit([e], { weakScores, staleThresholdDays: 365 });

      expect(result.weak).toHaveLength(0);
    });

    it('correctly differentiates weak vs strong entries in the same call', () => {
      const eWeak = makeEntry({ password: 'w' });
      const eStrong = makeEntry({ password: 'StrongPass!123' });
      const eAbsent = makeEntry({ password: 'whatever' }); // absent → default 4

      const weakScores = new Map([
        [eWeak.id, 1],
        [eStrong.id, 4],
        // eAbsent not in map
      ]);

      const result = runAudit([eWeak, eStrong, eAbsent], {
        weakScores,
        staleThresholdDays: 365,
      });

      expect(result.weak).toHaveLength(1);
      expect(result.weak[0]!.id).toBe(eWeak.id);
    });
  });

  // ---------------------------------------------------------------------------
  // runAudit - stale (AUDIT-04)
  // ---------------------------------------------------------------------------

  describe('runAudit - stale (AUDIT-04)', () => {
    it('flags an entry whose password age exceeds staleThresholdDays', () => {
      // 400 days old > 365 threshold → stale
      const e = makeEntryWithAge(400);

      const result = runAudit([e], {
        weakScores: new Map(),
        staleThresholdDays: 365,
      });

      expect(result.stale).toHaveLength(1);
      expect(result.stale[0]!.id).toBe(e.id);
    });

    it('does NOT flag an entry whose age is within the threshold', () => {
      // 100 days old < 365 threshold → NOT stale
      const e = makeEntryWithAge(100);

      const result = runAudit([e], {
        weakScores: new Map(),
        staleThresholdDays: 365,
      });

      expect(result.stale).toHaveLength(0);
    });

    it('respects a custom staleThresholdDays value', () => {
      // 200 days old — stale at 90-day threshold, not stale at 365-day threshold
      const e = makeEntryWithAge(200);

      const resultShort = runAudit([e], {
        weakScores: new Map(),
        staleThresholdDays: 90,
      });
      expect(resultShort.stale).toHaveLength(1);

      const resultLong = runAudit([e], {
        weakScores: new Map(),
        staleThresholdDays: 365,
      });
      expect(resultLong.stale).toHaveLength(0);
    });

    it('uses createdAt when passwordHistory is empty (no password change yet)', () => {
      // Entry created 400 days ago, no history → age measured from createdAt
      const createdAt = new Date(Date.now() - 400 * 24 * 60 * 60 * 1000).toISOString();
      const e = makeEntry({
        createdAt,
        modifiedAt: createdAt,
        passwordHistory: [], // no history
      });

      const result = runAudit([e], {
        weakScores: new Map(),
        staleThresholdDays: 365,
      });

      expect(result.stale).toHaveLength(1);
      expect(result.stale[0]!.id).toBe(e.id);
    });

    it('uses passwordHistory[0].changedAt when history is non-empty', () => {
      // Created 400 days ago, but password changed 50 days ago → NOT stale at 365 threshold
      const createdAt = new Date(Date.now() - 400 * 24 * 60 * 60 * 1000).toISOString();
      const changedAt = new Date(Date.now() - 50 * 24 * 60 * 60 * 1000).toISOString();
      const e = makeEntry({
        createdAt,
        passwordHistory: [{ password: 'old', changedAt }],
      });

      const result = runAudit([e], {
        weakScores: new Map(),
        staleThresholdDays: 365,
      });

      expect(result.stale).toHaveLength(0);
    });
  });

  // ---------------------------------------------------------------------------
  // runAudit - needsUpdate (AUDIT-05)
  // ---------------------------------------------------------------------------

  describe('runAudit - needsUpdate (AUDIT-05)', () => {
    it('flags entries with needsSiteUpdate === true', () => {
      const e1 = makeEntry({ needsSiteUpdate: true });
      const e2 = makeEntry({ needsSiteUpdate: false });
      const e3 = makeEntry({ needsSiteUpdate: true });

      const result = runAudit([e1, e2, e3], {
        weakScores: new Map(),
        staleThresholdDays: 365,
      });

      expect(result.needsUpdate).toHaveLength(2);
      const ids = result.needsUpdate.map((e) => e.id);
      expect(ids).toContain(e1.id);
      expect(ids).toContain(e3.id);
      expect(ids).not.toContain(e2.id);
    });

    it('returns empty needsUpdate when no entries have needsSiteUpdate === true', () => {
      const e1 = makeEntry({ needsSiteUpdate: false });
      const e2 = makeEntry({ needsSiteUpdate: false });

      const result = runAudit([e1, e2], {
        weakScores: new Map(),
        staleThresholdDays: 365,
      });

      expect(result.needsUpdate).toHaveLength(0);
    });
  });

  // ---------------------------------------------------------------------------
  // Tombstone exclusion — all four buckets (AUDIT-01, TEST-06)
  // ---------------------------------------------------------------------------

  describe('tombstone exclusion (deletedAt !== null excluded from all buckets)', () => {
    it('excludes a tombstoned entry from reused even when it shares a password', () => {
      const sharedPassword = 'shared-tombstone-test';
      const eActive = makeEntry({ password: sharedPassword });
      const eTombstone = makeEntry({
        password: sharedPassword,
        deletedAt: new Date().toISOString(), // tombstoned
      });

      const result = runAudit([eActive, eTombstone], {
        weakScores: new Map(),
        staleThresholdDays: 365,
      });

      // Only one active entry with this password — not actually "reused" since
      // the tombstone is excluded. The active entry should NOT be flagged.
      expect(result.reused).toHaveLength(0);
    });

    it('excludes a tombstoned entry from weak', () => {
      const eTombstone = makeEntry({
        password: 'weak-password',
        deletedAt: new Date().toISOString(),
      });
      const weakScores = new Map([[eTombstone.id, 0]]);

      const result = runAudit([eTombstone], { weakScores, staleThresholdDays: 365 });

      expect(result.weak).toHaveLength(0);
    });

    it('excludes a tombstoned entry from stale', () => {
      const eTombstone = makeEntryWithAge(400, {
        deletedAt: new Date().toISOString(),
      });

      const result = runAudit([eTombstone], {
        weakScores: new Map(),
        staleThresholdDays: 365,
      });

      expect(result.stale).toHaveLength(0);
    });

    it('excludes a tombstoned entry from needsUpdate', () => {
      const eTombstone = makeEntry({
        needsSiteUpdate: true,
        deletedAt: new Date().toISOString(),
      });

      const result = runAudit([eTombstone], {
        weakScores: new Map(),
        staleThresholdDays: 365,
      });

      expect(result.needsUpdate).toHaveLength(0);
    });

    it('handles an all-tombstone list by returning empty results in all buckets', () => {
      const ts = new Date().toISOString();
      const entries = [
        makeEntry({ password: 'shared', deletedAt: ts }),
        makeEntry({ password: 'shared', deletedAt: ts }),
        makeEntry({ needsSiteUpdate: true, deletedAt: ts }),
      ];
      const weakScores = new Map(entries.map((e) => [e.id, 0]));

      const result = runAudit(entries, { weakScores, staleThresholdDays: 365 });

      expect(result.reused).toHaveLength(0);
      expect(result.weak).toHaveLength(0);
      expect(result.stale).toHaveLength(0);
      expect(result.needsUpdate).toHaveLength(0);
    });
  });

  // ---------------------------------------------------------------------------
  // Empty input
  // ---------------------------------------------------------------------------

  describe('edge cases', () => {
    it('returns empty result for an empty entries array', () => {
      const result = runAudit([], { weakScores: new Map(), staleThresholdDays: 365 });
      expect(result.reused).toHaveLength(0);
      expect(result.weak).toHaveLength(0);
      expect(result.stale).toHaveLength(0);
      expect(result.needsUpdate).toHaveLength(0);
    });
  });
});
