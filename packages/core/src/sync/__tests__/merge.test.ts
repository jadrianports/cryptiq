// packages/core/src/sync/__tests__/merge.test.ts
//
// RED test suite for Phase 8 (08-02): example-based scenarios covering every
// named ROADMAP Success Criterion (SC-2..SC-5) and every D-NN merge decision.
//
// EXPECTED STATE: ALL tests in this file are RED. mergeInnerDocs and
// findPossibleDuplicates throw new Error('not implemented') (08-01 stubs). The
// tests fail at the stub — "expected <asserted behavior>, but it threw Error:
// not implemented". This is the INTENDED state of plan 08-02.
// Plan 08-03 turns this suite GREEN by implementing the merge engine.
//
// Requirements covered (RED gate, proves contract exists before implementation):
//   MERGE-02 — LWW on modifiedAt; newer wins; loser preserved (SC-2)
//   MERGE-03 — Create-vs-create: both entries survive (SC-3)
//   MERGE-04 — Delete-wins; losing edit's snapshot preserved (SC-4)
//   MERGE-05 — Overwritten password in history; cap 10 (D-03)
//   MERGE-06 — MergeClockSkewError on |Δ| > 30s (SC-5)
//   MERGE-07 — Deterministic deviceId tiebreaker (D-13/D-14)
//   D-04 — Settings: local wins
//   D-07 — Permanent delete is final; peer content NOT preserved
//   D-08 — Absent entry (no tombstone): kept
//   D-09 — schemaVersion mismatch → MergeSchemaMismatchError
//   D-15 — conflicts[] reason codes
//   D-16 — Per-device counts (added/updated/deleted/unchanged)
//   D-17 — Invalid input → MergeInvalidInputError; empty vault is valid
//   D-19 — Duplicate hint: same title+url flagged; distinct url not flagged
//
// Conventions:
//   - Fixed epoch constants; never Date.now() in test bodies (CLAUDE.md).
//   - No Math.random; no getSodium() — fixtures use literal id strings (CLAUDE.md).
//   - Typed-error assertions use expect.objectContaining({ code: '...' })
//     NOT instanceof, NOT message-text matching (RESEARCH Anti-Patterns).
//   - Conflict arrays sorted by entryId before asserting (RESEARCH Anti-Patterns).

import { describe, it, expect } from 'vitest';
import type { InnerDoc, Entry, EntryTotp, EntryCard, EntryIdentity } from '../../entries/types';
import type { MergeContext } from '../types';
import { DEFAULT_RANDOM_OPTIONS } from '../../generator/types';
import { mergeInnerDocs } from '../merge';
import { isPermanentTombstone } from '../types';
import { findPossibleDuplicates } from '../duplicate';

// ---------------------------------------------------------------------------
// Fixed epoch constants (never Date.now() — CLAUDE.md / lockLogic.test.ts pattern)
// ---------------------------------------------------------------------------

// A fixed reference epoch: 2025-01-01T00:00:00.000Z in ms
const EPOCH_BASE = 1_735_689_600_000;
// 1 hour later
const EPOCH_PLUS_1H = EPOCH_BASE + 3_600_000;
// 2 hours later
const EPOCH_PLUS_2H = EPOCH_BASE + 7_200_000;
// Used for deletedAt timestamps in tests
const EPOCH_PLUS_30M = EPOCH_BASE + 1_800_000;
const EPOCH_PLUS_45M = EPOCH_BASE + 2_700_000;

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

/** Build a MergeContext with sensible defaults (equal clocks, distinct deviceIds). */
function makeCtx(overrides?: Partial<MergeContext>): MergeContext {
  return {
    localDeviceId: 'device-local',
    remoteDeviceId: 'device-remote',
    localNowMs: EPOCH_BASE,
    remoteNowMs: EPOCH_BASE,
    ...overrides,
  };
}

/** Build a valid InnerDoc (schemaVersion 2, no entries). */
function makeInnerDoc(overrides?: Partial<InnerDoc>): InnerDoc {
  return {
    schemaVersion: 2,
    entries: [],
    settings: { generator: DEFAULT_RANDOM_OPTIONS },
    ...overrides,
  };
}

/** Build a full, valid active Entry with all required fields. */
function makeEntry(overrides?: Partial<Entry>): Entry {
  return {
    id: 'entry-default-001',
    type: 'login',
    title: 'Default Entry',
    username: 'user@example.com',
    password: 'default-password',
    url: 'https://example.com',
    notes: '',
    tags: [],
    favorite: false,
    needsSiteUpdate: false,
    generatorPreset: null,
    passwordHistory: [],
    lostVersions: [],
    createdAt: new Date(EPOCH_BASE).toISOString(),
    modifiedAt: new Date(EPOCH_BASE).toISOString(),
    deletedAt: null,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Describe: LWW merge (MERGE-02/D-01)
// ---------------------------------------------------------------------------

describe('LWW merge (MERGE-02/D-01)', () => {
  it('LWW: local newer wins; remote password in history', () => {
    // Local has a NEWER modifiedAt — local's version should win.
    // Remote's password must appear in the merged entry's passwordHistory.
    const sharedId = 'entry-lww-001';
    const localEntry = makeEntry({
      id: sharedId,
      password: 'local-new-password',
      modifiedAt: new Date(EPOCH_PLUS_1H).toISOString(),
    });
    const remoteEntry = makeEntry({
      id: sharedId,
      password: 'remote-old-password',
      modifiedAt: new Date(EPOCH_BASE).toISOString(),
    });
    const local = makeInnerDoc({ entries: [localEntry] });
    const remote = makeInnerDoc({ entries: [remoteEntry] });

    const result = mergeInnerDocs(local, remote, makeCtx());

    // SC-2: local won → merged entry has local's password
    const merged = result.merged.entries.find((e) => e.id === sharedId);
    expect(merged).toBeDefined();
    expect(merged!.password).toBe('local-new-password');

    // D-01: loser's password recoverable in history
    const allHistory = merged!.passwordHistory;
    const remoteInHistory = allHistory.some((h) => h.password === 'remote-old-password');
    expect(remoteInHistory).toBe(true);

    // D-16: updated count — local version was the winner; from local perspective unchanged
    // The remote was older so local's copy was not changed — D-16: unchanged for local
    expect(result.counts.unchanged).toBeGreaterThanOrEqual(1);
  });

  it('LWW: remote newer wins; local password in history', () => {
    // Remote has a NEWER modifiedAt — remote's version should win.
    // Local's password must appear in the merged entry's passwordHistory.
    const sharedId = 'entry-lww-002';
    const localEntry = makeEntry({
      id: sharedId,
      password: 'local-old-password',
      modifiedAt: new Date(EPOCH_BASE).toISOString(),
    });
    const remoteEntry = makeEntry({
      id: sharedId,
      password: 'remote-new-password',
      modifiedAt: new Date(EPOCH_PLUS_1H).toISOString(),
    });
    const local = makeInnerDoc({ entries: [localEntry] });
    const remote = makeInnerDoc({ entries: [remoteEntry] });

    const result = mergeInnerDocs(local, remote, makeCtx());

    const merged = result.merged.entries.find((e) => e.id === sharedId);
    expect(merged).toBeDefined();
    expect(merged!.password).toBe('remote-new-password');

    // D-01: loser's (local) password recoverable in history
    const localInHistory = merged!.passwordHistory.some((h) => h.password === 'local-old-password');
    expect(localInHistory).toBe(true);

    // D-16: updated — this device's version was replaced by remote's
    expect(result.counts.updated).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// Describe: Create-vs-create: both survive (MERGE-03/D-08/SC-3)
// ---------------------------------------------------------------------------

describe('create-vs-create: both survive (MERGE-03/D-08/SC-3)', () => {
  it('create-vs-create: both entries with distinct ids survive in merged output', () => {
    // Entries on separate devices with distinct CSPRNG UUIDs — neither has a tombstone.
    // Both must appear in the merged entry set (SC-3, D-08).
    const localEntry = makeEntry({ id: 'entry-local-c2c-001', title: 'Local Only' });
    const remoteEntry = makeEntry({ id: 'entry-remote-c2c-001', title: 'Remote Only' });
    const local = makeInnerDoc({ entries: [localEntry] });
    const remote = makeInnerDoc({ entries: [remoteEntry] });

    const result = mergeInnerDocs(local, remote, makeCtx());

    const ids = result.merged.entries.map((e) => e.id);
    expect(ids).toContain('entry-local-c2c-001');
    expect(ids).toContain('entry-remote-c2c-001');
    expect(result.merged.entries.length).toBe(2);

    // Create-vs-create is NOT a conflict (D-15)
    expect(result.conflicts.length).toBe(0);

    // D-16: remote entry was new-to-local → added
    expect(result.counts.added).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// Describe: Delete semantics (MERGE-04/D-05/D-06/D-07/SC-4)
// ---------------------------------------------------------------------------

describe('delete semantics (MERGE-04/D-05/D-06/D-07/SC-4)', () => {
  it('delete-wins (soft): soft tombstone over newer edit; snapshot preserved (D-05)', () => {
    // Local: soft-tombstoned entry (deletedAt set).
    // Remote: a NEWER active edit of the same id.
    // Rule D-05: delete-wins → merged keeps the tombstone.
    // Rule D-01: the losing remote edit's password is preserved in the tombstone's history.
    const sharedId = 'entry-delete-soft-001';
    const localTombstone = makeEntry({
      id: sharedId,
      password: 'pre-delete-password',
      deletedAt: new Date(EPOCH_BASE).toISOString(),
      modifiedAt: new Date(EPOCH_BASE).toISOString(),
    });
    const remoteEdit = makeEntry({
      id: sharedId,
      password: 'remote-newer-password',
      modifiedAt: new Date(EPOCH_PLUS_1H).toISOString(),
      deletedAt: null,
    });
    const local = makeInnerDoc({ entries: [localTombstone] });
    const remote = makeInnerDoc({ entries: [remoteEdit] });

    const result = mergeInnerDocs(local, remote, makeCtx());

    const merged = result.merged.entries.find((e) => e.id === sharedId);
    expect(merged).toBeDefined();
    // D-05: soft tombstone wins → deletedAt is non-null
    expect(merged!.deletedAt).not.toBeNull();

    // D-01: remote's losing password must be recoverable
    const remotePasswordPreserved =
      merged!.passwordHistory.some((h) => h.password === 'remote-newer-password') ||
      (merged!.lostVersions ?? []).some((s) => s.password === 'remote-newer-password');
    expect(remotePasswordPreserved).toBe(true);

    // D-15: delete-wins recorded as a conflict with reason 'delete-wins'
    const conflict = result.conflicts.find((c) => c.entryId === sharedId);
    expect(conflict).toBeDefined();
    expect(conflict!.reason).toBe('delete-wins');

    // D-16: this device already had the tombstone — deleted count from local perspective
    expect(result.counts.deleted).toBeGreaterThanOrEqual(0);
  });

  it('delete-wins (permanent): content-wiped tombstone wins; peer content NOT preserved (D-06/D-07)', () => {
    // Local: permanent tombstone (D-06 marker: deletedAt set + all secret fields wiped).
    // Remote: a live active entry with the same id.
    // Rule D-07: permanent tombstone wins everywhere; peer content is NOT preserved.
    // NOT recorded in conflicts (D-15: permanent-delete-final is the sanctioned exception).
    const sharedId = 'entry-perm-delete-001';
    const permanentTombstone = makeEntry({
      id: sharedId,
      // D-06 permanent tombstone: deletedAt set + ALL content collapsed to the
      // secret-free marker (title/url/tags wiped too — a strict empty-marker shape,
      // so a content-sparse SOFT delete is never misclassified as permanent).
      title: '',
      url: '',
      tags: [],
      password: '',
      username: '',
      notes: '',
      passwordHistory: [],
      lostVersions: [],
      deletedAt: new Date(EPOCH_BASE).toISOString(),
      modifiedAt: new Date(EPOCH_BASE).toISOString(),
    });
    const remoteActive = makeEntry({
      id: sharedId,
      password: 'remote-live-password',
      username: 'remote-user',
      notes: 'sensitive notes',
      modifiedAt: new Date(EPOCH_PLUS_1H).toISOString(),
      deletedAt: null,
    });
    const local = makeInnerDoc({ entries: [permanentTombstone] });
    const remote = makeInnerDoc({ entries: [remoteActive] });

    const result = mergeInnerDocs(local, remote, makeCtx());

    const merged = result.merged.entries.find((e) => e.id === sharedId);
    expect(merged).toBeDefined();
    // D-07: permanent tombstone wins — deletedAt preserved
    expect(merged!.deletedAt).not.toBeNull();
    // D-07: peer's content is NOT preserved — password remains wiped
    expect(merged!.password).toBe('');
    expect(merged!.username).toBe('');
    // D-07: no resurrection — 'remote-live-password' must NOT appear anywhere
    const remotePasswordResurrected =
      merged!.passwordHistory.some((h) => h.password === 'remote-live-password') ||
      (merged!.lostVersions ?? []).some((s) => s.password === 'remote-live-password');
    expect(remotePasswordResurrected).toBe(false);

    // D-15: permanent-delete-final is NOT a conflict
    const conflict = result.conflicts.find((c) => c.entryId === sharedId);
    expect(conflict).toBeUndefined();
  });

  it('both tombstoned: earlier deletedAt kept (MERGE-04)', () => {
    // Both local and remote soft-deleted the same entry at different times.
    // Rule: keep the EARLIER deletedAt (MERGE-04, D-04 both-tombstoned).
    const sharedId = 'entry-both-tomb-001';
    const localTombstone = makeEntry({
      id: sharedId,
      deletedAt: new Date(EPOCH_PLUS_30M).toISOString(), // earlier
      modifiedAt: new Date(EPOCH_PLUS_30M).toISOString(),
    });
    const remoteTombstone = makeEntry({
      id: sharedId,
      deletedAt: new Date(EPOCH_PLUS_45M).toISOString(), // later
      modifiedAt: new Date(EPOCH_PLUS_45M).toISOString(),
    });
    const local = makeInnerDoc({ entries: [localTombstone] });
    const remote = makeInnerDoc({ entries: [remoteTombstone] });

    const result = mergeInnerDocs(local, remote, makeCtx());

    const merged = result.merged.entries.find((e) => e.id === sharedId);
    expect(merged).toBeDefined();
    // MERGE-04: earlier deletedAt is kept
    expect(merged!.deletedAt).toBe(new Date(EPOCH_PLUS_30M).toISOString());
  });
});

// ---------------------------------------------------------------------------
// Describe: passwordHistory union cap (MERGE-05/D-03)
// ---------------------------------------------------------------------------

describe('history union cap (MERGE-05/D-03)', () => {
  it('history union: cap 10 respected, no duplicate (changedAt,password) pairs', () => {
    // Both sides have 8-item histories (some overlapping, some distinct).
    // After union: deduped, newest-first, length at most 10.
    const sharedId = 'entry-history-001';

    // Build 8 history items for local (times: base + 1..8 hours)
    const makeHistoryItem = (password: string, offsetMs: number) => ({
      password,
      changedAt: new Date(EPOCH_BASE + offsetMs).toISOString(),
    });

    // Local: items at hours 1-8 (8 items, newest = hour 8)
    const localHistory = [
      makeHistoryItem('hist-local-8', 8 * 3_600_000),
      makeHistoryItem('hist-local-7', 7 * 3_600_000),
      makeHistoryItem('hist-local-6', 6 * 3_600_000),
      makeHistoryItem('hist-local-5', 5 * 3_600_000),
      makeHistoryItem('hist-shared-4', 4 * 3_600_000),  // shared
      makeHistoryItem('hist-shared-3', 3 * 3_600_000),  // shared
      makeHistoryItem('hist-shared-2', 2 * 3_600_000),  // shared
      makeHistoryItem('hist-shared-1', 1 * 3_600_000),  // shared
    ];

    // Remote: same 4 shared items + 4 distinct remote items at different times
    const remoteHistory = [
      makeHistoryItem('hist-remote-12', 12 * 3_600_000), // newest overall
      makeHistoryItem('hist-remote-11', 11 * 3_600_000),
      makeHistoryItem('hist-remote-10', 10 * 3_600_000),
      makeHistoryItem('hist-remote-9', 9 * 3_600_000),
      makeHistoryItem('hist-shared-4', 4 * 3_600_000),  // shared (dup)
      makeHistoryItem('hist-shared-3', 3 * 3_600_000),  // shared (dup)
      makeHistoryItem('hist-shared-2', 2 * 3_600_000),  // shared (dup)
      makeHistoryItem('hist-shared-1', 1 * 3_600_000),  // shared (dup)
    ];

    const localEntry = makeEntry({
      id: sharedId,
      password: 'current-password',
      modifiedAt: new Date(EPOCH_PLUS_2H).toISOString(),
      passwordHistory: localHistory,
    });
    const remoteEntry = makeEntry({
      id: sharedId,
      password: 'current-password', // same current password — no LWW change
      modifiedAt: new Date(EPOCH_PLUS_2H).toISOString(),
      passwordHistory: remoteHistory,
    });
    const local = makeInnerDoc({ entries: [localEntry] });
    const remote = makeInnerDoc({ entries: [remoteEntry] });

    const result = mergeInnerDocs(local, remote, makeCtx());

    const merged = result.merged.entries.find((e) => e.id === sharedId);
    expect(merged).toBeDefined();

    // MERGE-05 / D-03: cap at 10
    expect(merged!.passwordHistory.length).toBeLessThanOrEqual(10);

    // D-03: no duplicate (changedAt, password) pairs
    const seen = new Set<string>();
    for (const item of merged!.passwordHistory) {
      const key = `${item.changedAt}::${item.password}`;
      expect(seen.has(key)).toBe(false);
      seen.add(key);
    }

    // D-03: newest-first ordering
    for (let i = 1; i < merged!.passwordHistory.length; i++) {
      const prev = Date.parse(merged!.passwordHistory[i - 1]!.changedAt);
      const curr = Date.parse(merged!.passwordHistory[i]!.changedAt);
      expect(prev).toBeGreaterThanOrEqual(curr);
    }
  });
});

// ---------------------------------------------------------------------------
// Describe: clock-skew guard (MERGE-06/D-12/SC-5)
// ---------------------------------------------------------------------------

describe('clock skew guard (MERGE-06/D-12/SC-5)', () => {
  it('clock skew > 30s: MergeClockSkewError thrown before any records merge', () => {
    // |Δ| = 30_001ms — strictly greater than 30s → must throw MERGE_CLOCK_SKEW (D-12).
    const ctx = makeCtx({ localNowMs: 0, remoteNowMs: 30_001 });
    const local = makeInnerDoc({ entries: [makeEntry({ id: 'entry-skew-001' })] });
    const remote = makeInnerDoc({ entries: [makeEntry({ id: 'entry-skew-001' })] });

    expect(() => mergeInnerDocs(local, remote, ctx)).toThrow(
      expect.objectContaining({ code: 'MERGE_CLOCK_SKEW' }),
    );
  });

  it('clock skew = 30s: NO error (strict greater-than boundary — D-12)', () => {
    // |Δ| = exactly 30_000ms — must NOT throw at all (strict >, not >=).
    // D-12: the guard is |localNowMs - remoteNowMs| > 30_000 (strict greater-than).
    // At exactly 30_000ms the merge must proceed and return a MergeResult.
    // This test asserts the positive case: a valid result is returned, not that
    // a specific error is absent. The stub always throws, so this is RED until 08-03.
    const ctx = makeCtx({ localNowMs: 0, remoteNowMs: 30_000 });
    const local = makeInnerDoc();
    const remote = makeInnerDoc();

    // Must not throw any error at exactly 30_000ms skew
    expect(() => mergeInnerDocs(local, remote, ctx)).not.toThrow();
  });

  it('clock skew > 30s: also throws when the remote is BEHIND local by 30_001ms', () => {
    // Symmetric: local > remote by 30_001ms (both directions should throw).
    const ctx = makeCtx({ localNowMs: 30_001, remoteNowMs: 0 });

    expect(() => mergeInnerDocs(makeInnerDoc(), makeInnerDoc(), ctx)).toThrow(
      expect.objectContaining({ code: 'MERGE_CLOCK_SKEW' }),
    );
  });
});

// ---------------------------------------------------------------------------
// Describe: tiebreak (MERGE-07/D-13/D-14)
// ---------------------------------------------------------------------------

describe('tiebreak (MERGE-07/D-13/D-14)', () => {
  it('tiebreak: lex-greater deviceId wins; loser snapshot preserved (D-13)', () => {
    // Both versions of the same entry have IDENTICAL modifiedAt but different content.
    // Tiebreak rule (D-13): lexicographically-greater deviceId ('device-remote' > 'device-local').
    // The loser ('device-local') must be preserved as a full snapshot (D-01).
    const sharedId = 'entry-tiebreak-001';
    const tiedModifiedAt = new Date(EPOCH_BASE).toISOString();

    const localEntry = makeEntry({
      id: sharedId,
      password: 'local-tiebreak-password',
      modifiedAt: tiedModifiedAt,
    });
    const remoteEntry = makeEntry({
      id: sharedId,
      password: 'remote-tiebreak-password',
      modifiedAt: tiedModifiedAt, // identical modifiedAt
    });
    const local = makeInnerDoc({ entries: [localEntry] });
    const remote = makeInnerDoc({ entries: [remoteEntry] });

    // 'device-remote' > 'device-local' lexicographically → remote wins
    const ctx = makeCtx({ localDeviceId: 'device-local', remoteDeviceId: 'device-remote' });
    const result = mergeInnerDocs(local, remote, ctx);

    const merged = result.merged.entries.find((e) => e.id === sharedId);
    expect(merged).toBeDefined();
    // D-13: lex-greater ('device-remote') wins
    expect(merged!.password).toBe('remote-tiebreak-password');

    // D-01: loser's password preserved
    const loserPreserved =
      merged!.passwordHistory.some((h) => h.password === 'local-tiebreak-password') ||
      (merged!.lostVersions ?? []).some((s) => s.password === 'local-tiebreak-password');
    expect(loserPreserved).toBe(true);

    // D-15: tiebreak recorded in conflicts with reason 'tiebreak'
    const conflict = result.conflicts.find((c) => c.entryId === sharedId);
    expect(conflict).toBeDefined();
    expect(conflict!.reason).toBe('tiebreak');
    expect(conflict!.winnerDeviceId).toBe('device-remote');
    expect(conflict!.loserDeviceId).toBe('device-local');
  });

  it('tiebreak: equal deviceIds + identical content = unchanged, no conflict (D-14 fallback)', () => {
    // Same deviceId on both sides and same content → no-op; neither side wins a conflict.
    // D-14: identical content + equal deviceIds → unchanged.
    const sharedId = 'entry-tiebreak-equal-001';
    const tiedModifiedAt = new Date(EPOCH_BASE).toISOString();

    const sharedEntry = makeEntry({
      id: sharedId,
      password: 'same-password',
      modifiedAt: tiedModifiedAt,
    });
    const local = makeInnerDoc({ entries: [{ ...sharedEntry }] });
    const remote = makeInnerDoc({ entries: [{ ...sharedEntry }] });

    // Same device ID on both sides
    const ctx = makeCtx({ localDeviceId: 'device-same', remoteDeviceId: 'device-same' });
    const result = mergeInnerDocs(local, remote, ctx);

    // D-14: unchanged — no snapshot added
    const merged = result.merged.entries.find((e) => e.id === sharedId);
    expect(merged).toBeDefined();
    expect(merged!.password).toBe('same-password');
    expect(merged!.passwordHistory.length).toBe(0);

    // D-16: unchanged count
    expect(result.counts.unchanged).toBeGreaterThanOrEqual(1);
    expect(result.counts.updated).toBe(0);

    // D-15: no conflict for equal-deviceId identical content
    expect(result.conflicts.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Describe: input and schema guards (D-09/D-17)
// ---------------------------------------------------------------------------

describe('input and schema guards (D-09/D-17)', () => {
  it('schemaVersion mismatch: MergeSchemaMismatchError before any records merge (D-09)', () => {
    // local = schemaVersion 2, remote = schemaVersion 1 → throw MERGE_SCHEMA_MISMATCH.
    // Must throw BEFORE any records are merged.
    const local: InnerDoc = makeInnerDoc({ schemaVersion: 2 });
    const remote: InnerDoc = {
      schemaVersion: 1,
      entries: [],
      settings: { generator: DEFAULT_RANDOM_OPTIONS },
    };

    expect(() => mergeInnerDocs(local, remote, makeCtx())).toThrow(
      expect.objectContaining({ code: 'MERGE_SCHEMA_MISMATCH' }),
    );
  });

  it('invalid entry (bad modifiedAt): MergeInvalidInputError; whole merge refused (D-17)', () => {
    // One entry has modifiedAt: 'not-a-date' — must throw MERGE_INVALID_INPUT.
    // The whole merge is refused (never partial).
    const badEntry = makeEntry({
      id: 'entry-invalid-001',
      modifiedAt: 'not-a-date',
    });
    const local = makeInnerDoc({ entries: [badEntry] });
    const remote = makeInnerDoc({ entries: [] });

    expect(() => mergeInnerDocs(local, remote, makeCtx())).toThrow(
      expect.objectContaining({ code: 'MERGE_INVALID_INPUT' }),
    );
  });

  it('invalid entry in REMOTE: MergeInvalidInputError (D-17)', () => {
    const badEntry = makeEntry({
      id: 'entry-invalid-002',
      modifiedAt: 'not-a-date',
    });
    const local = makeInnerDoc({ entries: [] });
    const remote = makeInnerDoc({ entries: [badEntry] });

    expect(() => mergeInnerDocs(local, remote, makeCtx())).toThrow(
      expect.objectContaining({ code: 'MERGE_INVALID_INPUT' }),
    );
  });

  it('empty vault (zero entries) is VALID: merges to the other side without error (D-17)', () => {
    // D-17: empty vault is NOT an error — it merges to the non-empty side.
    const remoteEntry = makeEntry({ id: 'entry-from-remote-001', title: 'Remote Entry' });
    const local = makeInnerDoc({ entries: [] });         // empty
    const remote = makeInnerDoc({ entries: [remoteEntry] });

    // Must NOT throw
    const result = mergeInnerDocs(local, remote, makeCtx());

    // Remote's entry should survive in merged output
    expect(result.merged.entries.some((e) => e.id === 'entry-from-remote-001')).toBe(true);
    expect(result.counts.added).toBeGreaterThanOrEqual(1);
  });

  it('both vaults empty: valid; merged has zero entries (D-17)', () => {
    const local = makeInnerDoc({ entries: [] });
    const remote = makeInnerDoc({ entries: [] });

    const result = mergeInnerDocs(local, remote, makeCtx());

    expect(result.merged.entries.length).toBe(0);
    expect(result.counts.added).toBe(0);
    expect(result.counts.updated).toBe(0);
    expect(result.counts.deleted).toBe(0);
    expect(result.counts.unchanged).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Describe: settings and absent-side semantics (D-04/D-08)
// ---------------------------------------------------------------------------

describe('settings and absent-side semantics (D-04/D-08)', () => {
  it('settings: local settings preserved regardless of remote (D-04)', () => {
    // Remote has different settings (e.g. different idleMinutes).
    // D-04: merged.settings must deep-equal LOCAL settings.
    const localSettings = {
      generator: DEFAULT_RANDOM_OPTIONS,
      lock: { idleMinutes: 10 as number | 'never', lockOnMinimize: false },
    };
    const remoteSettings = {
      generator: DEFAULT_RANDOM_OPTIONS,
      lock: { idleMinutes: 'never' as number | 'never', lockOnMinimize: true },
    };
    const local: InnerDoc = { schemaVersion: 2, entries: [], settings: localSettings };
    const remote: InnerDoc = { schemaVersion: 2, entries: [], settings: remoteSettings };

    const result = mergeInnerDocs(local, remote, makeCtx());

    // D-04: local settings must win
    expect(result.merged.settings).toEqual(localSettings);
    expect(result.merged.settings).not.toEqual(remoteSettings);
  });

  it('absent entry (no tombstone on either side): kept (D-08/MERGE-03)', () => {
    // Entry exists only on local, no tombstone anywhere → treated as new, kept.
    const localOnlyEntry = makeEntry({ id: 'entry-absent-001', title: 'Local Only' });
    const local = makeInnerDoc({ entries: [localOnlyEntry] });
    const remote = makeInnerDoc({ entries: [] }); // remote never saw this entry

    const result = mergeInnerDocs(local, remote, makeCtx());

    expect(result.merged.entries.some((e) => e.id === 'entry-absent-001')).toBe(true);
    // From local perspective: unchanged (local already had it)
    expect(result.counts.unchanged).toBeGreaterThanOrEqual(1);
  });

  it('entry only on remote (no tombstone): kept as new on local (D-08)', () => {
    const remoteOnlyEntry = makeEntry({ id: 'entry-absent-002', title: 'Remote Only' });
    const local = makeInnerDoc({ entries: [] });
    const remote = makeInnerDoc({ entries: [remoteOnlyEntry] });

    const result = mergeInnerDocs(local, remote, makeCtx());

    expect(result.merged.entries.some((e) => e.id === 'entry-absent-002')).toBe(true);
    // D-16: new-to-local → added
    expect(result.counts.added).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// Describe: duplicate hint (D-19)
// ---------------------------------------------------------------------------

describe('duplicate hint (D-19)', () => {
  it('duplicate hint: same title+url (case-insensitive) flagged as one group', () => {
    // Two active entries share the same title+url (after lowercasing) →
    // findPossibleDuplicates returns one group containing both (D-19).
    const entry1 = makeEntry({
      id: 'entry-dup-001',
      title: 'My Bank',
      url: 'https://bank.example.com',
    });
    const entry2 = makeEntry({
      id: 'entry-dup-002',
      title: 'MY BANK', // same when lowercased
      url: 'https://bank.example.com',
    });
    const doc = makeInnerDoc({ entries: [entry1, entry2] });

    const groups = findPossibleDuplicates(doc);

    expect(groups.length).toBe(1);
    const group = groups[0]!;
    const groupIds = group.entries.map((e) => e.id);
    expect(groupIds).toContain('entry-dup-001');
    expect(groupIds).toContain('entry-dup-002');
  });

  it('duplicate hint: distinct url not flagged — empty result (D-19)', () => {
    // Same title, different URL → NOT a duplicate (D-19 groups by title+url).
    const entry1 = makeEntry({
      id: 'entry-notdup-001',
      title: 'My Bank',
      url: 'https://bank1.example.com',
    });
    const entry2 = makeEntry({
      id: 'entry-notdup-002',
      title: 'My Bank',
      url: 'https://bank2.example.com', // different URL
    });
    const doc = makeInnerDoc({ entries: [entry1, entry2] });

    const groups = findPossibleDuplicates(doc);

    expect(groups.length).toBe(0);
  });

  it('duplicate hint: soft-deleted entries not counted as duplicates (D-19 active-only)', () => {
    // One active, one tombstoned entry sharing title+url → not flagged
    // (findPossibleDuplicates groups ACTIVE entries only — D-19)
    const activeEntry = makeEntry({
      id: 'entry-dup-active-001',
      title: 'Shared Site',
      url: 'https://shared.example.com',
      deletedAt: null,
    });
    const tombstoneEntry = makeEntry({
      id: 'entry-dup-tomb-001',
      title: 'Shared Site',
      url: 'https://shared.example.com',
      deletedAt: new Date(EPOCH_BASE).toISOString(), // tombstoned
    });
    const doc = makeInnerDoc({ entries: [activeEntry, tombstoneEntry] });

    const groups = findPossibleDuplicates(doc);

    // Only one active entry in the group → not a duplicate (need ≥ 2)
    expect(groups.length).toBe(0);
  });

  it('duplicate hint: three entries sharing title+url produces one group of 3 (D-19)', () => {
    const makeSharedEntry = (id: string) =>
      makeEntry({ id, title: 'triple dup', url: 'https://triple.example.com', deletedAt: null });

    const doc = makeInnerDoc({
      entries: [
        makeSharedEntry('entry-triple-001'),
        makeSharedEntry('entry-triple-002'),
        makeSharedEntry('entry-triple-003'),
      ],
    });

    const groups = findPossibleDuplicates(doc);
    expect(groups.length).toBe(1);
    expect(groups[0]!.entries.length).toBe(3);
  });

  it('duplicate hint returns empty array when no duplicates (D-19)', () => {
    const doc = makeInnerDoc({
      entries: [
        makeEntry({ id: 'entry-unique-001', title: 'Site A', url: 'https://a.example.com' }),
        makeEntry({ id: 'entry-unique-002', title: 'Site B', url: 'https://b.example.com' }),
      ],
    });
    const groups = findPossibleDuplicates(doc);
    expect(groups.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Describe: MergeResult structure (D-11/D-15/D-16)
// ---------------------------------------------------------------------------

describe('MergeResult structure (D-11/D-15/D-16)', () => {
  it('MergeResult has merged, counts, and conflicts fields (D-11/D-15/D-16)', () => {
    const local = makeInnerDoc();
    const remote = makeInnerDoc();

    const result = mergeInnerDocs(local, remote, makeCtx());

    expect(result).toHaveProperty('merged');
    expect(result).toHaveProperty('counts');
    expect(result).toHaveProperty('conflicts');
    expect(result.merged).toHaveProperty('entries');
    expect(typeof result.counts.added).toBe('number');
    expect(typeof result.counts.updated).toBe('number');
    expect(typeof result.counts.deleted).toBe('number');
    expect(typeof result.counts.unchanged).toBe('number');
    expect(Array.isArray(result.conflicts)).toBe(true);
  });

  it('merged InnerDoc inherits local schemaVersion (D-09 already verified they match)', () => {
    const local = makeInnerDoc({ schemaVersion: 2 });
    const remote = makeInnerDoc({ schemaVersion: 2 });

    const result = mergeInnerDocs(local, remote, makeCtx());

    expect(result.merged.schemaVersion).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// Describe: Counts semantics (D-16) — verify no negative counts
// ---------------------------------------------------------------------------

describe('counts non-negative (D-16)', () => {
  it('all counts are non-negative integers for any valid merge (D-16)', () => {
    const localEntry = makeEntry({ id: 'entry-count-001' });
    const remoteEntry = makeEntry({ id: 'entry-count-002' });
    const local = makeInnerDoc({ entries: [localEntry] });
    const remote = makeInnerDoc({ entries: [remoteEntry] });

    const result = mergeInnerDocs(local, remote, makeCtx());

    expect(result.counts.added).toBeGreaterThanOrEqual(0);
    expect(result.counts.updated).toBeGreaterThanOrEqual(0);
    expect(result.counts.deleted).toBeGreaterThanOrEqual(0);
    expect(result.counts.unchanged).toBeGreaterThanOrEqual(0);
    expect(Number.isInteger(result.counts.added)).toBe(true);
    expect(Number.isInteger(result.counts.updated)).toBe(true);
    expect(Number.isInteger(result.counts.deleted)).toBe(true);
    expect(Number.isInteger(result.counts.unchanged)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Describe: v3 field-parity (SYNCP-01, Phase 22)
//
// Phase 21 widened Entry with email/equivalentUrls/card/identity (schemaVersion 3).
// merge.ts hand-enumerates fields in deepCopyEntry/contentEqual/canonicalEntry/
// validateEntry — these fixtures prove all four sites recognize the new fields
// (no silent drop, no false-equal), while snapshotOf/meaningfulContentDiffers
// deliberately stay narrow (D-02/D-02a).
// ---------------------------------------------------------------------------

describe('v3 field-parity (SYNCP-01, Phase 22)', () => {
  it('one-sided-populate: remote-only entry with card/identity/email/equivalentUrls survives merge intact', () => {
    const remoteEntry = makeEntry({
      id: 'entry-v3-onesided-001',
      email: 'user@example.com',
      equivalentUrls: ['https://alt.example.com'],
      card: {
        cardholderName: 'Jane Doe',
        number: '4111111111111111',
        expiryMonth: '03',
        expiryYear: '2027',
        cvv: '123',
      },
      identity: {
        name: 'Jane Doe',
        email: 'jane@example.com',
        phone: '555-1234',
        address: '1 Example St',
      },
    });
    const local = makeInnerDoc({ schemaVersion: 3, entries: [] });
    const remote = makeInnerDoc({ schemaVersion: 3, entries: [remoteEntry] });

    const result = mergeInnerDocs(local, remote, makeCtx());

    const merged = result.merged.entries.find((e) => e.id === 'entry-v3-onesided-001');
    expect(merged).toBeDefined();
    expect(merged!.email).toBe('user@example.com');
    expect(merged!.equivalentUrls).toEqual(['https://alt.example.com']);
    expect(merged!.card).toEqual(remoteEntry.card);
    expect(merged!.identity).toEqual(remoteEntry.identity);
  });

  it('one-sided-populate: local-only entry with new fields survives merge intact', () => {
    const localEntry = makeEntry({
      id: 'entry-v3-onesided-002',
      email: 'local@example.com',
      equivalentUrls: ['https://alt2.example.com'],
      card: {
        cardholderName: 'Local Card',
        number: '5500000000000004',
        expiryMonth: '11',
        expiryYear: '2028',
        cvv: '999',
      },
    });
    const local = makeInnerDoc({ schemaVersion: 3, entries: [localEntry] });
    const remote = makeInnerDoc({ schemaVersion: 3, entries: [] });

    const result = mergeInnerDocs(local, remote, makeCtx());

    const merged = result.merged.entries.find((e) => e.id === 'entry-v3-onesided-002');
    expect(merged).toBeDefined();
    expect(merged!.email).toBe('local@example.com');
    expect(merged!.equivalentUrls).toEqual(['https://alt2.example.com']);
    expect(merged!.card).toEqual(localEntry.card);
  });

  it('no false-equal: two v3 entries identical except card.number, equal deviceId + modifiedAt, converge deterministically (not silently no-opped)', () => {
    const sharedId = 'entry-v3-diffcard-001';
    const tiedModifiedAt = new Date(EPOCH_BASE).toISOString();
    const localEntry = makeEntry({
      id: sharedId,
      modifiedAt: tiedModifiedAt,
      card: {
        cardholderName: 'Same Name',
        number: '4111111111111111',
        expiryMonth: '01',
        expiryYear: '2030',
        cvv: '111',
      },
    });
    const remoteEntry = makeEntry({
      id: sharedId,
      modifiedAt: tiedModifiedAt,
      card: {
        cardholderName: 'Same Name',
        number: '4222222222222222', // DIFFERS only here
        expiryMonth: '01',
        expiryYear: '2030',
        cvv: '111',
      },
    });
    const local = makeInnerDoc({ schemaVersion: 3, entries: [localEntry] });
    const remote = makeInnerDoc({ schemaVersion: 3, entries: [remoteEntry] });

    // Same deviceId on both sides forces the equal-modifiedAt path, which checks
    // contentEqual first (D-14 shortcut) — a false-equal here would silently
    // no-op the merge and drop one side's card number.
    const ctx = makeCtx({ localDeviceId: 'device-same', remoteDeviceId: 'device-same' });
    const result = mergeInnerDocs(local, remote, ctx);

    const merged = result.merged.entries.find((e) => e.id === sharedId);
    expect(merged).toBeDefined();
    const cardNumbers = [localEntry.card!.number, remoteEntry.card!.number];
    expect(cardNumbers).toContain(merged!.card!.number);

    // Determinism: repeated merges of the same inputs converge to the SAME winner.
    const result2 = mergeInnerDocs(local, remote, ctx);
    expect(result2.merged.entries.find((e) => e.id === sharedId)!.card!.number).toBe(
      merged!.card!.number,
    );
  });

  it('deep-copy-not-alias: mutating merged card/identity does not mutate the input entries', () => {
    const sharedId = 'entry-v3-deepcopy-001';
    const remoteEntry = makeEntry({
      id: sharedId,
      card: {
        cardholderName: 'Original',
        number: '4111111111111111',
        expiryMonth: '05',
        expiryYear: '2029',
        cvv: '321',
      },
      identity: {
        name: 'Original Name',
        email: 'orig@example.com',
        phone: '000',
        address: 'Somewhere',
      },
    });
    const local = makeInnerDoc({ schemaVersion: 3, entries: [] });
    const remote = makeInnerDoc({ schemaVersion: 3, entries: [remoteEntry] });

    const result = mergeInnerDocs(local, remote, makeCtx());
    const merged = result.merged.entries.find((e) => e.id === sharedId)!;

    merged.card!.number = 'MUTATED';
    merged.identity!.name = 'MUTATED';

    expect(remoteEntry.card!.number).toBe('4111111111111111');
    expect(remoteEntry.identity!.name).toBe('Original Name');
  });

  it('canonicalEntry tiebreak: equal-deviceId, equal-modifiedAt entries differing ONLY in a new field resolve deterministically', () => {
    const sharedId = 'entry-v3-canon-001';
    const tiedModifiedAt = new Date(EPOCH_BASE).toISOString();
    const localEntry = makeEntry({ id: sharedId, modifiedAt: tiedModifiedAt, email: 'aaa@example.com' });
    const remoteEntry = makeEntry({ id: sharedId, modifiedAt: tiedModifiedAt, email: 'zzz@example.com' });
    const local = makeInnerDoc({ schemaVersion: 3, entries: [localEntry] });
    const remote = makeInnerDoc({ schemaVersion: 3, entries: [remoteEntry] });
    const ctx = makeCtx({ localDeviceId: 'device-same', remoteDeviceId: 'device-same' });

    const result1 = mergeInnerDocs(local, remote, ctx);
    const result2 = mergeInnerDocs(local, remote, ctx);

    const merged1 = result1.merged.entries.find((e) => e.id === sharedId)!;
    const merged2 = result2.merged.entries.find((e) => e.id === sharedId)!;

    expect(merged1.email).toBe(merged2.email);
    expect(['aaa@example.com', 'zzz@example.com']).toContain(merged1.email);
  });

  it('validateEntry strictness: rejects malformed card/identity/equivalentUrls; accepts valid/absent', () => {
    const badCardShape = makeEntry({
      id: 'entry-bad-card-001',
      card: 'not an object' as unknown as EntryCard,
    });
    expect(() =>
      mergeInnerDocs(
        makeInnerDoc({ schemaVersion: 3, entries: [badCardShape] }),
        makeInnerDoc({ schemaVersion: 3, entries: [] }),
        makeCtx(),
      ),
    ).toThrow(expect.objectContaining({ code: 'MERGE_INVALID_INPUT' }));

    const badCardField = makeEntry({
      id: 'entry-bad-card-002',
      card: {
        cardholderName: 'X',
        number: 123 as unknown as string,
        expiryMonth: '01',
        expiryYear: '2030',
        cvv: '1',
      },
    });
    expect(() =>
      mergeInnerDocs(
        makeInnerDoc({ schemaVersion: 3, entries: [badCardField] }),
        makeInnerDoc({ schemaVersion: 3, entries: [] }),
        makeCtx(),
      ),
    ).toThrow(expect.objectContaining({ code: 'MERGE_INVALID_INPUT' }));

    const badIdentity = makeEntry({
      id: 'entry-bad-identity-001',
      identity: 'nope' as unknown as EntryIdentity,
    });
    expect(() =>
      mergeInnerDocs(
        makeInnerDoc({ schemaVersion: 3, entries: [badIdentity] }),
        makeInnerDoc({ schemaVersion: 3, entries: [] }),
        makeCtx(),
      ),
    ).toThrow(expect.objectContaining({ code: 'MERGE_INVALID_INPUT' }));

    const badUrls = makeEntry({
      id: 'entry-bad-urls-001',
      equivalentUrls: [42] as unknown as string[],
    });
    expect(() =>
      mergeInnerDocs(
        makeInnerDoc({ schemaVersion: 3, entries: [badUrls] }),
        makeInnerDoc({ schemaVersion: 3, entries: [] }),
        makeCtx(),
      ),
    ).toThrow(expect.objectContaining({ code: 'MERGE_INVALID_INPUT' }));

    // Valid card/identity + absent card/identity/email/equivalentUrls are BOTH accepted.
    const validEntry = makeEntry({
      id: 'entry-valid-001',
      card: { cardholderName: 'X', number: '1', expiryMonth: '01', expiryYear: '2030', cvv: '1' },
      identity: { name: 'X', email: 'x@x.com', phone: '1', address: 'x' },
    });
    const absentEntry = makeEntry({ id: 'entry-absent-fields-001' });
    expect(() =>
      mergeInnerDocs(
        makeInnerDoc({ schemaVersion: 3, entries: [validEntry, absentEntry] }),
        makeInnerDoc({ schemaVersion: 3, entries: [] }),
        makeCtx(),
      ),
    ).not.toThrow();
  });

  it('D-02a consistency: new-field-only diff does NOT produce a ConflictRecord (meaningfulContentDiffers stays narrow)', () => {
    const sharedId = 'entry-v3-d02a-001';
    const localEntry = makeEntry({
      id: sharedId,
      modifiedAt: new Date(EPOCH_PLUS_1H).toISOString(),
      email: 'local@example.com',
    });
    const remoteEntry = makeEntry({
      id: sharedId,
      modifiedAt: new Date(EPOCH_BASE).toISOString(), // older — local wins LWW
      email: 'remote@example.com', // differs ONLY in this new field vs local
    });
    const local = makeInnerDoc({ schemaVersion: 3, entries: [localEntry] });
    const remote = makeInnerDoc({ schemaVersion: 3, entries: [remoteEntry] });

    const result = mergeInnerDocs(local, remote, makeCtx());

    // All old meaningful fields (password/username/url/notes/title/tags) are identical
    // between local/remote here — only `email` differs. Per D-02a option (a), this
    // must NOT produce a conflict record (the snapshot cannot recover email anyway).
    const conflict = result.conflicts.find((c) => c.entryId === sharedId);
    expect(conflict).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Describe: schemaVersion ceiling guard (SYNCP-02, Phase 22)
//
// D-03: a KNOWN_SCHEMA_VERSIONS ceiling inside merge.ts, additive to (not a
// replacement of) the existing exact-equality gate (D-01).
// ---------------------------------------------------------------------------

describe('schemaVersion ceiling guard (SYNCP-02, Phase 22)', () => {
  it('mixed-version peer (D-01): local=2, remote=3 -> MergeSchemaMismatchError (exact-equality gate still fires)', () => {
    const local = makeInnerDoc({ schemaVersion: 2, entries: [] });
    const remote = makeInnerDoc({ schemaVersion: 3, entries: [] });

    expect(() => mergeInnerDocs(local, remote, makeCtx())).toThrow(
      expect.objectContaining({ code: 'MERGE_SCHEMA_MISMATCH' }),
    );
  });

  it('unknown-version ceiling: local=99 AND remote=99 (equal — would pass the OLD exact-equality gate) -> MergeSchemaMismatchError', () => {
    const local = makeInnerDoc({ schemaVersion: 99 as unknown as 1 | 2 | 3, entries: [] });
    const remote = makeInnerDoc({ schemaVersion: 99 as unknown as 1 | 2 | 3, entries: [] });

    expect(() => mergeInnerDocs(local, remote, makeCtx())).toThrow(
      expect.objectContaining({ code: 'MERGE_SCHEMA_MISMATCH' }),
    );
  });

  it('guard ordering: unknown schemaVersion 99 with a malformed entry throws the SCHEMA error, not invalid-input', () => {
    const malformedEntry = makeEntry({ id: '' }); // would throw MERGE_INVALID_INPUT if validated
    const local = makeInnerDoc({
      schemaVersion: 99 as unknown as 1 | 2 | 3,
      entries: [malformedEntry],
    });
    const remote = makeInnerDoc({ schemaVersion: 99 as unknown as 1 | 2 | 3, entries: [] });

    let thrown: unknown;
    try {
      mergeInnerDocs(local, remote, makeCtx());
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeDefined();
    expect((thrown as { code?: string }).code).toBe('MERGE_SCHEMA_MISMATCH');
  });
});

// ---------------------------------------------------------------------------
// Describe: totp field-parity + loss-sensitivity (TOTP-07, Phase 28) — THE GATE
//
// Proves all six re-derived merge/tombstone field-parity sites recognize the new
// `Entry.totp` field (no silent strip, no false-equal, deep-copy not alias), the
// schemaVersion ceiling widened to {1,2,3,4}, and — DELIBERATELY — that
// meaningfulContentDiffers/snapshotOf stay narrow (a totp-only diff → no conflict).
// ---------------------------------------------------------------------------

/** A non-default TOTP profile for fixtures. */
function makeTotp(overrides?: Partial<EntryTotp>): EntryTotp {
  return {
    secret: 'JBSWY3DPEHPK3PXP',
    algorithm: 'SHA256',
    digits: 8,
    period: 60,
    label: 'user@example.com',
    issuer: 'Example Corp',
    ...overrides,
  };
}

describe('totp field-parity + loss-sensitivity (TOTP-07, Phase 28)', () => {
  it('winner-keeps-totp (SC-2): totp-carrying side wins LWW and keeps the full totp object', () => {
    const sharedId = 'entry-totp-winner-001';
    const localEntry = makeEntry({
      id: sharedId,
      title: 'Winner With TOTP',
      totp: makeTotp(),
      modifiedAt: new Date(EPOCH_PLUS_1H).toISOString(), // newer -> wins LWW
    });
    const remoteEntry = makeEntry({
      id: sharedId,
      title: 'Loser No TOTP',
      modifiedAt: new Date(EPOCH_BASE).toISOString(), // older -> loses
    });
    const local = makeInnerDoc({ schemaVersion: 4, entries: [localEntry] });
    const remote = makeInnerDoc({ schemaVersion: 4, entries: [remoteEntry] });

    const result = mergeInnerDocs(local, remote, makeCtx());

    const merged = result.merged.entries.find((e) => e.id === sharedId);
    expect(merged).toBeDefined();
    expect(merged!.totp).toEqual(makeTotp());
  });

  it('one-sided-populate (SC-2): remote-only entry with totp survives the merge intact', () => {
    const remoteEntry = makeEntry({ id: 'entry-totp-onesided-001', totp: makeTotp() });
    const local = makeInnerDoc({ schemaVersion: 4, entries: [] });
    const remote = makeInnerDoc({ schemaVersion: 4, entries: [remoteEntry] });

    const result = mergeInnerDocs(local, remote, makeCtx());

    const merged = result.merged.entries.find((e) => e.id === 'entry-totp-onesided-001');
    expect(merged).toBeDefined();
    expect(merged!.totp).toEqual(makeTotp());
  });

  it('no-false-equal (SC-2): two entries differing ONLY in totp.secret (equal modifiedAt) are not collapsed; winner keeps its totp', () => {
    const sharedId = 'entry-totp-diff-001';
    const tiedModifiedAt = new Date(EPOCH_BASE).toISOString();
    const localEntry = makeEntry({
      id: sharedId,
      modifiedAt: tiedModifiedAt,
      totp: makeTotp({ secret: 'AAAAAAAAAAAAAAAA' }),
    });
    const remoteEntry = makeEntry({
      id: sharedId,
      modifiedAt: tiedModifiedAt,
      totp: makeTotp({ secret: 'ZZZZZZZZZZZZZZZZ' }),
    });
    const local = makeInnerDoc({ schemaVersion: 4, entries: [localEntry] });
    const remote = makeInnerDoc({ schemaVersion: 4, entries: [remoteEntry] });
    // Same deviceId forces the equal-modifiedAt path through the contentEqual (D-14)
    // shortcut — a false-equal there would silently drop one side's totp.secret.
    const ctx = makeCtx({ localDeviceId: 'device-same', remoteDeviceId: 'device-same' });

    const result = mergeInnerDocs(local, remote, ctx);

    const merged = result.merged.entries.find((e) => e.id === sharedId)!;
    expect(['AAAAAAAAAAAAAAAA', 'ZZZZZZZZZZZZZZZZ']).toContain(merged.totp!.secret);
    // Determinism: repeated merges converge to the same winner.
    const result2 = mergeInnerDocs(local, remote, ctx);
    expect(result2.merged.entries.find((e) => e.id === sharedId)!.totp!.secret).toBe(
      merged.totp!.secret,
    );
  });

  it('deep-copy-not-alias: mutating merged.totp.secret does not mutate the input entry', () => {
    const sharedId = 'entry-totp-deepcopy-001';
    const remoteEntry = makeEntry({ id: sharedId, totp: makeTotp({ secret: 'ORIGINAL12345678' }) });
    const local = makeInnerDoc({ schemaVersion: 4, entries: [] });
    const remote = makeInnerDoc({ schemaVersion: 4, entries: [remoteEntry] });

    const result = mergeInnerDocs(local, remote, makeCtx());
    const merged = result.merged.entries.find((e) => e.id === sharedId)!;
    merged.totp!.secret = 'MUTATED';

    expect(remoteEntry.totp!.secret).toBe('ORIGINAL12345678');
  });

  it('validateEntry strictness (T-28-01): rejects malformed totp; accepts valid/absent', () => {
    const badTotpShape = makeEntry({
      id: 'entry-bad-totp-001',
      totp: 'not an object' as unknown as EntryTotp,
    });
    expect(() =>
      mergeInnerDocs(
        makeInnerDoc({ schemaVersion: 4, entries: [badTotpShape] }),
        makeInnerDoc({ schemaVersion: 4, entries: [] }),
        makeCtx(),
      ),
    ).toThrow(expect.objectContaining({ code: 'MERGE_INVALID_INPUT' }));

    const badSecret = makeEntry({
      id: 'entry-bad-totp-002',
      totp: { secret: 123 as unknown as string, algorithm: 'SHA1', digits: 6, period: 30 },
    });
    expect(() =>
      mergeInnerDocs(
        makeInnerDoc({ schemaVersion: 4, entries: [badSecret] }),
        makeInnerDoc({ schemaVersion: 4, entries: [] }),
        makeCtx(),
      ),
    ).toThrow(expect.objectContaining({ code: 'MERGE_INVALID_INPUT' }));

    const badDigits = makeEntry({
      id: 'entry-bad-totp-003',
      totp: {
        secret: 'X',
        algorithm: 'SHA1',
        digits: 'six' as unknown as number,
        period: 30,
      },
    });
    expect(() =>
      mergeInnerDocs(
        makeInnerDoc({ schemaVersion: 4, entries: [badDigits] }),
        makeInnerDoc({ schemaVersion: 4, entries: [] }),
        makeCtx(),
      ),
    ).toThrow(expect.objectContaining({ code: 'MERGE_INVALID_INPUT' }));

    // Valid totp + absent totp are BOTH accepted.
    const validEntry = makeEntry({ id: 'entry-totp-valid-001', totp: makeTotp() });
    const absentEntry = makeEntry({ id: 'entry-totp-absent-001' });
    expect(() =>
      mergeInnerDocs(
        makeInnerDoc({ schemaVersion: 4, entries: [validEntry, absentEntry] }),
        makeInnerDoc({ schemaVersion: 4, entries: [] }),
        makeCtx(),
      ),
    ).not.toThrow();
  });

  it('isPermanentTombstone (T-28-02): a deleted entry with all login fields empty BUT a live totp is NOT permanent', () => {
    const softWithTotp = makeEntry({
      id: 'entry-totp-tombstone-001',
      title: '',
      username: '',
      password: '',
      url: '',
      notes: '',
      tags: [],
      passwordHistory: [],
      lostVersions: [],
      deletedAt: new Date(EPOCH_PLUS_30M).toISOString(),
      totp: makeTotp(),
    });
    expect(isPermanentTombstone(softWithTotp)).toBe(false);

    // Sanity: the same content-wiped entry WITHOUT totp IS a permanent marker.
    const permNoTotp = makeEntry({
      id: 'entry-totp-tombstone-002',
      title: '',
      username: '',
      password: '',
      url: '',
      notes: '',
      tags: [],
      passwordHistory: [],
      lostVersions: [],
      deletedAt: new Date(EPOCH_PLUS_30M).toISOString(),
    });
    expect(isPermanentTombstone(permNoTotp)).toBe(true);
  });

  it('v4-accepted (SC-2): a v4<->v4 merge proceeds (allowlist widened)', () => {
    const local = makeInnerDoc({ schemaVersion: 4, entries: [makeEntry({ id: 'e-v4-1' })] });
    const remote = makeInnerDoc({ schemaVersion: 4, entries: [] });
    expect(() => mergeInnerDocs(local, remote, makeCtx())).not.toThrow();
  });

  it('unknown-version ceiling (T-28-03): local=99 AND remote=99 -> MergeSchemaMismatchError', () => {
    const local = makeInnerDoc({ schemaVersion: 99 as unknown as InnerDoc['schemaVersion'], entries: [] });
    const remote = makeInnerDoc({ schemaVersion: 99 as unknown as InnerDoc['schemaVersion'], entries: [] });
    expect(() => mergeInnerDocs(local, remote, makeCtx())).toThrow(
      expect.objectContaining({ code: 'MERGE_SCHEMA_MISMATCH' }),
    );
  });

  it('guard ordering (T-28-03): unknown schemaVersion 99 with a malformed entry throws SCHEMA, not INVALID_INPUT', () => {
    const malformedEntry = makeEntry({ id: '' });
    const local = makeInnerDoc({
      schemaVersion: 99 as unknown as InnerDoc['schemaVersion'],
      entries: [malformedEntry],
    });
    const remote = makeInnerDoc({ schemaVersion: 99 as unknown as InnerDoc['schemaVersion'], entries: [] });

    let thrown: unknown;
    try {
      mergeInnerDocs(local, remote, makeCtx());
    } catch (e) {
      thrown = e;
    }
    expect((thrown as { code?: string }).code).toBe('MERGE_SCHEMA_MISMATCH');
  });

  it('loss-sensitivity (SC-4): a totp-only equal-modifiedAt diff produces NO ConflictRecord; winner keeps totp', () => {
    const sharedId = 'entry-totp-losssens-001';
    const tiedModifiedAt = new Date(EPOCH_BASE).toISOString();
    // Identical on ALL six meaningful old fields (password/username/url/notes/title/tags);
    // differ ONLY in totp. Per the deliberate D-02a/SC-4 exclusion, no conflict is recorded.
    const localEntry = makeEntry({
      id: sharedId,
      modifiedAt: tiedModifiedAt,
      totp: makeTotp({ secret: 'AAAAAAAAAAAAAAAA' }),
    });
    const remoteEntry = makeEntry({
      id: sharedId,
      modifiedAt: tiedModifiedAt,
      totp: makeTotp({ secret: 'ZZZZZZZZZZZZZZZZ' }),
    });
    const local = makeInnerDoc({ schemaVersion: 4, entries: [localEntry] });
    const remote = makeInnerDoc({ schemaVersion: 4, entries: [remoteEntry] });
    const ctx = makeCtx({ localDeviceId: 'device-same', remoteDeviceId: 'device-same' });

    const result = mergeInnerDocs(local, remote, ctx);

    // No conflict — totp is excluded from meaningfulContentDiffers/snapshotOf (SC-4).
    expect(result.conflicts.find((c) => c.entryId === sharedId)).toBeUndefined();
    // The deterministic winner still carries a totp (canonicalEntry-decided, not lost).
    const merged = result.merged.entries.find((e) => e.id === sharedId)!;
    expect(['AAAAAAAAAAAAAAAA', 'ZZZZZZZZZZZZZZZZ']).toContain(merged.totp!.secret);
  });
});
