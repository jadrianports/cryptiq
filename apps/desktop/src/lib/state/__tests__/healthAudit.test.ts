// apps/desktop/src/lib/state/__tests__/healthAudit.test.ts
//
// Unit tests for healthAudit.svelte.ts — the session-scoped health-audit store.
//
// Test strategy (mirrors dialogGuard.test.ts):
//   - Node environment (vitest.config.ts: environment: 'node').
//   - @tauri-apps/api/core: vi.mock (not used by healthAudit, but import graph may need it).
//   - @cryptiq/core: vi.mock — runAudit and getVaultSettings are faked so tests run
//     without WASM / a real vault object. Injected scorer is a vi.fn — no real zxcvbn.
//   - vi.useFakeTimers() for the async chunked-scan path (controls setTimeout 0 yields).
//
// Scenarios covered:
//   A. Small miss-set (≤ SYNC_THRESHOLD): result is set synchronously (no yield needed).
//   B. Cache hit: injected scorer NOT called again for unchanged id+modifiedAt.
//   C. Changed modifiedAt: only the changed entry is re-scored.
//   D. Large miss-set: status transitions scanning → ready; scorer called for all misses;
//      result is set after all chunks; UI not blocked (fake timers drain cleanly).
//   E. clearHealthAudit(): empties cache + result; cancels in-flight scan (stale writes suppressed).
//   F. Cancellation: a second ensureAuditFresh during a large scan prevents the first
//      scan from overwriting the newer result.
//   G. Empty-password entries are not scored.
//   H. Tombstoned entries are not scored.
//   I. weakScores passed to runAudit is keyed by entry.id (not id+modifiedAt).
//   J. getVaultSettings is called with the vault; staleThresholdDays is forwarded.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ---------------------------------------------------------------------------
// Module mocks — hoisted by Vitest.
// ---------------------------------------------------------------------------

vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(),
}));

// We mock @cryptiq/core so that:
//   1. runAudit returns a deterministic fake result.
//   2. getVaultSettings returns a default settings object.
//   3. No WASM / real vault format needed.
vi.mock('@cryptiq/core', () => {
  const runAudit = vi.fn((_entries: unknown, _opts: unknown) => ({
    reused: [],
    weak: [],
    stale: [],
    needsUpdate: [],
  }));
  const getVaultSettings = vi.fn(() => ({
    audit: { staleThresholdDays: 365 },
  }));
  return { runAudit, getVaultSettings };
});

import type { Entry } from '@cryptiq/core';
import { runAudit, getVaultSettings } from '@cryptiq/core';
import {
  healthAudit,
  ensureAuditFresh,
  clearHealthAudit,
} from '../healthAudit.svelte';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/** Create a minimal Entry conforming to the full Entry interface. */
function makeEntry(id: string, modifiedAt: string, password = 'secret'): Entry {
  return {
    id,
    modifiedAt,
    password,
    deletedAt: null,
    title: `Entry ${id}`,
    username: '',
    url: '',
    notes: '',
    tags: [],
    favorite: false,
    needsSiteUpdate: false,
    generatorPreset: null,
    passwordHistory: [],
    createdAt: modifiedAt,
    type: 'login',
  };
}

/** Wrap entries into a minimal vault-shaped object accepted by ensureAuditFresh. */
function makeVault(entries: Entry[]) {
  return { entries: { entries } };
}

/** A default no-op scorer compatible with (entry: Entry) => number. */
function makeScorer(score = 3): (entry: Entry) => number {
  return vi.fn((_entry: Entry) => score) as (entry: Entry) => number;
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe('healthAudit — session-scoped health-audit store', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
    clearHealthAudit();
  });

  afterEach(() => {
    clearHealthAudit();
    vi.useRealTimers();
  });

  // -------------------------------------------------------------------------
  // A. Small miss-set (≤ SYNC_THRESHOLD) — synchronous, flash-free fix-return
  // -------------------------------------------------------------------------

  it('A: small miss-set → scorer called, result set, status=ready', async () => {
    const scorer = vi.fn((_e: Entry) => 1) as (entry: Entry) => number;
    const entry = makeEntry('e1', '2024-01-01');
    const vault = makeVault([entry]);

    await ensureAuditFresh(vault, scorer);

    expect(scorer).toHaveBeenCalledTimes(1);
    expect(scorer).toHaveBeenCalledWith(entry);
    expect(runAudit).toHaveBeenCalledTimes(1);
    expect(healthAudit.status).toBe('ready');
    expect(healthAudit.result).not.toBeNull();
  });

  it('A: 8 entries (= SYNC_THRESHOLD) → all scored, status=ready', async () => {
    const scorer = vi.fn((_e: Entry) => 3) as (entry: Entry) => number;
    const entries = Array.from({ length: 8 }, (_, i) => makeEntry(`e${i}`, '2024-01-01'));
    const vault = makeVault(entries);

    await ensureAuditFresh(vault, scorer);

    expect(scorer).toHaveBeenCalledTimes(8);
    expect(healthAudit.status).toBe('ready');
  });

  // -------------------------------------------------------------------------
  // B. Cache hit — injected scorer NOT called again for unchanged id+modifiedAt
  // -------------------------------------------------------------------------

  it('B: cache hit → scorer NOT called for unchanged entry', async () => {
    const scorer = vi.fn((_e: Entry) => 3) as (entry: Entry) => number;
    const entry = makeEntry('e1', '2024-01-01');
    const vault = makeVault([entry]);

    // First call: entry cached.
    await ensureAuditFresh(vault, scorer);
    expect(scorer).toHaveBeenCalledTimes(1);

    vi.clearAllMocks();

    // Second call: id+modifiedAt unchanged → cache hit, scorer NOT called.
    await ensureAuditFresh(vault, scorer);
    expect(scorer).not.toHaveBeenCalled();
    expect(runAudit).toHaveBeenCalledTimes(1); // runAudit still called (cheap rebuild)
    expect(healthAudit.status).toBe('ready');
  });

  it('B: 5 cached entries — second call scores none of them', async () => {
    const scorer = vi.fn((_e: Entry) => 3) as (entry: Entry) => number;
    const entries = Array.from({ length: 5 }, (_, i) => makeEntry(`e${i}`, '2024-01-01'));
    const vault = makeVault(entries);

    await ensureAuditFresh(vault, scorer);
    expect(scorer).toHaveBeenCalledTimes(5);

    vi.clearAllMocks();
    await ensureAuditFresh(vault, scorer);
    expect(scorer).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // C. Changed modifiedAt — only the changed entry is re-scored
  // -------------------------------------------------------------------------

  it('C: updated modifiedAt → only that entry re-scored on next call', async () => {
    const scorer = vi.fn((_e: Entry) => 3) as (entry: Entry) => number;
    const e1 = makeEntry('e1', '2024-01-01');
    const e2 = makeEntry('e2', '2024-01-01');
    const vault1 = makeVault([e1, e2]);

    // First call: both entries cached.
    await ensureAuditFresh(vault1, scorer);
    expect(scorer).toHaveBeenCalledTimes(2);

    vi.clearAllMocks();

    // Simulate user updating e2 (modifiedAt changes).
    const e2Updated = makeEntry('e2', '2024-06-01');
    const vault2 = makeVault([e1, e2Updated]);

    await ensureAuditFresh(vault2, scorer);

    // Only e2 re-scored (e1's cache key unchanged).
    expect(scorer).toHaveBeenCalledTimes(1);
    expect(scorer).toHaveBeenCalledWith(e2Updated);
  });

  it('C: same id with new modifiedAt → cache miss → re-scored', async () => {
    const scorer = vi.fn((_e: Entry) => 2) as (entry: Entry) => number;
    const e1 = makeEntry('e1', '2024-01-01');
    await ensureAuditFresh(makeVault([e1]), scorer);
    expect(scorer).toHaveBeenCalledTimes(1);
    vi.clearAllMocks();

    // Same id, new modifiedAt → cache miss.
    const e1v2 = makeEntry('e1', '2025-01-01');
    await ensureAuditFresh(makeVault([e1v2]), scorer);
    expect(scorer).toHaveBeenCalledTimes(1);
    expect(scorer).toHaveBeenCalledWith(e1v2);
  });

  // -------------------------------------------------------------------------
  // D. Large miss-set — async chunked scan; status scanning → ready
  // -------------------------------------------------------------------------

  it('D: large miss-set → status transitions scanning then ready after timers drain', async () => {
    const scorer = makeScorer(3);
    // 30 entries = 2 chunks (25+5); SYNC_THRESHOLD=8 → async path.
    const entries = Array.from({ length: 30 }, (_, i) => makeEntry(`e${i}`, '2024-01-01'));
    const vault = makeVault(entries);

    const p = ensureAuditFresh(vault, scorer);

    // Flush microtask queue; large-miss path sets status='scanning' synchronously.
    await Promise.resolve();
    expect(healthAudit.status).toBe('scanning');

    // Drain all async yields (setTimeout 0 between chunks).
    await vi.runAllTimersAsync();
    await p;

    expect(scorer).toHaveBeenCalledTimes(30);
    expect(runAudit).toHaveBeenCalledTimes(1);
    expect(healthAudit.status).toBe('ready');
    expect(healthAudit.result).not.toBeNull();
  });

  it('D: prior result preserved during large-scan refresh (non-blanking re-open)', async () => {
    const scorer = makeScorer(3);

    // Populate a result with a small vault first.
    const smallEntries = Array.from({ length: 3 }, (_, i) => makeEntry(`s${i}`, '2024-01-01'));
    await ensureAuditFresh(makeVault(smallEntries), scorer);
    const priorResult = healthAudit.result;
    expect(priorResult).not.toBeNull();

    vi.clearAllMocks();

    // Add 30 NEW entries (cache miss → large-miss async path).
    const bigEntries = [
      ...smallEntries,
      ...Array.from({ length: 30 }, (_, i) => makeEntry(`n${i}`, '2024-01-01')),
    ];
    const p = ensureAuditFresh(makeVault(bigEntries), makeScorer(3));

    await Promise.resolve(); // reach first yield

    // Prior result must still be visible while scanning (non-blanking).
    expect(healthAudit.result).toBe(priorResult);
    expect(healthAudit.status).toBe('scanning');

    await vi.runAllTimersAsync();
    await p;

    expect(healthAudit.status).toBe('ready');
  });

  // -------------------------------------------------------------------------
  // E. clearHealthAudit() — empties cache + result; cancels in-flight scan
  // -------------------------------------------------------------------------

  it('E: clearHealthAudit() resets result=null, status=idle', async () => {
    await ensureAuditFresh(makeVault([makeEntry('e1', '2024-01-01')]), makeScorer());
    expect(healthAudit.result).not.toBeNull();

    clearHealthAudit();

    expect(healthAudit.result).toBeNull();
    expect(healthAudit.status).toBe('idle');
  });

  it('E: clearHealthAudit() empties cache — same entry re-scored on next call', async () => {
    const scorer = makeScorer();
    const entry = makeEntry('e1', '2024-01-01');
    await ensureAuditFresh(makeVault([entry]), scorer);
    expect(scorer).toHaveBeenCalledTimes(1);

    clearHealthAudit();
    vi.clearAllMocks();

    // Cache empty → scored again.
    await ensureAuditFresh(makeVault([entry]), scorer);
    expect(scorer).toHaveBeenCalledTimes(1);
  });

  it('E: clearHealthAudit() during large scan → stale scan does NOT write result', async () => {
    const scorer = makeScorer();
    const entries = Array.from({ length: 30 }, (_, i) => makeEntry(`e${i}`, '2024-01-01'));
    const vault = makeVault(entries);

    const p = ensureAuditFresh(vault, scorer);
    await Promise.resolve(); // reach first yield

    clearHealthAudit(); // increments generation

    await vi.runAllTimersAsync();
    await p;

    // Stale scan must NOT write (generation mismatch).
    expect(healthAudit.result).toBeNull();
    expect(healthAudit.status).toBe('idle');
  });

  // -------------------------------------------------------------------------
  // F. Cancellation — second ensureAuditFresh cancels the first
  // -------------------------------------------------------------------------

  it('F: second ensureAuditFresh during large scan — first scan suppressed, second result wins', async () => {
    const entries1 = Array.from({ length: 30 }, (_, i) => makeEntry(`e${i}`, '2024-01-01'));
    const vault1 = makeVault(entries1);

    const p1 = ensureAuditFresh(vault1, makeScorer());
    await Promise.resolve(); // reach first yield in scan 1

    // Second call (small vault, sync path) increments generation → invalidates scan 1.
    const vault2 = makeVault([makeEntry('e-new', '2024-06-01')]);
    const p2 = ensureAuditFresh(vault2, makeScorer());

    await vi.runAllTimersAsync();
    await Promise.all([p1, p2]);

    expect(healthAudit.status).toBe('ready');
    expect(runAudit).toHaveBeenCalled();
    expect(healthAudit.result).not.toBeNull();
  });

  it('F: null vault during large scan → result is cleared', async () => {
    const entry = makeEntry('e1', '2024-01-01');
    await ensureAuditFresh(makeVault([entry]), makeScorer());
    expect(healthAudit.result).not.toBeNull();

    await ensureAuditFresh(null, makeScorer());

    expect(healthAudit.result).toBeNull();
    expect(healthAudit.status).toBe('idle');
  });

  // -------------------------------------------------------------------------
  // G. Entries with empty passwords — not scored
  // -------------------------------------------------------------------------

  it('G: entries with empty password are not scored', async () => {
    const scorer = makeScorer();
    const e1 = makeEntry('e1', '2024-01-01', ''); // empty password
    const e2 = makeEntry('e2', '2024-01-01', 'abc'); // non-empty
    const vault = makeVault([e1, e2]);

    await ensureAuditFresh(vault, scorer);

    expect(scorer).toHaveBeenCalledTimes(1);
    expect(scorer).toHaveBeenCalledWith(e2);
  });

  // -------------------------------------------------------------------------
  // H. Tombstoned entries — excluded from scoring
  // -------------------------------------------------------------------------

  it('H: tombstoned entries (deletedAt !== null) are not scored', async () => {
    const scorer = makeScorer();
    const active = makeEntry('e1', '2024-01-01');
    // Tombstone: spread active and override deletedAt to a string.
    const deleted: Entry = { ...makeEntry('e2', '2024-01-01'), deletedAt: '2024-03-01' };
    const vault = makeVault([active, deleted]);

    await ensureAuditFresh(vault, scorer);

    expect(scorer).toHaveBeenCalledTimes(1);
    expect(scorer).toHaveBeenCalledWith(active);
  });

  // -------------------------------------------------------------------------
  // I. runAudit weakScores keyed by entry.id (core seam contract)
  // -------------------------------------------------------------------------

  it('I: weakScores map passed to runAudit is keyed by entry.id (not id+modifiedAt)', async () => {
    const scorer = vi.fn((_e: Entry) => 1) as (entry: Entry) => number;
    const entry = makeEntry('my-uuid', '2024-01-01');
    const vault = makeVault([entry]);

    await ensureAuditFresh(vault, scorer);

    expect(runAudit).toHaveBeenCalledTimes(1);
    const [, opts] = (runAudit as ReturnType<typeof vi.fn>).mock.calls[0] as [
      unknown,
      { weakScores: Map<string, number> },
    ];
    expect(opts.weakScores).toBeInstanceOf(Map);
    // Key must be 'my-uuid', NOT 'my-uuid 2024-01-01'.
    expect(opts.weakScores.has('my-uuid')).toBe(true);
    expect(opts.weakScores.get('my-uuid')).toBe(1);
    expect(opts.weakScores.has('my-uuid 2024-01-01')).toBe(false);
  });

  // -------------------------------------------------------------------------
  // J. getVaultSettings called with the vault, staleThresholdDays passed through
  // -------------------------------------------------------------------------

  it('J: getVaultSettings is called with the vault to obtain staleThresholdDays', async () => {
    (getVaultSettings as ReturnType<typeof vi.fn>).mockReturnValue({
      audit: { staleThresholdDays: 180 },
    });

    const scorer = makeScorer();
    const entry = makeEntry('e1', '2024-01-01');
    const vault = makeVault([entry]);

    await ensureAuditFresh(vault, scorer);

    expect(getVaultSettings).toHaveBeenCalledWith(vault);
    const [, opts] = (runAudit as ReturnType<typeof vi.fn>).mock.calls[0] as [
      unknown,
      { staleThresholdDays: number },
    ];
    expect(opts.staleThresholdDays).toBe(180);
  });
});
