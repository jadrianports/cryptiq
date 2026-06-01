// packages/core/src/storage/__tests__/lockLogic.test.ts
//
// VAULT-09 pure lock-decision seam tests.
// ALL tests in this file pass against the Task-1 implementation — lockLogic.ts is
// a complete, pure implementation (no IO, no stubs).
//
// Decision table coverage (P3-08/P3-09/P3-10):
//   1. No existing lock → acquire-free
//   2. Same host, PID dead → take-over-stale
//   3. Same host, lock > 30 min old → take-over-stale
//   4. Same host, live PID, fresh lock → take-over-stale (single-instance: no live peer; UAT T5)
//   5. Cross-host, fresh lock → cross-host-warn
//   6. Cross-host, stale lock (> 30 min) → take-over-stale
//   7. Null existing (unparseable lock) → acquire-free
//   8. Same host, PID dead AND stale → take-over-stale (PID check takes precedence in message)
//
// Source: CONTEXT.md P3-08/P3-09/P3-10 + 03-RESEARCH §Advisory Lock Pseudocode

import { describe, it, expect } from 'vitest';
import {
  evaluateLock,
  isOlderThan30Min,
} from '../lockLogic';
import type { LockFilePayload } from '../lockLogic';

// ---- Helpers ----

const HOSTNAME_A = 'workstation-a';
const HOSTNAME_B = 'laptop-b';

/** Build a LockFilePayload with a startedAt offset from nowMs. */
function makePayload(
  hostname: string,
  pid: number,
  ageMs: number,
  nowMs: number,
): LockFilePayload {
  return {
    pid,
    hostname,
    startedAt: new Date(nowMs - ageMs).toISOString(),
  };
}

const NOW = 1_000_000_000_000; // fixed epoch for deterministic tests
const SELF = { hostname: HOSTNAME_A };

// ---------------------------------------------------------------------------
// isOlderThan30Min unit tests
// ---------------------------------------------------------------------------

describe('isOlderThan30Min', () => {
  it('returns false for a lock < 30 minutes old', () => {
    const startedAt = new Date(NOW - 29 * 60 * 1000).toISOString();
    expect(isOlderThan30Min(startedAt, NOW)).toBe(false);
  });

  it('returns true for a lock exactly 30+ minutes old', () => {
    const startedAt = new Date(NOW - 31 * 60 * 1000).toISOString();
    expect(isOlderThan30Min(startedAt, NOW)).toBe(true);
  });

  it('returns false for an unparseable timestamp (treat as fresh)', () => {
    expect(isOlderThan30Min('not-a-date', NOW)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// evaluateLock decision table
// ---------------------------------------------------------------------------

describe('evaluateLock', () => {
  // 1. No existing lock
  it('returns acquire-free when existing lock is null', () => {
    const result = evaluateLock(null, SELF, { pidIsAlive: false, nowMs: NOW });
    expect(result.kind).toBe('acquire-free');
  });

  // 2. Same host, PID dead
  it('returns take-over-stale when same-host PID is dead (fresh lock age)', () => {
    const existing = makePayload(HOSTNAME_A, 1234, 5 * 60 * 1000, NOW); // 5 min old
    const result = evaluateLock(existing, SELF, { pidIsAlive: false, nowMs: NOW });
    expect(result.kind).toBe('take-over-stale');
    if (result.kind === 'take-over-stale') {
      expect(result.reason).toContain('1234'); // reason mentions the dead PID
    }
  });

  // 3. Same host, lock > 30 min old (PID "alive" — age takes over)
  it('returns take-over-stale when same-host lock is older than 30 min', () => {
    const existing = makePayload(HOSTNAME_A, 9999, 35 * 60 * 1000, NOW); // 35 min old
    const result = evaluateLock(existing, SELF, { pidIsAlive: true, nowMs: NOW });
    expect(result.kind).toBe('take-over-stale');
    if (result.kind === 'take-over-stale') {
      expect(result.reason).toMatch(/30 min|startedAt/);
    }
  });

  // 4. Same host, live PID, fresh lock → take-over-stale (UAT T5: single-instance plugin
  //    guarantees no live same-host peer, so a same-host lock is always taken over —
  //    pidIsAlive is no longer consulted to avoid PID-reuse / self-PID false positives).
  it('takes over a same-host lock even when fresh and the PID appears alive (single-instance)', () => {
    const existing = makePayload(HOSTNAME_A, 5555, 10 * 60 * 1000, NOW); // 10 min old
    const result = evaluateLock(existing, SELF, { pidIsAlive: true, nowMs: NOW });
    expect(result.kind).toBe('take-over-stale');
    if (result.kind === 'take-over-stale') {
      expect(result.reason).toContain('5555'); // reason references the prior pid
    }
  });

  // 5. Cross-host, fresh lock → warn + allow
  it('returns cross-host-warn when different hostname with a fresh lock', () => {
    const existing = makePayload(HOSTNAME_B, 7777, 5 * 60 * 1000, NOW); // 5 min old
    const result = evaluateLock(existing, SELF, { pidIsAlive: false, nowMs: NOW });
    expect(result.kind).toBe('cross-host-warn');
    if (result.kind === 'cross-host-warn') {
      expect(result.hostname).toBe(HOSTNAME_B);
    }
  });

  // 6. Cross-host, stale lock → take over
  it('returns take-over-stale when cross-host lock is older than 30 min', () => {
    const existing = makePayload(HOSTNAME_B, 8888, 45 * 60 * 1000, NOW); // 45 min old
    const result = evaluateLock(existing, SELF, { pidIsAlive: false, nowMs: NOW });
    expect(result.kind).toBe('take-over-stale');
    if (result.kind === 'take-over-stale') {
      expect(result.reason).toContain(HOSTNAME_B);
    }
  });

  // 7. Null existing (unparseable lock file produces null at call-site)
  it('returns acquire-free for null (same as no lock)', () => {
    const result = evaluateLock(null, { hostname: HOSTNAME_B }, { pidIsAlive: true, nowMs: NOW });
    expect(result.kind).toBe('acquire-free');
  });

  // 8. Same host, both dead PID AND stale — still take-over-stale
  it('returns take-over-stale when same-host lock is both stale and PID dead', () => {
    const existing = makePayload(HOSTNAME_A, 1111, 60 * 60 * 1000, NOW); // 60 min old
    const result = evaluateLock(existing, SELF, { pidIsAlive: false, nowMs: NOW });
    expect(result.kind).toBe('take-over-stale');
  });

  // 9. Boundary: exactly at threshold is NOT yet stale (must be strictly greater than 30 min).
  //    Tested via the CROSS-HOST path, where staleness changes the outcome (same-host always
  //    takes over now, so the boundary is only observable cross-host: not-stale → warn).
  it('does not treat a lock at exactly 30 min as stale (edge case)', () => {
    const thirtyMin = makePayload(HOSTNAME_B, 2222, 30 * 60 * 1000, NOW); // cross-host, exactly 30 min
    const result = evaluateLock(thirtyMin, SELF, { pidIsAlive: false, nowMs: NOW });
    // 30 min exactly: age === threshold; NOT > threshold → NOT stale → fresh cross-host → warn.
    expect(result.kind).toBe('cross-host-warn');
  });
});
