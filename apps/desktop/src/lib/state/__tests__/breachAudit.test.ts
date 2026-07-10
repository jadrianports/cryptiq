// apps/desktop/src/lib/state/__tests__/breachAudit.test.ts
//
// Unit tests for breachAudit.svelte.ts — the session-scoped breach-sweep store.
//
// CRITICAL: only the injected HibpInvoke function is mocked (a vi.fn() fake passed
// into ensureBreachAuditFresh/retryUnknown). @cryptiq/core is NEVER mocked wholesale
// — the real sha1Hex/matchesSuffix/lookupHibpRange k-anonymity logic runs in every
// test below, exactly mirroring how the production hibpInvoke adapter is consumed.
//
// Scenarios covered (each maps to a Validation row in 31-RESEARCH.md):
//   1. HIBP-04/D-07 dedup — N entries sharing M distinct passwords cost exactly M calls.
//   2. D-09 never-cache-a-failure — a failed sweep never poisons the cache; a re-sweep
//      with no clear in between re-queries the same password.
//   3. D-06 per-group isolation — one dead group's failure marks only its own entries
//      unknown; other groups still resolve to safe/breached.
//   4. D-05 bounded concurrency — peak simultaneous in-flight invoke calls never
//      exceeds the concurrency constant (5).
//   5. Generation cancel (Pitfall 4) — clearBreachAudit() before a deferred invoke
//      resolves prevents it from writing into result/cache.
//   6. D-11 retry-only-unknowns — retryUnknown re-queries ONLY the currently-unknown
//      groups, not a full re-sweep.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { Entry, HibpInvoke } from '@cryptiq/core';
import { sha1Hex } from '@cryptiq/core';
import {
  breachAudit,
  ensureBreachAuditFresh,
  retryUnknown,
  clearBreachAudit,
  reconcileBreachAudit,
} from '../breachAudit.svelte';

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/** Create a minimal Entry conforming to the full Entry interface. */
function makeEntry(id: string, password: string): Entry {
  return {
    id,
    modifiedAt: '2024-01-01T00:00:00.000Z',
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
    createdAt: '2024-01-01T00:00:00.000Z',
    type: 'login',
  };
}

/** Wrap entries into a minimal vault-shaped object accepted by ensureBreachAuditFresh. */
function makeVault(entries: Entry[]) {
  return { entries: { entries } };
}

/** Never matches — HIBP range response with zero lines. */
const fakeInvokeAllSafe: HibpInvoke = async () => '';

/** Always rejects — simulates a fully offline/unreachable HIBP endpoint. */
const fakeInvokeAllFail: HibpInvoke = async () => {
  throw new Error('offline');
};

/** Builds a real HIBP-shaped match response for `password`'s true SHA-1 suffix. */
function realMatchResponseFor(password: string): string {
  const suffix = sha1Hex(password).slice(5);
  return `${suffix}:1\r\n`;
}

/** The 5-char prefix a given password's lookup will request (mirrors the real seam). */
function prefixFor(password: string): string {
  return sha1Hex(password).slice(0, 5);
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe('breachAudit — session-scoped breach-sweep store', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    clearBreachAudit();
  });

  afterEach(() => {
    clearBreachAudit();
  });

  // -------------------------------------------------------------------------
  // 1. HIBP-04/D-07 dedup
  // -------------------------------------------------------------------------

  it('N entries sharing M distinct passwords cost exactly M invoke calls', async () => {
    const invokeSpy = vi.fn(fakeInvokeAllSafe);
    const entries = [
      makeEntry('e1', 'shared-pw'),
      makeEntry('e2', 'shared-pw'),
      makeEntry('e3', 'shared-pw'),
      makeEntry('e4', 'unique-pw'),
    ]; // 4 entries, 2 distinct passwords

    await ensureBreachAuditFresh(makeVault(entries), invokeSpy);

    expect(invokeSpy).toHaveBeenCalledTimes(2);
    expect(breachAudit.result?.safe).toHaveLength(4);
    expect(breachAudit.status).toBe('ready');
    expect(breachAudit.hasSwept).toBe(true);
  });

  it('a real breach match is detected via the true SHA-1 suffix and cached (dedup on re-sweep)', async () => {
    const password = 'pwned-password-123';
    const invokeSpy = vi.fn(async (_cmd: string, args: { prefix: string }) => {
      if (args.prefix === prefixFor(password)) return realMatchResponseFor(password);
      return '';
    });
    const entries = [makeEntry('e1', password), makeEntry('e2', password)]; // 2 entries, 1 password

    await ensureBreachAuditFresh(makeVault(entries), invokeSpy);

    expect(invokeSpy).toHaveBeenCalledTimes(1);
    expect(breachAudit.result?.breached.map((e) => e.id).sort()).toEqual(['e1', 'e2']);

    // Re-sweep with the SAME vault, no clear in between → cache hit, zero new calls.
    await ensureBreachAuditFresh(makeVault(entries), invokeSpy);
    expect(invokeSpy).toHaveBeenCalledTimes(1);
  });

  // -------------------------------------------------------------------------
  // 2. D-09 never-cache-a-failure
  // -------------------------------------------------------------------------

  it('a failed lookup is never written to the cache — re-sweeping the same password re-queries it', async () => {
    const invokeSpy = vi.fn(fakeInvokeAllFail);
    const entries = [makeEntry('e1', 'pw-a')];

    await ensureBreachAuditFresh(makeVault(entries), invokeSpy); // sweep 1: fails
    expect(breachAudit.result?.unknown).toHaveLength(1);
    expect(breachAudit.result?.breached).toHaveLength(0);
    expect(breachAudit.result?.safe).toHaveLength(0);

    await ensureBreachAuditFresh(makeVault(entries), invokeSpy); // sweep 2: same password, NO clear

    expect(invokeSpy).toHaveBeenCalledTimes(2); // NOT 1 — proves nothing was cached from sweep 1
    expect(breachAudit.result?.unknown).toHaveLength(1);
  });

  // -------------------------------------------------------------------------
  // 3. D-06 per-group isolation
  // -------------------------------------------------------------------------

  it('one dead group is marked unknown while other groups still resolve normally', async () => {
    const safePassword = 'safe-pw';
    const failPassword = 'fail-pw';
    const failPrefix = prefixFor(failPassword);
    const invokeSpy = vi.fn(async (_cmd: string, args: { prefix: string }) => {
      if (args.prefix === failPrefix) throw new Error('timeout');
      return '';
    });
    const entries = [makeEntry('e1', safePassword), makeEntry('e2', failPassword)];

    await ensureBreachAuditFresh(makeVault(entries), invokeSpy);

    expect(breachAudit.result?.safe.map((e) => e.id)).toEqual(['e1']);
    expect(breachAudit.result?.unknown.map((e) => e.id)).toEqual(['e2']);
    expect(breachAudit.result?.breached).toEqual([]);
  });

  // -------------------------------------------------------------------------
  // 4. D-05 bounded concurrency
  // -------------------------------------------------------------------------

  it('never has more than 5 lookups in flight at once', async () => {
    let inFlight = 0;
    let peak = 0;
    const resolvers: Array<() => void> = [];
    const invokeSpy = vi.fn(async (_cmd: string, _args: { prefix: string }) => {
      inFlight++;
      peak = Math.max(peak, inFlight);
      await new Promise<void>((resolve) => {
        resolvers.push(() => {
          inFlight--;
          resolve();
        });
      });
      return '';
    });

    // 8 distinct passwords > concurrency (5) so at least one worker must wait.
    const entries = Array.from({ length: 8 }, (_, i) => makeEntry(`e${i}`, `pw-${i}`));
    const p = ensureBreachAuditFresh(makeVault(entries), invokeSpy);

    // The synchronous call chain (ensureBreachAuditFresh -> _sweep -> worker ->
    // lookupHibpRange -> invoke) reaches every initial worker's pending invoke call
    // before this statement returns control to the test — no flush needed here.
    expect(inFlight).toBeLessThanOrEqual(5);
    expect(inFlight).toBeGreaterThan(0);

    // Drain: resolve whatever is pending and flush microtasks until every group has
    // been queried exactly once and nothing remains in flight.
    let iterations = 0;
    while ((invokeSpy.mock.calls.length < 8 || inFlight > 0) && iterations < 100) {
      if (resolvers.length > 0) {
        const r = resolvers.shift();
        r?.();
      }
      await Promise.resolve();
      await Promise.resolve();
      await Promise.resolve();
      iterations++;
    }

    await p;

    expect(invokeSpy).toHaveBeenCalledTimes(8);
    expect(peak).toBeLessThanOrEqual(5);
    expect(peak).toBeGreaterThan(0);
  });

  // -------------------------------------------------------------------------
  // 5. Generation cancel (Pitfall 4) — lock mid-sweep suppresses stale writes
  // -------------------------------------------------------------------------

  it('clearBreachAudit() before a deferred invoke resolves prevents it from writing', async () => {
    // Boxed (not a bare `let`) so TS doesn't narrow the property to `null` across the
    // opaque ensureBreachAuditFresh() call — the closure below genuinely reassigns it
    // synchronously (same reasoning as the concurrency test), TS just can't see that.
    const box: { resolve: ((v: string) => void) | null } = { resolve: null };
    const deferredInvoke: HibpInvoke = () =>
      new Promise((resolve) => {
        box.resolve = resolve;
      });

    const entries = [makeEntry('e1', 'pw-a')];
    const p = ensureBreachAuditFresh(makeVault(entries), deferredInvoke);

    // By this point the synchronous call chain has already reached the pending
    // invoke() call and captured box.resolve (mirrors the concurrency test's
    // reasoning — no await needed to observe this).
    expect(box.resolve).not.toBeNull();

    clearBreachAudit(); // simulates a vault lock mid-sweep — bumps the generation

    box.resolve?.(''); // the stale lookup resolves AFTER the clear
    await p;

    expect(breachAudit.result).toBeNull();
    expect(breachAudit.status).toBe('idle');
    expect(breachAudit.hasSwept).toBe(false);
  });

  it('a second ensureBreachAuditFresh cancels the first — stale sweep does not overwrite the newer one', async () => {
    const box: { resolve: ((v: string) => void) | null } = { resolve: null };
    const deferredInvoke: HibpInvoke = () =>
      new Promise((resolve) => {
        box.resolve = resolve;
      });

    const staleEntries = [makeEntry('stale', 'pw-stale')];
    const p1 = ensureBreachAuditFresh(makeVault(staleEntries), deferredInvoke);
    expect(box.resolve).not.toBeNull();

    // Start a second, faster sweep before the first resolves — bumps the generation.
    const freshEntries = [makeEntry('fresh', 'pw-fresh')];
    const p2 = ensureBreachAuditFresh(makeVault(freshEntries), fakeInvokeAllSafe);
    await p2;

    // Now let the stale first sweep resolve — it must NOT clobber the fresh result.
    box.resolve?.('');
    await p1;

    expect(breachAudit.result?.safe.map((e) => e.id)).toEqual(['fresh']);
  });

  // -------------------------------------------------------------------------
  // 6. D-11 retry-only-unknowns
  // -------------------------------------------------------------------------

  it('retryUnknown re-queries ONLY the currently-unknown groups', async () => {
    const failPasswords = ['fail-1', 'fail-2', 'fail-3'];
    const failPrefixes = new Set(failPasswords.map(prefixFor));
    const invokeMixed = vi.fn(async (_cmd: string, args: { prefix: string }) => {
      if (failPrefixes.has(args.prefix)) throw new Error('timeout');
      return '';
    });

    const entries = [
      ...failPasswords.map((pw, i) => makeEntry(`fail-entry-${i}`, pw)),
      ...Array.from({ length: 7 }, (_, i) => makeEntry(`safe-entry-${i}`, `safe-pw-${i}`)),
    ]; // 10 total: 3 unknown, 7 safe
    const vault = makeVault(entries);

    await ensureBreachAuditFresh(vault, invokeMixed);
    expect(breachAudit.result?.unknown).toHaveLength(3);
    expect(breachAudit.result?.safe).toHaveLength(7);

    vi.clearAllMocks();
    const invokeNowSucceeds = vi.fn(fakeInvokeAllSafe);
    await retryUnknown(vault, invokeNowSucceeds);

    expect(invokeNowSucceeds).toHaveBeenCalledTimes(3); // ONLY the 3 unknown groups
    expect(breachAudit.result?.unknown).toHaveLength(0);
    expect(breachAudit.result?.safe).toHaveLength(10); // prior 7 preserved + 3 newly-resolved
    expect(breachAudit.status).toBe('ready');
  });

  it('retryUnknown is a no-op when there is no prior result', async () => {
    const invokeSpy = vi.fn(fakeInvokeAllSafe);
    await retryUnknown(makeVault([makeEntry('e1', 'pw-a')]), invokeSpy);
    expect(invokeSpy).not.toHaveBeenCalled();
    expect(breachAudit.result).toBeNull();
  });

  // -------------------------------------------------------------------------
  // 7. CR-01 reconcileBreachAudit — post-sweep additions surface as 'unknown',
  //    NEVER a network call, prior cached classifications stay intact.
  // -------------------------------------------------------------------------

  it('reconcileBreachAudit surfaces a post-sweep new entry as unknown, with NO invoke call', async () => {
    const invokeSpy = vi.fn(fakeInvokeAllSafe);
    const swept = [makeEntry('e1', 'pw-a'), makeEntry('e2', 'pw-b')];

    await ensureBreachAuditFresh(makeVault(swept), invokeSpy);
    expect(breachAudit.result?.safe.map((e) => e.id).sort()).toEqual(['e1', 'e2']);
    expect(breachAudit.result?.unknown).toHaveLength(0);
    expect(invokeSpy).toHaveBeenCalledTimes(2);

    vi.clearAllMocks(); // isolate the reconcile call below — must trigger ZERO new calls

    // A new entry added after the sweep, with an uncached password hash.
    const newEntry = makeEntry('e3', 'pw-never-swept');
    const vault2 = makeVault([...swept, newEntry]);

    reconcileBreachAudit(vault2);

    // NO network egress from reconcile (D-04) — the cache-miss routes to 'unknown'.
    expect(invokeSpy).not.toHaveBeenCalled();
    expect(breachAudit.result?.unknown.map((e) => e.id)).toEqual(['e3']);
    expect(breachAudit.result?.safe.map((e) => e.id).sort()).toEqual(['e1', 'e2']);
    expect(breachAudit.result?.breached).toEqual([]);
    // hasSwept/status are untouched by reconcile — still reflects the original sweep.
    expect(breachAudit.hasSwept).toBe(true);
    expect(breachAudit.status).toBe('ready');
  });

  it('reconcileBreachAudit is a no-op before the first sweep or mid-sweep', async () => {
    // Before any sweep at all — hasSwept is false.
    reconcileBreachAudit(makeVault([makeEntry('e1', 'pw-a')]));
    expect(breachAudit.result).toBeNull();

    // Mid-sweep (status === 'scanning') — must not clobber the streaming result.
    const box: { resolve: ((v: string) => void) | null } = { resolve: null };
    const deferredInvoke: HibpInvoke = () =>
      new Promise((resolve) => {
        box.resolve = resolve;
      });
    const entries = [makeEntry('e1', 'pw-a')];
    const p = ensureBreachAuditFresh(makeVault(entries), deferredInvoke);
    expect(box.resolve).not.toBeNull();
    expect(breachAudit.status).toBe('scanning');

    // Calling reconcile while scanning must not disturb the in-flight sweep's result.
    reconcileBreachAudit(makeVault(entries));
    expect(breachAudit.status).toBe('scanning');

    box.resolve?.('');
    await p;
    expect(breachAudit.result?.safe).toHaveLength(1);
  });
});
