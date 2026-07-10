// apps/desktop/src/lib/state/breachAudit.svelte.ts
//
// Session-scoped breach-sweep store: the desktop-tier engine for HIBP-04 (cache/dedup)
// and HIBP-05 (fail-closed "unknown" state). Mirrors healthAudit.svelte.ts's five
// mechanics (injected side-effect, generation-counter cancellation, streaming work,
// $state.raw result, clear-on-lock) but owns a hash-keyed in-memory cache and a
// bounded-concurrency sweep instead of a zxcvbn scoring loop.
//
// DESIGN: this store is a desktop-tier OVERLAY, NOT a core AuditResult widening
// (31-RESEARCH.md section 3). The async, streaming, partially-complete lifecycle of a
// network sweep cannot ride the synchronous weakScores seam runAudit() expects. This
// module never touches packages/core/src/audit/ or any sync/InnerDoc surface.
//
// CACHE-KEY DEVIATION (read before touching this file):
//   The cache is keyed by `sha1Hex(entry.password)` — i.e. PASSWORD-DERIVED data used
//   as a Map key. This is permitted ONLY under three conditions (D-07/D-08):
//     1. It is the sanctioned Phase-30 hash, imported unchanged from `@cryptiq/core`
//        (no second SHA-1 source — see hibp/hash.ts's own header for why libsodium
//        can't provide this and why @noble/hashes/legacy is the one bent exception).
//     2. It stays in-memory only — a module-level `Map`, never serialized, never
//        written to disk, never sent anywhere but the 5-char PREFIX (computed inside
//        the LOCKED lookupHibpRange seam, not here).
//     3. It is cleared on vault lock via clearBreachAudit() (D-08).
//   NEVER console.* the hash (treat it as secret-adjacent) even though only 5 hex
//   chars of it ever leave the device — the full 40-char hash computed client-side is
//   still password-derived.
//
// FAIL-CLOSED CONTRACT (D-09, the load-bearing rule this whole module exists to prove):
//   A group whose lookupHibpRange call throws (HibpLookupError or anything else) is
//   recorded as `unknown` and its hash is NEVER written to `_cache`. A subsequent sweep
//   (or retryUnknown) re-queries it. Caching a failure as `false` would silently
//   coerce "we don't know" into "not breached" — exactly the defect HIBP-05 exists to
//   prevent.
//
// Module shape: mirrors healthAudit.svelte.ts — module-level bare `let` for
// non-reactive handles, `$state`/`$state.raw` for reactive display, exported
// functions + a getter object. NO class.

import type { Entry, HibpInvoke } from '@cryptiq/core';
import { lookupHibpRange, sha1Hex } from '@cryptiq/core';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Bounded concurrency (D-05: ~4-6 in flight, never unbounded, no retry inside the loop). */
const CONCURRENCY = 5;

// ---------------------------------------------------------------------------
// Result shape
// ---------------------------------------------------------------------------

export interface BreachAuditResult {
  breached: Entry[];
  unknown: Entry[];
  safe: Entry[];
}

// ---------------------------------------------------------------------------
// Hash cache (non-reactive, PASSWORD-DERIVED — see header comment)
//
// Key: sha1Hex(entry.password) — the full 40-char uppercase SHA-1 hex (D-07).
// Value: definitive breached(true)/safe(false). ONLY a resolved (non-throwing)
// lookupHibpRange result may write here (D-09) — a caught error NEVER writes.
//
// Session-scoped: cleared on vault lock via clearBreachAudit().
// ---------------------------------------------------------------------------
let _cache = new Map<string, boolean>();

// ---------------------------------------------------------------------------
// Reactive state
//
// `_result`: $state.raw — holds Entry refs with plaintext (Pitfall 7; never deep $state).
// `_status`: $state (plain) — a string status flag, never secret material.
// `_hasSwept`: $state (plain) — distinguishes "never swept this unlocked session" from
//              "swept at least once, showing cache" (D-04 — HealthView auto-runs the
//              sweep exactly once per unlocked session, not on every vault mutation).
// ---------------------------------------------------------------------------
let _result = $state.raw<BreachAuditResult | null>(null);
let _status = $state<'idle' | 'scanning' | 'ready'>('idle');
let _hasSwept = $state(false);

// ---------------------------------------------------------------------------
// Cancellation token
//
// A generation counter increments each time a new sweep starts (or a clear occurs).
// The bounded-concurrency worker pool captures the current generation and checks it
// BOTH before starting a lookup AND before writing its result (Pitfall 4 — a lock
// mid-sweep must stop every in-flight lookup from writing, not just between chunks,
// since D-05 streams results per-item rather than per-batch).
// ---------------------------------------------------------------------------
let _generation = 0;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Build a shallow-copied snapshot so $state.raw reactivity fires on reassignment. */
function _snapshotResult(breached: Entry[], safe: Entry[], unknown: Entry[]): BreachAuditResult {
  return { breached: [...breached], unknown: [...unknown], safe: [...safe] };
}

/**
 * Group active, non-empty-password entries by sha1Hex(password) (D-07: N entries
 * sharing one password cost exactly ONE request).
 */
function _groupByPasswordHash(entries: Entry[]): Map<string, Entry[]> {
  const groups = new Map<string, Entry[]>();
  for (const e of entries) {
    if (e.deletedAt !== null || e.password.length === 0) continue;
    const hash = sha1Hex(e.password);
    const bucket = groups.get(hash);
    if (bucket) {
      bucket.push(e);
    } else {
      groups.set(hash, [e]);
    }
  }
  return groups;
}

/**
 * Split `groups` into already-cached classification (breached/safe) and the
 * remaining uncached groups that need a live lookup. Cached groups are NEVER
 * `unknown` — a failure is never cached (D-09), so every cache hit is definitive.
 */
function _classifyGroups(groups: Map<string, Entry[]>): {
  breached: Entry[];
  safe: Entry[];
  uncached: [string, Entry[]][];
} {
  const breached: Entry[] = [];
  const safe: Entry[] = [];
  const uncached: [string, Entry[]][] = [];
  for (const [hash, entries] of groups) {
    if (_cache.has(hash)) {
      if (_cache.get(hash) === true) {
        breached.push(...entries);
      } else {
        safe.push(...entries);
      }
    } else {
      uncached.push([hash, entries]);
    }
  }
  return { breached, safe, uncached };
}

/**
 * Bounded-concurrency worker pool over `uncached` groups (D-05). Streams each
 * group's outcome into the (mutable, non-reactive) breached/safe/unknown arrays and
 * publishes a fresh $state.raw snapshot per item as it lands. No retry inside this
 * loop — a caller-invoked retryUnknown() runs a fresh, filtered pass (D-11).
 */
async function _sweep(
  uncached: [string, Entry[]][],
  invoke: HibpInvoke,
  gen: number,
  breached: Entry[],
  safe: Entry[],
  unknown: Entry[],
): Promise<void> {
  let cursor = 0;

  async function worker(): Promise<void> {
    while (cursor < uncached.length) {
      // Check BEFORE starting a lookup — a lock/clear/newer sweep already superseded us.
      if (gen !== _generation) return;
      const next = uncached[cursor++];
      if (next === undefined) return;
      const [hash, groupEntries] = next;

      let outcome: { failed: false; breached: boolean } | { failed: true };
      try {
        const isBreached = await lookupHibpRange(groupEntries[0]!.password, invoke);
        outcome = { failed: false, breached: isBreached };
      } catch {
        // HibpLookupError or anything else — routes to `unknown`, NEVER cached (D-09/D-06).
        outcome = { failed: true };
      }

      // Check AGAIN before writing — per-item staleness (Pitfall 4), not per-chunk.
      if (gen !== _generation) return;

      if (outcome.failed) {
        unknown.push(...groupEntries);
      } else {
        _cache.set(hash, outcome.breached);
        if (outcome.breached) {
          breached.push(...groupEntries);
        } else {
          safe.push(...groupEntries);
        }
      }

      _result = _snapshotResult(breached, safe, unknown);
    }
  }

  const workerCount = Math.min(CONCURRENCY, uncached.length);
  const workers = Array.from({ length: workerCount }, () => worker());
  await Promise.all(workers);
}

/** Extract active entries with non-empty passwords from a vault-shaped object. */
function _extractScoreable(vault: { entries: object }): Entry[] {
  const inner = vault.entries as { entries?: Entry[] };
  const allEntries: Entry[] = Array.isArray(inner.entries) ? inner.entries : [];
  return allEntries.filter((e) => e.deletedAt === null && e.password.length > 0);
}

// ---------------------------------------------------------------------------
// Exported API
// ---------------------------------------------------------------------------

/**
 * The exported breachAudit object mirrors healthAudit's getter-object pattern:
 * getter properties that read from module-level reactive state, reactive across
 * modules that import this singleton.
 */
export const breachAudit = {
  /** The current breach-sweep result, or null when idle / not yet computed. */
  get result(): BreachAuditResult | null {
    return _result;
  },
  /** Current sweep status. */
  get status(): 'idle' | 'scanning' | 'ready' {
    return _status;
  },
  /** True once a sweep has completed (or short-circuited to all-cached) this unlocked session. */
  get hasSwept(): boolean {
    return _hasSwept;
  },
};

/**
 * Clear the hash cache, result, status, hasSwept flag, and cancel any in-flight sweep.
 *
 * Called on vault lock (App.svelte's existing lock-cleanup $effect, alongside
 * clearHealthAudit()): releases Entry refs (plaintext) and bounds the password-derived
 * hash-cache lifetime to the unlocked session (D-08). Idempotent.
 */
export function clearBreachAudit(): void {
  _generation++; // invalidate any in-flight sweep
  _cache = new Map();
  _result = null;
  _status = 'idle';
  _hasSwept = false;
}

/**
 * Orchestrate a fresh breach sweep: group active entries by password hash, classify
 * already-cached groups instantly, then bounded-concurrency-sweep the rest, streaming
 * results into the reactive result as they land.
 *
 * @param vault      The unlocked vault object (from vaultSession.vault), or null (locked).
 * @param hibpInvoke Injected HibpInvoke — the production `hibpInvoke` adapter in prod,
 *                   a fake in tests. Never mock `@cryptiq/core` wholesale — only this
 *                   injected function — so the real sha1Hex/matchesSuffix k-anonymity
 *                   logic runs even in unit tests.
 */
export async function ensureBreachAuditFresh(
  vault: { entries: object } | null,
  hibpInvoke: HibpInvoke,
): Promise<void> {
  if (vault === null) {
    _generation++;
    _result = null;
    _status = 'idle';
    _hasSwept = false;
    return;
  }

  // Capture this generation BEFORE any async work — see clearBreachAudit()/Pitfall 4.
  const gen = ++_generation;

  const scoreable = _extractScoreable(vault);
  const groups = _groupByPasswordHash(scoreable);
  const { breached, safe, uncached } = _classifyGroups(groups);
  const unknown: Entry[] = [];

  if (gen !== _generation) return;
  _result = _snapshotResult(breached, safe, unknown);

  if (uncached.length === 0) {
    _status = 'ready';
    _hasSwept = true;
    return;
  }

  _status = 'scanning';
  // DO NOT clear _result here — the cached classification set above stays visible
  // while the uncached groups sweep (non-blanking, mirrors healthAudit PATH C).

  await _sweep(uncached, hibpInvoke, gen, breached, safe, unknown);

  if (gen !== _generation) return;
  _status = 'ready';
  _hasSwept = true;
}

/**
 * Synchronously reconcile the breach-sweep result against the CURRENT vault contents,
 * WITHOUT any network lookup (D-04 — the sweep itself stays session-once; this only
 * re-buckets entries using the existing hash cache).
 *
 * CR-01: an entry created or edited AFTER the one-time sweep is otherwise absent from
 * every bucket (not even `unknown`), which lets `isAllClear` render a false "All clear".
 * This re-derives breached/safe/unknown from `_cache` for the CURRENT entry set: a
 * cache hit routes to breached/safe as before; a cache MISS (new entry, or an edited
 * entry whose new password hash was never swept) routes to `unknown` — a cache miss is
 * definitionally "not yet checked", never "safe". No `lookupHibpRange`/`hibpInvoke` call
 * happens here — call sites MUST NOT re-arm a network sweep on every vault mutation
 * (that would violate the D-04 session-once egress budget).
 *
 * Self-guards: no-op before the first sweep (`!_hasSwept`) and no-op while a sweep is
 * actively streaming (`_status === 'scanning'`) so this never clobbers in-flight writes
 * from `_sweep`. Does not touch `_generation` — this performs no async work to cancel.
 *
 * @param vault The unlocked vault object (from vaultSession.vault), or null (locked).
 */
export function reconcileBreachAudit(vault: { entries: object } | null): void {
  if (vault === null || !_hasSwept || _status === 'scanning') return;

  const scoreable = _extractScoreable(vault);
  const groups = _groupByPasswordHash(scoreable);

  const breached: Entry[] = [];
  const safe: Entry[] = [];
  const unknown: Entry[] = [];

  for (const [hash, groupEntries] of groups) {
    if (_cache.has(hash)) {
      if (_cache.get(hash) === true) {
        breached.push(...groupEntries);
      } else {
        safe.push(...groupEntries);
      }
    } else {
      // Cache miss = not-yet-checked = unknown. NEVER a network lookup here.
      unknown.push(...groupEntries);
    }
  }

  _result = _snapshotResult(breached, safe, unknown);
}

/**
 * Re-query ONLY the currently-unknown groups (D-11) — never a full re-scan. No-op if
 * there is no result yet or the vault is locked.
 */
export async function retryUnknown(
  vault: { entries: object } | null,
  hibpInvoke: HibpInvoke,
): Promise<void> {
  if (vault === null || _result === null) return;

  const gen = ++_generation;

  const scoreable = _extractScoreable(vault);
  const unknownIds = new Set(_result.unknown.map((e) => e.id));
  const retryEntries = scoreable.filter((e) => unknownIds.has(e.id));
  const groups = _groupByPasswordHash(retryEntries);

  // The unknown set is, by construction (D-09), never in `_cache` — every group here
  // genuinely needs a live lookup. No re-classification pass needed.
  const uncached: [string, Entry[]][] = [...groups.entries()];

  // Preserve the prior breached/safe classification; rebuild `unknown` fresh from this pass.
  const breached = [..._result.breached];
  const safe = [..._result.safe];
  const unknown: Entry[] = [];

  if (gen !== _generation) return;
  _result = _snapshotResult(breached, safe, unknown);
  _status = 'scanning';

  if (uncached.length === 0) {
    if (gen !== _generation) return;
    _status = 'ready';
    return;
  }

  await _sweep(uncached, hibpInvoke, gen, breached, safe, unknown);

  if (gen !== _generation) return;
  _status = 'ready';
}
