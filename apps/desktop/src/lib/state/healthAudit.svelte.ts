// apps/desktop/src/lib/state/healthAudit.svelte.ts
//
// Session-scoped health-audit store: instant-fresh for small miss-sets, non-blocking
// chunked scan for large miss-sets (cold vault / bulk import).
//
// DESIGN INTENT (approved brainstorm — see 06-04-SUMMARY.md fix-forward section):
//
//   | Situation                            | What the user sees                             |
//   |--------------------------------------|------------------------------------------------|
//   | Return to Health after fixing entry  | INSTANT and FRESH — fix already reflected      |
//   | Re-open Health, nothing changed      | INSTANT — cached result reused                 |
//   | First open (cold, many unscored)     | Brief skeleton; fills in; UI stays clickable   |
//   | Right after bulk import              | Brief non-blocking refresh; UI stays clickable |
//
// The expensive work is zxcvbn-scoring NEW/CHANGED passwords, not re-running runAudit.
// The score cache (keyed by `id + modifiedAt`) means after fixing one entry only ONE
// password is uncached → scoring it is sub-millisecond → recompute synchronously.
// Chunked scan only fires when MANY passwords are uncached (cold/bulk).
//
// Module shape: mirrors clipboardGuard.svelte.ts — module-level bare `let` for
// non-reactive handles, `$state` for reactive display, exported functions + object.
// NO class.
//
// RULES (CLAUDE.md):
//   - $state.raw for the AuditResult (holds Entry refs with plaintext — Pitfall 7).
//   - $state (plain) for the `status` string (not secret data).
//   - NON-SECRET cache key: `${entry.id} ${entry.modifiedAt}` — NEVER the password.
//   - Do NOT import zxcvbn here — scorer is INJECTED so this module stays unit-testable
//     without the real dictionary bundles. Also decouples bulk from the scorer lifecycle.
//   - Do NOT import @tauri-apps/* — no IO in this module.
//   - No console.* of passwords or any secret data.
//   - weakScores Map passed to runAudit MUST be keyed by entry.id (core seam).

import type { Entry, AuditResult } from '@cryptiq/core';
import { runAudit, getVaultSettings } from '@cryptiq/core';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Maximum number of cache misses scored synchronously (pre-paint, no yield).
 *
 * At ≤ SYNC_THRESHOLD uncached entries the entire scoring + audit runs synchronously
 * before the browser paints, so the caller sees a fresh result with zero stale flash.
 * The critical case is 1 (user just fixed an entry → exactly one cache miss).
 *
 * Tune so synchronous pre-paint cost stays imperceptible (each zxcvbn call ≪ 1ms
 * with the dictionaries already loaded). 8 is conservative.
 */
const SYNC_THRESHOLD = 8;

/**
 * Number of entries scored per chunk in the async (large miss-set) path.
 * A yield (setTimeout 0) is awaited between chunks so the main thread stays responsive.
 */
const CHUNK_SIZE = 25;

// ---------------------------------------------------------------------------
// Score cache (non-reactive, NON-SECRET)
//
// Key: `${entry.id} ${entry.modifiedAt}` — NEVER the plaintext password.
// Value: integer zxcvbn score 0-4.
//
// Session-scoped: cleared on vault lock via clearHealthAudit().
// ---------------------------------------------------------------------------
let _scoreCache = new Map<string, number>();

// ---------------------------------------------------------------------------
// Reactive state
//
// `_result`: $state.raw — holds Entry refs with plaintext (Pitfall 7; never deep $state).
// `_status`: $state (plain) — a string status flag, never secret material.
// ---------------------------------------------------------------------------
let _result = $state.raw<AuditResult | null>(null);
let _status = $state<'idle' | 'scanning' | 'ready'>('idle');

// ---------------------------------------------------------------------------
// Cancellation token
//
// A generation counter increments each time a new scan starts (or a clear occurs).
// The async chunked loop captures the current generation and checks it after each
// chunk — if the generation advanced, the loop bails without writing result/status.
// ---------------------------------------------------------------------------
let _generation = 0;

// ---------------------------------------------------------------------------
// Internal helper: build weakScores Map keyed by entry.id from the cache
// (post-scoring, all active entries with non-empty passwords are cached).
// ---------------------------------------------------------------------------
function _buildWeakScores(entries: Entry[]): Map<string, number> {
  const weakScores = new Map<string, number>();
  for (const e of entries) {
    if (e.deletedAt === null && e.password.length > 0) {
      const key = `${e.id} ${e.modifiedAt}`;
      const score = _scoreCache.get(key);
      if (score !== undefined) {
        weakScores.set(e.id, score);
      }
    }
  }
  return weakScores;
}

// ---------------------------------------------------------------------------
// Exported API
// ---------------------------------------------------------------------------

/**
 * The exported healthAudit object mirrors the `ui` / `clipboardClear` pattern:
 * getter properties that read from module-level reactive state, making them
 * reactive across modules that import this singleton.
 */
export const healthAudit = {
  /** The current AuditResult, or null when idle / not yet computed. */
  get result(): AuditResult | null {
    return _result;
  },
  /** Current scan status. */
  get status(): 'idle' | 'scanning' | 'ready' {
    return _status;
  },
};

/**
 * Clear the score cache, result, status, and cancel any in-flight chunked scan.
 *
 * Called on vault lock (defense-in-depth: result holds Entry refs with plaintext;
 * clearing bounds memory and prevents stale data showing after re-unlock).
 * Idempotent — safe to call when nothing is active.
 */
export function clearHealthAudit(): void {
  _generation++; // invalidate any in-flight scan
  _scoreCache = new Map();
  _result = null;
  _status = 'idle';
}

/**
 * Orchestrate a fresh health audit, using the score cache to avoid re-scoring
 * unchanged entries.
 *
 * @param vault     The unlocked vault object (from vaultSession.vault).
 * @param scoreEntry Injected scorer: `(entry: Entry) => number` (0-4). Receives one
 *                   active entry with a non-empty password. Must NOT be called for
 *                   entries already in the cache. zxcvbn is the canonical scorer in
 *                   production; a fake scorer is used in unit tests.
 *
 * Score cache key is `${entry.id} ${entry.modifiedAt}` — NEVER the plaintext
 * password. weakScores passed to runAudit is keyed by entry.id (core seam).
 */
export async function ensureAuditFresh(
  vault: { entries: object } | null,
  scoreEntry: (entry: Entry) => number,
): Promise<void> {
  // Null vault = locked; nothing to audit.
  if (vault === null) {
    _generation++;
    _result = null;
    _status = 'idle';
    return;
  }

  // Capture this generation BEFORE any async work.
  // If clearHealthAudit() or a newer ensureAuditFresh() fires before we finish,
  // _generation will have advanced and our writes will be suppressed.
  const gen = ++_generation;

  // Extract active entries with non-empty passwords (the only ones that need scoring).
  const inner = vault.entries as { entries?: Entry[] };
  const allEntries: Entry[] = Array.isArray(inner.entries) ? inner.entries : [];
  const scoreable = allEntries.filter((e) => e.deletedAt === null && e.password.length > 0);

  // Determine cache misses: entries whose `id + modifiedAt` key is not in the cache.
  const misses = scoreable.filter((e) => !_scoreCache.has(`${e.id} ${e.modifiedAt}`));

  // Read stale threshold (single defaulted accessor).
  const staleThresholdDays = getVaultSettings(vault as Parameters<typeof getVaultSettings>[0]).audit?.staleThresholdDays ?? 365;

  // ── PATH A: No misses ────────────────────────────────────────────────────────
  // All active entries are cached → recompute runAudit from cached scores cheaply.
  // Result is instant and fresh (no new scoring needed).
  if (misses.length === 0) {
    const weakScores = _buildWeakScores(allEntries);
    if (gen !== _generation) return;
    _result = runAudit(allEntries, { weakScores, staleThresholdDays });
    _status = 'ready';
    return;
  }

  // ── PATH B: Small miss-set (≤ SYNC_THRESHOLD) ────────────────────────────────
  // Score synchronously before paint. The critical case is exactly 1 miss (user
  // just fixed one entry). This path guarantees zero stale-flag flash on fix-return.
  if (misses.length <= SYNC_THRESHOLD) {
    for (const e of misses) {
      const score = scoreEntry(e);
      _scoreCache.set(`${e.id} ${e.modifiedAt}`, score);
    }
    if (gen !== _generation) return;
    const weakScores = _buildWeakScores(allEntries);
    if (gen !== _generation) return;
    _result = runAudit(allEntries, { weakScores, staleThresholdDays });
    _status = 'ready';
    return;
  }

  // ── PATH C: Large miss-set (> SYNC_THRESHOLD) ────────────────────────────────
  // Set status='scanning'. Keep the prior result if present (non-blanking re-open).
  // Null → component shows a calm skeleton (cold open / bulk import).
  // Score misses in cancellable chunks; yield between chunks (main thread stays alive).
  _status = 'scanning';
  // DO NOT clear _result here — keep prior result visible if available.

  for (let i = 0; i < misses.length; i += CHUNK_SIZE) {
    // Check cancellation before each chunk.
    if (gen !== _generation) return;

    const chunk = misses.slice(i, i + CHUNK_SIZE);
    for (const e of chunk) {
      const score = scoreEntry(e);
      _scoreCache.set(`${e.id} ${e.modifiedAt}`, score);
    }

    // Yield between chunks so the main thread can paint / handle input.
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
  }

  // Final cancellation check after all chunks.
  if (gen !== _generation) return;

  const weakScores = _buildWeakScores(allEntries);
  if (gen !== _generation) return;

  _result = runAudit(allEntries, { weakScores, staleThresholdDays });
  _status = 'ready';
}
