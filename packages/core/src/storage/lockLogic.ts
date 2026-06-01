// packages/core/src/storage/lockLogic.ts
//
// VAULT-09 PURE LOCK-STATE EVALUATION SEAM.
//
// This module contains ONLY pure functions — no IO, no imports of @tauri-apps,
// node:fs, node:path, or libsodium. PID liveness is injected as a boolean from
// the Tauri caller, keeping the untestable OS syscall out of this module.
//
// The lock-decision logic (P3-08/P3-09/P3-10):
//   P3-08 — Session-held lock: acquired on vault unlock, held for session,
//            released on lock/quit, re-verified before each atomic write.
//   P3-09 — Same host, provably-stale (dead PID OR > 30 min old) → take over.
//            "Provably stale" because single-instance plugin prevents two live
//            same-machine Cryptiq processes; a fresh same-host lock is a crash leftover.
//   P3-10 — Cross-host fresh lock → warn + allow (user may edit on two devices at once).
//            Cross-host stale (> 30 min) → take over silently.
//
// Threat model note (T-03-01): a forged lockfile can influence the decision
// (warn → allow; stale → take-over), but the lock never contains secrets and
// the worst outcome is a spurious override — acceptable for advisory semantics.
//
// Source: CONTEXT.md P3-08/P3-09/P3-10 + 03-RESEARCH §Advisory Lock Detail

/** Shape of the `<vault>.lock` JSON file on disk. */
export interface LockFilePayload {
  pid: number;
  hostname: string;
  /** ISO 8601 timestamp of when this lock was acquired. */
  startedAt: string;
}

/**
 * Tagged decision returned by `evaluateLock`.
 *
 * | Decision              | Meaning                                                  |
 * |-----------------------|----------------------------------------------------------|
 * | `acquire-free`        | No existing lock (or unparseable) — safe to take it.    |
 * | `take-over-stale`     | Existing lock is provably stale — safe to override.     |
 * | `cross-host-warn`     | Existing fresh lock from another hostname — warn user.  |
 * | `locked-by-live`      | Live same-host lock — vault is in use; refuse.          |
 */
export type LockDecision =
  | { kind: 'acquire-free' }
  | { kind: 'take-over-stale'; reason: string }
  | { kind: 'cross-host-warn'; hostname: string }
  | { kind: 'locked-by-live'; pid: number; hostname: string };

/** Options for `evaluateLock`. */
export interface EvaluateLockOpts {
  /**
   * Whether the PID in the existing lock is still alive.
   * Supplied by the Tauri caller via platform-specific syscall so this module
   * stays pure (no OS imports). Ignored for cross-host locks.
   */
  pidIsAlive: boolean;
  /**
   * Current time as a Unix epoch in milliseconds.
   * Defaults to `Date.now()` if not supplied. Injected for testability.
   */
  nowMs?: number;
}

/** Stale threshold: 30 minutes in milliseconds. */
const STALE_THRESHOLD_MS = 30 * 60 * 1000;

/**
 * Return true if the lock's `startedAt` timestamp is more than 30 minutes old.
 *
 * @param startedAtIso ISO 8601 lock acquisition time.
 * @param nowMs        Current time in ms (defaults to Date.now()).
 */
export function isOlderThan30Min(startedAtIso: string, nowMs?: number): boolean {
  const now = nowMs ?? Date.now();
  const lockTime = new Date(startedAtIso).getTime();
  // If the timestamp is unparseable, NaN comparison → false (treat as fresh, not stale).
  if (Number.isNaN(lockTime)) return false;
  return now - lockTime > STALE_THRESHOLD_MS;
}

/**
 * Evaluate the lock acquisition decision (VAULT-09 pure seam).
 *
 * @param existing  The parsed existing lock payload, or `null` if no lock file exists /
 *                  the lock file was unparseable. `null` → `acquire-free`.
 * @param self      Identity of the current process: `{ hostname }`.
 *                  (PID is not needed here — it is embedded by the Tauri caller when
 *                  writing the new lock; only the existing lock's PID matters for liveness.)
 * @param opts      `{ pidIsAlive, nowMs? }` — injected by the Tauri caller.
 *
 * @returns A `LockDecision` indicating what the caller should do.
 */
export function evaluateLock(
  existing: LockFilePayload | null,
  self: { hostname: string },
  opts: EvaluateLockOpts,
): LockDecision {
  // No existing lock (or unparseable) → free to acquire.
  if (existing === null) {
    return { kind: 'acquire-free' };
  }

  const stale = isOlderThan30Min(existing.startedAt, opts.nowMs);

  if (existing.hostname === self.hostname) {
    // P3-09: Same machine. The single-instance plugin (decision 13) guarantees at most ONE
    // live Cryptiq process per host, so a same-host lock is always our OWN or a DEAD prior
    // instance — never a live peer. ALWAYS take over (UAT T5 fix). `opts.pidIsAlive` is no
    // longer consulted: it false-positived on OS PID reuse after a relaunch (and never
    // recognised our own PID), wedging unlock with a spurious "locked by another process".
    // The `locked-by-live` decision is retained in the union for API stability but is no
    // longer returned from the same-host path.
    const reason = stale
      ? `lock is older than 30 min (startedAt=${existing.startedAt})`
      : `same-host lock (pid ${existing.pid}) — single-instance guarantees no live peer`;
    return { kind: 'take-over-stale', reason };
  } else {
    // P3-10: Different hostname.
    if (stale) {
      // Cross-host stale → safe to take over.
      return {
        kind: 'take-over-stale',
        reason: `cross-host lock from ${existing.hostname} is older than 30 min (startedAt=${existing.startedAt})`,
      };
    }
    // Fresh cross-host lock → warn user but allow (advisory, non-blocking).
    return { kind: 'cross-host-warn', hostname: existing.hostname };
  }
}
