// packages/core/src/audit/types.ts
//
// Health audit types — Phase 6 (P6-05 / AUDIT-01..05).
//
// `AuditOptions.weakScores` is the injection seam: apps/desktop scores each
// entry's password with zxcvbn-ts and passes the scores as a Map — core never
// imports zxcvbn-ts directly (ESLint no-restricted-imports + core-purity rule).
// Mirrors the `EvaluateLockOpts.pidIsAlive` injected-boolean pattern (P3-08).
//
// Source: CONTEXT.md P6-05 + 06-PATTERNS.md § audit/types.ts

import type { Entry } from '../entries/types';

/**
 * Injected options for `runAudit`.
 *
 * `weakScores` is populated by `apps/desktop` (zxcvbn-ts per-entry score 0–4).
 * Core reads it via `weakScores.get(entry.id) ?? 4` — entries absent from the
 * map default to 4 (very unguessable), which is the fail-safe direction: do not
 * spuriously flag passwords as weak when no score is available (P6-08 / T-06-10).
 */
export interface AuditOptions {
  /**
   * Map of entry ID → zxcvbn score (integer 0–4).
   *
   * Built by `apps/desktop` before calling `runAudit`. Core never imports zxcvbn.
   * Absent entry IDs default to 4 (not weak). (AUDIT-03 / P6-05 injection seam)
   */
  weakScores: Map<string, number>;

  /**
   * Days before a password is considered stale. Default: 365.
   * Configurable in Settings (AUDIT-04); persisted in `InnerDoc.settings.audit`.
   */
  staleThresholdDays: number;
}

/**
 * Result returned by `runAudit`.
 *
 * Each array contains references to the original `Entry` objects from the
 * decrypted vault — no copies are made. Tombstoned entries (`deletedAt !== null`)
 * are excluded from all four buckets (AUDIT-01).
 */
export interface AuditResult {
  /** Entries whose non-empty password value is shared with ≥ 1 other active entry. (AUDIT-02) */
  reused: Entry[];
  /** Entries whose injected zxcvbn score ≤ WEAK_THRESHOLD (2). (AUDIT-03) */
  weak: Entry[];
  /** Entries whose password age exceeds staleThresholdDays. (AUDIT-04) */
  stale: Entry[];
  /** Entries with `needsSiteUpdate === true`. (AUDIT-05) */
  needsUpdate: Entry[];
}
