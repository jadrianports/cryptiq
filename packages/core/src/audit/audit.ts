// packages/core/src/audit/audit.ts
//
// Pure health-audit orchestration verb — Phase 6 (P6-05 / AUDIT-01..05).
//
// PURE: no network, no @tauri-apps/*, no svelte, no node:fs/path, no console.*.
// zxcvbn score is INJECTED via AuditOptions.weakScores (P3-08 seam precedent).
// Password age is derived via the existing derivePasswordAge helper (no re-implementation).
//
// WEAK_THRESHOLD = 2 is a module-level constant (not a parameter — P6-08 fixed cutoff).
//
// Source: CONTEXT.md P6-05/P6-08 + 06-PATTERNS.md § audit/audit.ts

import type { Entry } from '../entries/types';
import { derivePasswordAge } from '../entries/crud';
import type { AuditOptions, AuditResult } from './types';

/**
 * zxcvbn score threshold below which a password is considered weak.
 *
 * zxcvbn scale: 0 = too guessable, 1 = very guessable, 2 = somewhat guessable,
 * 3 = safely unguessable, 4 = very unguessable. Score ≤ 2 = "below good."
 *
 * Fixed at 2 (P6-08) — not user-configurable, unlike the stale threshold.
 */
const WEAK_THRESHOLD = 2;

/**
 * Run the health audit over a set of vault entries.
 *
 * Filters tombstones out first (`deletedAt === null` only), then classifies
 * active entries into four non-exclusive buckets:
 *
 * - **reused**: entries sharing a non-empty password with ≥ 1 other active entry. (AUDIT-02)
 * - **weak**: entries whose injected zxcvbn score ≤ 2 (absent → defaults to 4). (AUDIT-03)
 * - **stale**: entries whose `derivePasswordAge()` exceeds `opts.staleThresholdDays` × 86_400_000 ms. (AUDIT-04)
 * - **needsUpdate**: entries with `needsSiteUpdate === true`. (AUDIT-05)
 *
 * An entry may appear in multiple buckets simultaneously.
 *
 * Pure function — no IO, no side effects, no console.* (T-06-09 / AUDIT-01).
 *
 * @param entries   All entries from the decrypted vault (active + tombstones).
 * @param opts      Injected options: weakScores map + staleThresholdDays.
 * @returns         AuditResult with four Entry[] buckets (all references, no copies).
 */
export function runAudit(entries: Entry[], opts: AuditOptions): AuditResult {
  // Tombstone exclusion: operate only on active entries (AUDIT-01).
  const active = entries.filter((e) => e.deletedAt === null);

  // ---- AUDIT-02: Reused -------------------------------------------------------
  // Group active entries by password value. Entries with an empty password are
  // excluded from grouping (an empty password is not a "reused" password).
  const passwordGroups = new Map<string, Entry[]>();
  for (const e of active) {
    if (e.password.length > 0) {
      const existing = passwordGroups.get(e.password);
      if (existing !== undefined) {
        existing.push(e);
      } else {
        passwordGroups.set(e.password, [e]);
      }
    }
  }
  // An entry is "reused" when its group has more than one member.
  const reused = active.filter(
    (e) => e.password.length > 0 && (passwordGroups.get(e.password)?.length ?? 0) > 1,
  );

  // ---- AUDIT-03: Weak (injected score) ----------------------------------------
  // Absent entries default to 4 (not weak) — fail-safe toward not-spuriously-flagging
  // passwords whose score is unknown. (T-06-10 / P6-08)
  const weak = active.filter((e) => (opts.weakScores.get(e.id) ?? 4) <= WEAK_THRESHOLD);

  // ---- AUDIT-04: Stale --------------------------------------------------------
  // Password age uses the same derivePasswordAge helper as the rest of core —
  // single implementation, no re-derivation (key_link: audit.ts → crud.ts).
  const staleMs = opts.staleThresholdDays * 24 * 60 * 60 * 1000;
  const stale = active.filter((e) => derivePasswordAge(e) > staleMs);

  // ---- AUDIT-05: Needs site update --------------------------------------------
  const needsUpdate = active.filter((e) => e.needsSiteUpdate === true);

  return { reused, weak, stale, needsUpdate };
}
