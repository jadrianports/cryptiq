// apps/desktop/src/lib/zxcvbnSetup.ts
//
// Shared zxcvbn-ts lazy-singleton configuration + scoring helper (Phase 17
// Plan 02 / HEALTH-02).
//
// Extracted from StrengthMeter.svelte's former `<script module>` block so a
// plain, non-Svelte module (apps/desktop/src/lib/bridge/rpcDispatch.ts) can
// score passwords too, without a second/third copy of the zxcvbn-ts
// `setOptions()` call site. StrengthMeter.svelte and HealthView.svelte both
// delegate to this module instead of keeping their own lazy-singleton copy —
// behavior-identical consolidation, no render change, no scoring-value change.
//
// Plain .ts module: no Svelte, no Tauri, no @tauri-apps/* imports — safe to
// import from rpcDispatch.ts (a non-Svelte module) and from Svelte components
// alike.

import { zxcvbn, zxcvbnOptions } from '@zxcvbn-ts/core';
import * as zxcvbnCommon from '@zxcvbn-ts/language-common';
import * as zxcvbnEn from '@zxcvbn-ts/language-en';

let _configured = false;

/**
 * Configure zxcvbn-ts's language packs exactly once (idempotent — safe to
 * call on every score request; language packs are heavy, so the guard
 * matters for repeated calls, not correctness).
 */
export function ensureZxcvbnConfigured(): void {
  if (_configured) return;
  zxcvbnOptions.setOptions({
    translations: zxcvbnEn.translations,
    graphs: zxcvbnCommon.adjacencyGraphs,
    dictionary: {
      ...zxcvbnCommon.dictionary,
      ...zxcvbnEn.dictionary,
    },
  });
  _configured = true;
}

/**
 * Score a password 0-4 via zxcvbn-ts.
 *
 * Empty passwords default to 4 (not weak) — the same fail-safe default used
 * by `packages/core`'s `runAudit` for entries absent from `weakScores`
 * (AUDIT-03 / P6-08): never spuriously flag a password as weak when there is
 * nothing to score.
 */
export function scorePassword(password: string): number {
  ensureZxcvbnConfigured();
  return password.length > 0 ? zxcvbn(password).score : 4;
}
