// apps/extension/src/lib/captureFlow.ts
//
// Plan 19-02: pure capture-decision orchestration -- decideCaptureFlow
// (CAP-01, D-05/D-06 new/update/picker), shouldNudgeGenerate (HEALTH-01 weak-
// password nudge), and buildSaveParams (GEN-02 generated-value threading). No
// Svelte import here -- Popup.svelte calls these directly, which lets
// CAP-01/HEALTH-01/GEN-02 be unit-tested without standing up Svelte-component
// browser-mode infra apps/extension lacks today (mirrors popupFill.ts's
// decideFillFlow rationale, 17-RESEARCH.md).
//
// No crypto/audit logic here (CLAUDE.md thin-client boundary) -- this module
// only shapes already-fetched metadata and assembles a save-params object; it
// never calls chrome.* and never performs an RPC round trip itself.
//
// Source: 19-RESEARCH.md Pattern 3 (decideCaptureFlow target signature),
// Assumption A3 (no-username-match defaults to 'new'), Open Questions
// (RESOLVED) Q2 (known-domain-no-match -> save new, no picker); 19-PATTERNS.md
// § captureFlow.ts.

import type { EntryMatchMetadata } from './contentScriptMessages';

/**
 * CAP-01 / D-05 / D-06: the new/update/picker decision. Filters the
 * already-fetched, already-origin-scoped `match-origin` candidates down to
 * those whose username matches the captured username. Zero matches -> 'new'
 * (covers both a brand-new domain with zero candidates AND a known domain
 * with no username match -- resolved Open Question 2, both save-as-new with
 * no picker). Exactly one match -> 'update' with that entry's id. More than
 * one -> 'picker' with the matching candidates for the user to choose among.
 */
export type CaptureDecision =
  | { kind: 'new' }
  | { kind: 'update'; entryId: string }
  | { kind: 'picker'; candidates: EntryMatchMetadata[] };

export function decideCaptureFlow(candidates: EntryMatchMetadata[], capturedUsername: string): CaptureDecision {
  const matches = candidates.filter((c) => c.username === capturedUsername);
  if (matches.length === 0) return { kind: 'new' };
  if (matches.length === 1) return { kind: 'update', entryId: matches[0]!.id };
  return { kind: 'picker', candidates: matches };
}

/**
 * HEALTH-01: weak-password nudge threshold. zxcvbn scores run 0-4; a score
 * strictly below "good" (3) nudges the popup toward the Generate action
 * instead of saving the typed password as-is. The threshold is named/tunable
 * rather than inlined so future calibration doesn't require re-deriving the
 * boundary from a magic number.
 */
const WEAK_NUDGE_MAX_SCORE = 2;

export function shouldNudgeGenerate(score: number): boolean {
  return score <= WEAK_NUDGE_MAX_SCORE;
}

/**
 * GEN-02: the generated-value -> save-params threading seam. Assembles the
 * `save-or-update-entry` RPC params object (apps/desktop/src/lib/bridge/
 * rpcDispatch.ts's `{ mode, entryId?, title, username, password, url }`
 * shape) from the popup's local state, with `password` sourced from
 * whatever the popup currently holds -- a typed value or a freshly generated
 * one -- so a generated password is provably carried into the save call
 * unchanged. Pure assembler: no RPC call, no logging, no persistence.
 */
export interface BuildSaveParamsInput {
  mode: 'new' | 'update';
  entryId?: string;
  title: string;
  username: string;
  password: string;
  url: string;
}

export interface SaveParams {
  mode: 'new' | 'update';
  entryId?: string;
  title: string;
  username: string;
  password: string;
  url: string;
}

export function buildSaveParams(input: BuildSaveParamsInput): SaveParams {
  const params: SaveParams = {
    mode: input.mode,
    title: input.title,
    username: input.username,
    password: input.password,
    url: input.url,
  };
  if (input.entryId !== undefined) {
    params.entryId = input.entryId;
  }
  return params;
}
