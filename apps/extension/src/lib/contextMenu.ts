// apps/extension/src/lib/contextMenu.ts
//
// Plan 18-02 (UX-03): pure, Svelte-free context-menu helpers -- mirrors
// popupFill.ts's discipline (no crypto import, no chrome.* calls here, only
// shape-only/decision logic so it is directly unit-testable without a real
// browser or fake-browser harness). background.ts's contextMenus.onClicked
// handler calls these directly; neither helper ever touches a secret.
//
// Source: 18-RESEARCH.md Pattern 3/4, Pitfall 3 (frame-id refusal), Open
// Question 1 recommendation (a) (best-effort top candidate).

import type { EntryMatchMetadata } from './contentScriptMessages';

/**
 * XSEC-01 consistency (T-18-07): a context-menu click may originate inside a
 * cross-origin sub-frame (`frameId !== 0`). Refuse (top-frame only) exactly
 * like `ensureContentScript`'s `allFrames`-omitted injection already
 * structurally guarantees -- `frameId === undefined` (older Chrome versions
 * that don't report it) or `frameId === 0` (the top frame) both proceed;
 * any other frameId is refused.
 */
export function shouldRefuseFrame(frameId: number | undefined): boolean {
  return frameId !== undefined && frameId !== 0;
}

/** One top-candidate result: the two identifiers the context-menu fill flow
 * needs (`fill-entry`'s entryId + a best-effort username for the sibling
 * field) -- structurally carries no password/secret field. */
export interface TopCandidate {
  id: string;
  username: string;
}

/**
 * Open Question 1 recommendation (a): best-effort top candidate. `candidates`
 * already arrive in the app's own favorites/modifiedAt order (Phase 16 D-08)
 * -- this function does no reordering or filtering of its own, only picks
 * the first entry (or `null` for an empty list). Multi-match ambiguity is an
 * accepted, documented best-effort behavior (the popup remains the precise
 * picker surface for anything more deliberate).
 */
export function pickTopCandidate(candidates: EntryMatchMetadata[]): TopCandidate | null {
  if (candidates.length === 0) return null;
  const [first] = candidates;
  return { id: first.id, username: first.username };
}
