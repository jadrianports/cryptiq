// apps/extension/src/lib/popupFill.ts
//
// Plan 17-04: pure popup fill orchestration -- ensureContentScript
// (ping-then-inject, XSEC-01 never allFrames), recheckTabUnchanged (XSEC-03
// TOCTOU), buildPickerViewModel (FILL-05 + HEALTH-02 badge flags), and
// decideFillFlow (FILL-04/05/06 -- the 0/1/many + no-field decision). No
// Svelte import here -- Popup.svelte (Task 2) calls these directly, which
// lets FILL-04/05/06 + XSEC-01/03 be unit-tested in the DOM/fake-browser env
// without standing up Svelte-component browser-mode infra apps/extension
// lacks today (17-RESEARCH.md rationale).
//
// No crypto/audit logic here (CLAUDE.md thin-client boundary) -- this module
// only orchestrates chrome.* calls + shapes already-fetched metadata; it
// never touches a secret (the one secret-carrying field, `FillRequest.secret`,
// passes straight through Popup.svelte to chrome.tabs.sendMessage without
// ever being read or retained by this module).
//
// Source: 17-RESEARCH.md Architecture Patterns Diagram (steps 3, 7),
// §Common Pitfalls ("re-injecting a duplicate content script"),
// §iframe/Origin Refusal checkpoint 3; 17-CONTEXT.md D-01/D-02/D-04.

import type { EntryMatchMetadata } from './contentScriptMessages';

/**
 * XSEC-01, Pitfall "re-injecting a duplicate content script": idempotent
 * ping-then-inject. Pings first via `chrome.tabs.sendMessage` -- an existing
 * content-script listener answers synchronously and we do NOT re-inject
 * (idempotent, avoids duplicate MutationObservers/listeners on repeated
 * popup opens). Only on a caught rejection ("Could not establish
 * connection" -- no listener yet in this tab) do we inject via
 * `chrome.scripting.executeScript`, and `allFrames` is NEVER passed --
 * omitted defaults to `false`/top-frame-only per Chrome's own
 * `InjectionTarget` contract (XSEC-01/XSEC-03 satisfied structurally, not by
 * a runtime check that could have a bug). Fails closed to `false` on any
 * `executeScript` throw (e.g. a `chrome://` page) -- never guesses
 * injection succeeded.
 */
export async function ensureContentScript(tabId: number): Promise<boolean> {
  try {
    await chrome.tabs.sendMessage(tabId, { type: 'cryptiq-ping' });
    return true; // already injected -- idempotent, no re-inject
  } catch {
    // "Could not establish connection" -- no listener in this tab yet.
  }
  try {
    await chrome.scripting.executeScript({
      target: { tabId }, // allFrames deliberately OMITTED -- top frame only (XSEC-01)
      files: ['content-scripts/fill.js'], // WXT-generated runtime content-script output path
    });
    return true;
  } catch {
    return false; // e.g. a chrome:// page -- fail closed, never guess
  }
}

/**
 * XSEC-03 TOCTOU guard: re-query the active tab immediately before sending
 * the secret and confirm BOTH the tab id AND its origin are unchanged since
 * the match list was fetched (defense-in-depth against the tab navigating
 * away between "show picker" and "user clicks fill" -- 17-RESEARCH.md
 * "iframe/Origin Refusal" checkpoint 3). Returns `false` (refuse) on ANY
 * mismatch or lookup failure -- fails closed, never guesses.
 */
export async function recheckTabUnchanged(expectedTabId: number, expectedOrigin: string): Promise<boolean> {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || tab.id !== expectedTabId || !tab.url) return false;
    return new URL(tab.url).origin === expectedOrigin;
  } catch {
    return false;
  }
}

/** One picker row: order-preserving, structurally carries no password/secret
 * field (BRIDGE-08 wire-minimization carried through to the render layer). */
export interface PickerRow {
  id: string;
  title: string;
  username: string;
  weak: boolean;
  reused: boolean;
}

/**
 * FILL-05 + HEALTH-02: order-preserving map from `match-origin` candidates to
 * picker rows carrying the passive weak/reused badge flags. Candidates are
 * already app-side ordered (Phase 16 D-08 favorites/modifiedAt) and already
 * scoped to the current tab's origin (Phase 16 `matchByOrigin`) -- every
 * result rendered here IS, by construction, a "current-tab match"
 * (17-RESEARCH.md "Picker Ordering"), so this function does no reordering or
 * filtering of its own, only shaping. `weak`/`reused` default to `false`
 * when the candidate omits them (optional booleans on the wire type).
 */
export function buildPickerViewModel(candidates: EntryMatchMetadata[]): PickerRow[] {
  return candidates.map((c) => ({
    id: c.id,
    title: c.title,
    username: c.username,
    weak: c.weak ?? false,
    reused: c.reused ?? false,
  }));
}

export interface FillFlowInput {
  candidates: EntryMatchMetadata[];
  fieldsDetected: boolean;
}

export type FillFlowDecision =
  | { kind: 'no-matches'; fillAnyway: false }
  | { kind: 'single'; fillAnyway: boolean }
  | { kind: 'picker'; fillAnyway: boolean };

/**
 * FILL-04/05/06: the 0/1/many + no-field decision. `fillAnyway` is FILL-06's
 * explicit escape hatch -- true whenever `cryptiq-detect` reported no
 * fillable field on the current page, letting D-02's conservative field
 * detection stay conservative (a detection miss is never silently
 * over-fired; it falls back to a manual, popup-driven fill). `no-matches`
 * never sets `fillAnyway` -- with zero candidates there is no entry to fill
 * anyway.
 */
export function decideFillFlow({ candidates, fieldsDetected }: FillFlowInput): FillFlowDecision {
  const fillAnyway = !fieldsDetected;
  if (candidates.length === 0) return { kind: 'no-matches', fillAnyway: false };
  if (candidates.length === 1) return { kind: 'single', fillAnyway };
  return { kind: 'picker', fillAnyway };
}
