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

import type { EntryMatchMetadata, FillRequest } from './contentScriptMessages';

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
 * field (BRIDGE-08 wire-minimization carried through to the render layer).
 * Phase 26 (D-04): widened with the metadata's always-present `type` (the
 * row's `type` is NEVER the fill dispatch authority -- D-03 -- it only lets
 * `handleFillClick` thread the login identifiers; forward-compat for Phase
 * 27's entry-type iconography) and an optional `email` (login identifier,
 * IDENT-02). */
export interface PickerRow {
  id: string;
  title: string;
  username: string;
  type: EntryMatchMetadata['type'];
  email?: string;
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
 * Phase 26 (D-04): `type` threads through as required; `email` via
 * conditional spread (exactOptionalPropertyTypes -- never a literal
 * candidate-to-key assignment, which would assign `undefined` itself).
 */
export function buildPickerViewModel(candidates: EntryMatchMetadata[]): PickerRow[] {
  return candidates.map((c) => {
    const email = c.email;
    return {
      id: c.id,
      title: c.title,
      username: c.username,
      type: c.type,
      ...(email !== undefined ? { email } : {}),
      weak: c.weak ?? false,
      reused: c.reused ?? false,
    };
  });
}

/** One `search-entries` result row exactly as the RPC returns it (Plan 18-01)
 * -- structurally carries no password field (BRIDGE-08 wire minimization).
 * Phase 26 (D-06/D-04): optional `email` -- the desktop `search-entries`
 * handler now sources it per-type (26-02), mirroring `match-origin`'s
 * `EntryMatchMetadata.email?` discipline. */
export interface SearchEntryResult {
  id: string;
  title: string;
  username: string;
  currentTab: boolean;
  email?: string;
}

/** One search-result display row -- 1:1 with `SearchEntryResult` today, kept
 * as its own type (mirroring `PickerRow`'s separation from
 * `EntryMatchMetadata`) so the render layer depends on a view-model type, not
 * the wire type, even though the shapes currently match exactly. Phase 26
 * (D-04): optional `email`, threaded from `SearchEntryResult.email`. */
export interface SearchRow {
  id: string;
  title: string;
  username: string;
  currentTab: boolean;
  email?: string;
}

/**
 * UX-01: order-preserving map from `search-entries` results to display rows.
 * Mirrors `buildPickerViewModel`'s shape-only, no-reorder/no-filter
 * discipline -- the RPC already ordered current-tab-first (18-01's stable
 * sort), so this function does no reordering or filtering of its own, only
 * shaping. An empty `results` array maps to an empty `rows` array (drives the
 * "No matches"/"No saved logins yet." empty states in Popup.svelte). Phase 26
 * (D-04): `email` threaded via conditional spread (exactOptionalPropertyTypes).
 */
export function buildSearchViewModel(results: SearchEntryResult[]): SearchRow[] {
  return results.map((r) => {
    const email = r.email;
    return {
      id: r.id,
      title: r.title,
      username: r.username,
      currentTab: r.currentTab,
      ...(email !== undefined ? { email } : {}),
    };
  });
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

/** The `fill-entry` RPC's decrypted, discriminated response shape (Phase 24,
 * LOCKED). Redeclared here (not imported from core -- thin-client boundary)
 * as the input `buildFillRequest` consumes -- mirrors `FillRequest`'s own
 * `card`/`identity` field shapes field-for-field. */
export type FillEntryPayload =
  | { type: 'login'; secret: string }
  | {
      type: 'card';
      card: {
        cardholderName: string;
        number: string;
        expiryMonth: string;
        expiryYear: string;
        cvv: string;
        brand?: string;
      };
    }
  | { type: 'identity'; identity: { email: string; phone: string; address: string } };

/**
 * CFILL-04/D-03: pure dispatch seam -- given the fresh, decrypted `fill-entry`
 * RPC payload (the dispatch AUTHORITY per D-03, never a row's possibly-drifted
 * `EntryMatchMetadata.type`) and the login identifiers threaded from the
 * clicked row (D-04), builds the matching `kind`-tagged `FillRequest`. No
 * Svelte import, no `chrome.*` call, no `$state` -- unit-testable without
 * standing up Popup.svelte's browser-mode infra (17-RESEARCH.md precedent).
 * `email` is conditionally spread (omit-key-when-absent, exactOptionalPropertyTypes)
 * -- never `email: identifiers.email`.
 */
export function buildFillRequest(
  payload: FillEntryPayload,
  identifiers: { username: string; email?: string },
  expectedOrigin: string,
): FillRequest {
  if (payload.type === 'login') {
    return {
      type: 'cryptiq-fill',
      kind: 'login',
      secret: payload.secret,
      username: identifiers.username,
      ...(identifiers.email !== undefined ? { email: identifiers.email } : {}),
      expectedOrigin,
    };
  }
  if (payload.type === 'card') {
    return { type: 'cryptiq-fill', kind: 'card', card: payload.card, expectedOrigin };
  }
  return { type: 'cryptiq-fill', kind: 'identity', identity: payload.identity, expectedOrigin };
}
