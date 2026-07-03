// apps/extension/src/lib/contentScriptMessages.ts
//
// Single source of truth for the popup <-> content-script wire (17-RESEARCH.md
// Architecture Patterns Diagram). Mirrors bridgeRpc.ts's discriminated-union +
// exported-interface style: a message-type string union, a request/result
// pair per message type, and a locally-redeclared EntryMatchMetadata — NOT a
// `@cryptiq/core` import (apps/extension stays a thin client with no
// workspace dependency on core; Popup.svelte already redeclares this shape
// today, see its own comment at that call site).
//
// Every exported type here is structurally secret-free EXCEPT FillRequest,
// which is the sole, explicit, one-way secret-carrying message (popup ->
// content script only, fired on an explicit user click, per 17-CONTEXT.md
// D-01/D-04 and 16-CONTEXT.md BRIDGE-08 wire-minimization). No `DetectResult`,
// `FillResult`, or `EntryMatchMetadata` may ever gain a `password`/`secret`
// field — verified by `grep -L password` in this plan's acceptance criteria.

/** The three popup<->content-script message names (17-RESEARCH.md Architecture
 * Patterns Diagram: cryptiq-ping / cryptiq-detect / cryptiq-fill). */
export type ContentScriptMessageType = 'cryptiq-ping' | 'cryptiq-detect' | 'cryptiq-fill';

/** Result of a `cryptiq-detect` message: whether the content script found a
 * fillable field pair on the current page. No field contents, no secret. */
export interface DetectResult {
  ok: true;
  fieldsDetected: boolean;
}

/** The sole secret-carrying message on this wire: popup -> content script,
 * fired only on an explicit user click after `fill-entry` already returned
 * the secret over the authenticated bridge (bridgeRpc.ts). `expectedOrigin`
 * is the exact origin the popup captured when it fetched the match list —
 * the content script re-derives `location.origin` at fill time and refuses
 * on any mismatch (XSEC-03 TOCTOU + punycode-homograph guard). */
export interface FillRequest {
  type: 'cryptiq-fill';
  secret: string;
  username: string;
  expectedOrigin: string;
}

/** Result of a `cryptiq-fill` message. Fail-closed: any refusal reason is
 * explicit and typed, never a bare boolean. No field ever echoes the secret
 * back. */
export type FillResult = { ok: true } | { ok: false; reason: 'origin-mismatch' | 'no-field-found' };

/**
 * Metadata-only match shape, extended with the two optional HEALTH-02 health
 * flags (17-RESEARCH.md Open Question #1 — two separate booleans, resolved).
 * Deliberately mirrors `@cryptiq/core`'s `EntryMatchMetadata`
 * (packages/core/src/entries/matchByOrigin.ts) field-for-field WITHOUT
 * importing it — apps/extension holds no workspace dependency on
 * `@cryptiq/core` (thin-client boundary, CLAUDE.md). Structurally has no
 * `password`/`secret` field.
 */
export interface EntryMatchMetadata {
  id: string;
  title: string;
  username: string;
  domainHint: string;
  /** HEALTH-02: true when this entry's password scores below the `core`
   * audit engine's weak threshold. Computed app-side (rpcDispatch.ts),
   * never in the extension. */
  weak?: boolean;
  /** HEALTH-02: true when this entry's password value is reused by another
   * active entry. Computed app-side (rpcDispatch.ts), never in the extension. */
  reused?: boolean;
}
