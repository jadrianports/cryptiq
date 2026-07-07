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
 * on any mismatch (XSEC-03 TOCTOU + punycode-homograph guard).
 *
 * Phase 25 (CFILL-03, D-01/D-05): widened to a `kind`-discriminated union so
 * the same message carries card/identity secrets alongside the original
 * login shape. `kind` is an INNER discriminant — `type` stays the single
 * `'cryptiq-fill'` message type, so `ContentScriptMessageType`/
 * `KNOWN_MESSAGE_TYPES` (fill.content.ts) need no new entry. The `login`
 * variant is byte-compatible with the pre-Phase-25 shape (bare `secret`/
 * `username`) so no existing call site changes until Phase 26 touches the
 * popup send-side. The `card`/`identity` variants redeclare `EntryCard`/
 * `EntryIdentity` (packages/core/src/entries/types.ts, Phase 21 LOCKED)
 * field-for-field WITHOUT importing `@cryptiq/core` — same thin-client
 * boundary discipline as `EntryMatchMetadata` below (CLAUDE.md). All three
 * variants carry decrypted-upstream secrets crossing on this sole
 * click-gated fill message — never on the metadata wire. */
export type FillRequest =
  | { type: 'cryptiq-fill'; kind: 'login'; secret: string; username: string; expectedOrigin: string }
  | {
      type: 'cryptiq-fill';
      kind: 'card';
      card: {
        cardholderName: string;
        number: string;
        expiryMonth: string;
        expiryYear: string;
        cvv: string;
        brand?: string;
      };
      expectedOrigin: string;
    }
  | {
      type: 'cryptiq-fill';
      kind: 'identity';
      identity: { email: string; phone: string; address: string };
      expectedOrigin: string;
    };

/** Result of a `cryptiq-fill` message. Fail-closed: any refusal reason is
 * explicit and typed, never a bare boolean. No field ever echoes the secret
 * back. */
export type FillResult = { ok: true } | { ok: false; reason: 'origin-mismatch' | 'no-field-found' };

/**
 * Plan 19-02: the content-script -> background capture signal (CAP-01/CAP-04).
 * Fired on a detected form submit — NOT a fillable metadata type, and must
 * NEVER be conflated with `EntryMatchMetadata` below (which must stay
 * password-free). `password` here is a transient in-flight value: background.ts
 * buffers it via `captureBuffer.writeCapture` into `chrome.storage.session`
 * (memory-only, never disk) and never logs it. Exported standalone (NOT added
 * to `ContentScriptMessageType`, which is specifically the ping/detect/fill
 * request family) so background.ts (Plan 03) can type-discriminate on
 * `'cryptiq-capture'` alongside that separate union, mirroring how
 * `FillRequest`/`DetectResult` are their own exports.
 */
export interface CaptureMessage {
  type: 'cryptiq-capture';
  username: string;
  password: string;
  origin: string;
}

/**
 * Plan 18-02 (UX-03): the context-menu -> content-script focused-field fill
 * message. Distinct from `FillRequest` (which carries the popup's captured
 * `expectedOrigin` for an exact-origin TOCTOU refusal, XSEC-03) because a
 * context-menu click is itself the fresh user gesture on the SAME page --
 * but background.ts performs several native-messaging round trips
 * (ensureContentScript, match-origin, fill-entry / generate-password) between
 * the right-click and this DOM write, so the tab may have navigated in that
 * window (WR-02). `expectedOrigin` is the origin background.ts captured at
 * right-click time; `handleFillFocused` re-derives `location.origin` at write
 * time and refuses on any mismatch (same XSEC-03 TOCTOU discipline as
 * `FillRequest`). `username` is optional/best-effort (only sent when a sibling
 * username field was found by background.ts's own match-origin candidate).
 * Exported standalone (mirrors `CaptureMessage`'s precedent) rather than
 * folded into `ContentScriptMessageType`, which is specifically the
 * ping/detect/fill request family.
 */
export interface FillFocusedMessage {
  type: 'cryptiq-fill-focused';
  secret: string;
  expectedOrigin: string;
  username?: string;
}

/** Result of a `cryptiq-fill-focused` message. Fail-closed: mirrors
 * `FillResult`'s typed-refusal discipline -- never a bare boolean. */
export type FillFocusedResult = { ok: true } | { ok: false; reason: 'origin-mismatch' | 'no-field-found' };

/**
 * Metadata-only match shape, extended with the two optional HEALTH-02 health
 * flags (17-RESEARCH.md Open Question #1 — two separate booleans, resolved).
 * Deliberately mirrors `@cryptiq/core`'s `EntryMatchMetadata`
 * (packages/core/src/entries/matchByOrigin.ts) field-for-field WITHOUT
 * importing it — apps/extension holds no workspace dependency on
 * `@cryptiq/core` (thin-client boundary, CLAUDE.md).
 *
 * Phase 24 (RPC-02, D-01/D-02/D-02a): `type` and `email` mirror core's
 * widening field-for-field WITHOUT importing it. `type` is spelled out
 * inline (never `Entry['type']` — the extension does not import core's
 * `Entry` type) and is always present; `email` is optional, present only
 * when the source entry has one. Structurally has NO `password`/`secret`/
 * `card`/`identity`/`cvv`/`number`/`name`/`phone`/`address` field — this
 * type simply cannot carry a secret, mirroring the existing no-`password`
 * guarantee.
 */
export interface EntryMatchMetadata {
  id: string;
  title: string;
  username: string;
  domainHint: string;
  /** Entry type discriminator (Phase 24, RPC-02). Always present. Spelled
   * out inline — mirrors core's `Entry['type']` without importing it. */
  type: 'login' | 'card' | 'identity' | 'secure-note';
  /** Non-secret email identifier (Phase 24, RPC-02/D-01/D-02). Optional —
   * omitted entirely (never `email: undefined`) when the source entry has
   * none. */
  email?: string;
  /** HEALTH-02: true when this entry's password scores below the `core`
   * audit engine's weak threshold. Computed app-side (rpcDispatch.ts),
   * never in the extension. */
  weak?: boolean;
  /** HEALTH-02: true when this entry's password value is reused by another
   * active entry. Computed app-side (rpcDispatch.ts), never in the extension. */
  reused?: boolean;
}
