// apps/extension/entrypoints/fill.content.ts
//
// FILL-01/02/04/06, XSEC-01/02/03: registration:'runtime' content script --
// registered ONLY on-demand via chrome.scripting.executeScript from the
// popup's activeTab gesture (Plan 17-04); NEVER declared in the manifest's
// content_scripts block, so it does not run on every page load (XSEC-04).
// Injection always targets the tab's TOP FRAME ONLY (allFrames omitted at
// the popup's executeScript call site, Plan 17-04) -- this content script
// therefore never runs inside any iframe, structurally satisfying XSEC-01
// (cross-origin-iframe refusal here is an ABSENCE of a code path, not a
// runtime check that could have a bug).
//
// Renders NO in-page DOM -- no attachShadow, no visible node
// appendChild/insertBefore anywhere in this file (D-01/XSEC-02: the popup is
// the ONLY clickable trigger surface; there is nothing here for Marek
// Toth's Jan-2026 clickjacking technique to disguise/click).
//
// cryptiq-fill's FIRST action is an EXACT `location.origin` compare against
// `expectedOrigin` (the origin the popup captured when it fetched the match
// list) -- refuses (writes NOTHING) on ANY mismatch, closing both the
// punycode/homograph class and the TOCTOU window between "show picker" and
// "user clicks fill" (XSEC-03). `location.origin` is already the browser's
// own ASCII/punycode-normalized form -- no PSL/IDNA/tldts import here, and
// none needed (do NOT import registrableHost/tldts into this file).
//
// Every response is a typed, fail-closed `{ok, ...}` shape (mirrors
// bridgeRpc.ts's discriminated-result convention and background.ts's
// type-discriminated onMessage dispatch idiom) -- this handler NEVER throws
// across the chrome.runtime.onMessage boundary.
//
// No window.addEventListener('message', ...) bridge exists in this file --
// chrome.runtime.onMessage only ever receives messages from the extension's
// own contexts (popup/background), a platform guarantee; adding a page-
// message bridge would reopen the fake-message spoofing class this design
// deliberately avoids (17-RESEARCH.md Security Domain).
//
// Source: 17-RESEARCH.md Architecture Patterns Diagram / Code Examples,
// 17-CONTEXT.md D-01/D-02/D-03.

import type {
  CaptureMessage,
  DetectResult,
  FillFocusedMessage,
  FillFocusedResult,
  FillRequest,
  FillResult,
} from '../src/lib/contentScriptMessages';
import { scanForCardFields, scanForIdentityFields, scanForLoginFields } from '../src/lib/fieldDetection';
import { fillField, fillSelectField, formatExpiryForField, isFieldVisible } from '../src/lib/domFill';

const OBSERVER_DEBOUNCE_MS = 250; // 17-RESEARCH.md MutationObserver Pattern: ~200-300ms window.

interface PingMessage {
  type: 'cryptiq-ping';
}
interface DetectMessage {
  type: 'cryptiq-detect';
}
type IncomingMessage = PingMessage | DetectMessage | FillRequest | FillFocusedMessage;

const KNOWN_MESSAGE_TYPES = new Set(['cryptiq-ping', 'cryptiq-detect', 'cryptiq-fill', 'cryptiq-fill-focused']);

function isKnownMessage(value: unknown): value is IncomingMessage {
  return typeof value === 'object' && value !== null && KNOWN_MESSAGE_TYPES.has((value as { type?: unknown }).type as string);
}

/**
 * Phase 25 (CFILL-03, D-04 forgiving fill): fills the card branch of
 * `handleFill`. Every write is gated on (a) the field being detected, (b)
 * `isFieldVisible` (a hidden decoy field never receives a value even on a
 * token match, T-25-09), and (c) a stored value being present. `expiryMonth`/
 * `expiryYear` route through `fillSelectField` when the matched element is a
 * `<select>` (else `fillField`); `ccExpCombined` routes through
 * `formatExpiryForField` then `fillField`; every other field routes through
 * `fillField`. Returns the count of fields actually written -- the caller
 * decides ok/no-field-found from that count (D-04: >=1 write is success).
 * NEVER calls submit()/requestSubmit() -- same never-auto-submit discipline
 * as `fillField`/`fillSelectField` themselves.
 */
function fillCardFields(card: Extract<FillRequest, { kind: 'card' }>['card']): number {
  const fields = scanForCardFields(document);
  let written = 0;

  const fillText = (el: HTMLInputElement | HTMLSelectElement | undefined, value: string | undefined): void => {
    if (!el || !value) return;
    if (!(el instanceof HTMLInputElement)) return; // not a text-writable field
    if (!isFieldVisible(el)) return;
    fillField(el, value);
    written += 1;
  };

  const fillExpiry = (el: HTMLInputElement | HTMLSelectElement | undefined, value: string | undefined): void => {
    if (!el || !value) return;
    if (!isFieldVisible(el)) return;
    if (el instanceof HTMLSelectElement) {
      const result = fillSelectField(el, value);
      if (result.filled) written += 1;
      return; // a fillSelectField skip (no matching <option>) does NOT count
    }
    fillField(el, value);
    written += 1;
  };

  fillText(fields.cardholderName, card.cardholderName);
  fillText(fields.number, card.number);
  fillText(fields.cvv, card.cvv);
  fillText(fields.brand, card.brand);
  fillExpiry(fields.expiryMonth, card.expiryMonth);
  fillExpiry(fields.expiryYear, card.expiryYear);

  const combined = fields.ccExpCombined;
  if (combined instanceof HTMLInputElement && isFieldVisible(combined) && card.expiryMonth && card.expiryYear) {
    fillField(combined, formatExpiryForField(combined, card.expiryMonth, card.expiryYear));
    written += 1;
  }

  return written;
}

/**
 * Phase 25 (CFILL-03, D-04 forgiving fill): fills the identity branch of
 * `handleFill`. Same matched+visible+valued gate as `fillCardFields`; no
 * `<select>` path for identity fields -- always routes through `fillField`.
 * Returns the count of fields actually written.
 */
function fillIdentityFields(identity: Extract<FillRequest, { kind: 'identity' }>['identity']): number {
  const fields = scanForIdentityFields(document);
  let written = 0;

  const fillText = (el: HTMLInputElement | undefined, value: string | undefined): void => {
    if (!el || !value) return;
    if (!isFieldVisible(el)) return;
    fillField(el, value);
    written += 1;
  };

  fillText(fields.email, identity.email);
  fillText(fields.tel, identity.phone);
  fillText(fields.address, identity.address);

  return written;
}

/**
 * cryptiq-fill: exact-origin refusal FIRST (XSEC-03), unconditionally for
 * every `kind` -- do NOT move this check inside a branch. Then dispatches on
 * `msg.kind` (Phase 25, CFILL-03/D-01): `login` is the pre-Phase-25 behavior
 * verbatim (a FRESH re-scan -- the page may have mutated since an earlier
 * cryptiq-detect call -- then fillField, never a direct `.value =`
 * assignment, never a submit); `card`/`identity` route through
 * `fillCardFields`/`fillIdentityFields`'s forgiving-fill gate (D-04: >=1
 * field written -> ok:true, else no-field-found). Drops all local references
 * to the incoming secret on return by simply not retaining them past this
 * call's stack frame.
 */
function handleFill(msg: FillRequest): FillResult {
  if (location.origin !== msg.expectedOrigin) {
    return { ok: false, reason: 'origin-mismatch' };
  }

  if (msg.kind === 'card') {
    const written = fillCardFields(msg.card);
    return written > 0 ? { ok: true } : { ok: false, reason: 'no-field-found' };
  }

  if (msg.kind === 'identity') {
    const written = fillIdentityFields(msg.identity);
    return written > 0 ? { ok: true } : { ok: false, reason: 'no-field-found' };
  }

  const { user, pass } = scanForLoginFields(document);
  if (!user && !pass) {
    return { ok: false, reason: 'no-field-found' };
  }

  if (user) fillField(user, msg.username);
  if (pass) fillField(pass, msg.secret);

  return { ok: true };
}

/**
 * cryptiq-fill-focused (Plan 18-02, UX-03): the context-menu's focused-field
 * write. It writes directly into `document.activeElement` rather than
 * re-scanning for a user/pass pair. Routes ALL DOM writes through `fillField`
 * (never a raw `.value =` assignment) -- the one audited native-setter
 * primitive (RESEARCH Anti-Patterns).
 *
 * WR-02: exact-origin refusal FIRST, mirroring `handleFill`. Although the
 * right-click is a fresh gesture on this page, background.ts performs several
 * native-messaging round trips (ensureContentScript, match-origin, fill-entry)
 * between that click and this message, and the tab can navigate cross-origin
 * in that window. `location.origin` is the browser's own ASCII/punycode-
 * normalized form; refuse (write NOTHING) on any mismatch.
 */
function handleFillFocused(msg: FillFocusedMessage): FillFocusedResult {
  if (location.origin !== msg.expectedOrigin) {
    return { ok: false, reason: 'origin-mismatch' };
  }

  const active = document.activeElement;
  if (!(active instanceof HTMLInputElement)) {
    return { ok: false, reason: 'no-field-found' };
  }

  // CR-01 (secret-leak guard): the context menu is registered on ALL `editable`
  // fields, so `active` may be a plain text / username / search input. The
  // secret (a fetched or freshly generated password) must NEVER be written into
  // a non-password field — that would expose it on screen and submit it to the
  // site as that field's value. Fail closed; the popup remains the surface for
  // anything the focused-field write cannot safely satisfy.
  if (active.type !== 'password') {
    return { ok: false, reason: 'no-field-found' };
  }

  if (msg.username) {
    const { user } = scanForLoginFields(document);
    if (user) fillField(user, msg.username);
  }

  fillField(active, msg.secret);
  return { ok: true };
}

function setupMessageListener(): void {
  chrome.runtime.onMessage.addListener((message: unknown, _sender, sendResponse) => {
    if (!isKnownMessage(message)) return false;

    if (message.type === 'cryptiq-ping') {
      sendResponse({ ok: true });
      return false; // synchronous response, no need to keep the channel open
    }

    if (message.type === 'cryptiq-detect') {
      const { user, pass } = scanForLoginFields(document);
      const result: DetectResult = { ok: true, fieldsDetected: Boolean(user || pass) };
      sendResponse(result);
      return false;
    }

    if (message.type === 'cryptiq-fill-focused') {
      sendResponse(handleFillFocused(message));
      return false;
    }

    // message.type === 'cryptiq-fill'
    sendResponse(handleFill(message));
    return false;
  });
}

/**
 * FILL-02: a MutationObserver on document.body catches SPA/late-injected
 * forms. Debounced (not the observation itself, only the re-scan trigger):
 * a burst of mutation-record batches inside one ~250ms window coalesces to
 * exactly ONE scanForLoginFields() call, avoiding the "re-scan the whole DOM
 * on every mutation" perf trap on SPA-heavy sites. ctx.setTimeout auto-
 * cancels on context invalidation; the observer's own disconnect is tied to
 * ctx.onInvalidated explicitly since observer.observe() has no such
 * auto-cancel wrapper of its own. ctx.addEventListener's own
 * 'wxt:locationchange' handling starts WXT's internal location watcher on
 * first use (there is no public `locationWatcher.run()` to call directly --
 * it is a private field per ContentScriptContext's type declaration) and
 * additionally catches SPA client-side route changes that swap a DOM
 * subtree in one batch -- the same "fresh page, fresh detection, no
 * cross-nav state" signal FILL-07/D-03 requires.
 */
function setupObserver(ctx: InstanceType<typeof ContentScriptContext>): void {
  let scanPending = false;

  const scheduleRescan = () => {
    if (scanPending) return; // already coalescing this window's mutations
    scanPending = true;
    ctx.setTimeout(() => {
      scanPending = false;
      scanForLoginFields(document);
    }, OBSERVER_DEBOUNCE_MS);
  };

  const observer = new MutationObserver(() => scheduleRescan());
  observer.observe(document.body, { childList: true, subtree: true });
  ctx.onInvalidated(() => observer.disconnect());

  ctx.addEventListener(window, 'wxt:locationchange', () => scheduleRescan());
}

/**
 * CAP-01/CAP-03: capture-phase submit listener -- fires BEFORE the page's own
 * handler can call stopPropagation() and BEFORE navigation teardown begins.
 * Reuses scanForLoginFields verbatim (no duplicate field-detection logic),
 * then posts a `cryptiq-capture` message to background.ts SYNCHRONOUSLY (not
 * inside a `.then()`): the page may navigate away immediately after this
 * submit event finishes dispatching, so the send must be fired-and-forgotten
 * on the same tick.
 *
 * Renders NO DOM here -- no attachShadow, no appendChild/insertBefore, no
 * visible node anywhere in this handler (D-01/XSEC-02 non-negotiable).
 *
 * SPA logins that swap views client-side without ever firing a native
 * `submit` event are an ACCEPTED best-effort gap (17-RESEARCH.md Pitfall 2 /
 * FILL-07's framing) -- deliberately NOT compensated for with a
 * MutationObserver "page transitioned" heuristic, which would be unreliable
 * and is out of scope for this capture signal.
 */
function handleSubmit(): void {
  const { user, pass } = scanForLoginFields(document);
  if (!pass || !pass.value) return; // nothing to capture without a password value

  const message: CaptureMessage = {
    type: 'cryptiq-capture',
    username: user?.value ?? '',
    password: pass.value,
    origin: location.origin,
  };
  void chrome.runtime.sendMessage(message).catch(() => {
    // Best-effort: no listener (e.g. background not yet woken, or the
    // extension context is mid-teardown) simply means nothing is captured
    // this time -- never throw out of a submit handler.
  });
}

function setupSubmitCapture(ctx: InstanceType<typeof ContentScriptContext>): void {
  // Capture phase (`capture: true`) so this fires before the page's own
  // handler can stopPropagation() it and before navigation teardown.
  ctx.addEventListener(document, 'submit', handleSubmit, { capture: true });
}

export default defineContentScript({
  registration: 'runtime', // NOT auto-injected; never appears in manifest content_scripts
  main(ctx) {
    setupMessageListener();
    setupObserver(ctx);
    setupSubmitCapture(ctx);
  },
});
