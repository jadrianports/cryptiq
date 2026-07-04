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
import { scanForLoginFields } from '../src/lib/fieldDetection';
import { fillField } from '../src/lib/domFill';

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
 * cryptiq-fill: exact-origin refusal FIRST (XSEC-03), then a FRESH re-scan
 * (the page may have mutated since an earlier cryptiq-detect call -- never
 * reuse a cached field reference), then fillField (never a direct `.value =`
 * assignment, never a submit). Drops all local references to `msg.secret`
 * on return by simply not retaining them past this call's stack frame.
 */
function handleFill(msg: FillRequest): FillResult {
  if (location.origin !== msg.expectedOrigin) {
    return { ok: false, reason: 'origin-mismatch' };
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
 * write. Unlike `handleFill`, there is no earlier "show picker" moment to
 * TOCTOU-guard against -- the right-click itself is the fresh gesture on
 * this same page -- so this branch writes directly into
 * `document.activeElement` rather than re-scanning for a user/pass pair.
 * Routes ALL DOM writes through `fillField` (never a raw `.value =`
 * assignment) -- the one audited native-setter primitive (RESEARCH
 * Anti-Patterns).
 */
function handleFillFocused(msg: FillFocusedMessage): FillFocusedResult {
  const active = document.activeElement;
  if (!(active instanceof HTMLInputElement)) {
    return { ok: false, reason: 'no-field-found' };
  }

  if (msg.username && active.type === 'password') {
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
