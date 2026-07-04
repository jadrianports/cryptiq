// apps/extension/entrypoints/background.ts
//
// MV3 service worker: lazily (re)opens the native port to the Cryptiq
// bridge sidecar (com.cryptiq.bridge, D-07) and reconnects on demand after
// an MV3 service-worker restart/idle-teardown (D-16, BRIDGE-07). No
// keepalive ping — MV3's ~30s idle suspension is expected and NOT fought.
//
// Every outbound request (sendEcho) is timeout-guarded (Pitfall 4 /
// BRIDGE-07): a native-port round trip that never replies surfaces a typed
// rejection instead of hanging the caller forever.
//
// Plan 06 (BRIDGE-04/06/10): on first need, associate once (plaintext
// handshake via bridgeRpc.sendAssociate), persist the returned
// { hostPublicKey, pairingToken } via associationStore.saveAssociation,
// and thereafter speak every RPC through bridgeRpc.sendRpc (box-wrapped,
// token INSIDE the box). The identity keypair + association are loaded
// from chrome.storage.local on EVERY call (Pitfall 2) — never regenerated
// — so a reconnect after an MV3 SW restart is silently trusted (SC-1),
// exactly like the fresh-per-request native port opened below
// (openNativePort/withNativePort) does for the pipe connection itself.

import { sendAssociate, sendRpc, bytesToBase64, type BridgeErrorResult } from '../src/lib/bridgeRpc';
import { getOrCreateIdentityKeypair, loadAssociation, saveAssociation } from '../src/lib/associationStore';
import { writeCapture, clearCaptureForTab } from '../src/lib/captureBuffer';
import { ensureContentScript } from '../src/lib/popupFill';
import { pickTopCandidate, shouldRefuseFrame } from '../src/lib/contextMenu';
import type { EntryMatchMetadata } from '../src/lib/contentScriptMessages';

export default defineBackground(() => {
  const ECHO_TIMEOUT_MS = 5000; // Pitfall 4: never a silent hang.
  const CURRENT_PROTOCOL_VERSION = 1; // D-02

  interface BridgeEnvelope {
    protocolVersion: number;
    type: string;
    id: string | null;
    payload: unknown;
  }

  // BUG-5 fix: the native port is SINGLE-USE per request. The app
  // (handle_bridge_connection) serves exactly ONE request per pipe connection
  // and then closes it, and the sidecar exits after one relay — so a REUSED
  // port's second request rides an already-dead connection and fails fast with
  // a typed `disconnected` (every 2nd+ send, incl. the `sendRpc` that follows
  // `ensureAssociation`'s `sendAssociate` inside a single sendAuthenticatedRpc).
  // A fresh `connectNative` port per request matches that one-request-per-
  // connection contract and bridgeRpc.ts's "stateless per-connection" design
  // (clientPublicKey + token ride every message), so there is no cross-request
  // port state to preserve. This also realizes what this file's own comments
  // always CLAIMED ("the sidecar reconnects per message") but the old cached
  // `getPort()` never actually did.
  //
  // `openNativePort()` logs a connecting line on EVERY open — this is the SC-4
  // observability signal (fires on first-ever connect AND every reconnect after
  // an MV3 SW restart/idle-teardown), visible in the service-worker console.
  function openNativePort(): chrome.runtime.Port {
    console.info('[cryptiq-ext] connecting to native host com.cryptiq.bridge');
    const p = chrome.runtime.connectNative('com.cryptiq.bridge'); // D-07: exact host_name.

    p.onDisconnect.addListener(() => {
      // Distinguish "host not found" (extension not registered / app never
      // installed the native-host manifest) from a normal post-request
      // disconnect via chrome.runtime.lastError — surfaced for the SW console
      // only; the request's own settle path (typed error or timeout) is what
      // resolves the caller.
      const lastError = chrome.runtime.lastError;
      if (lastError) {
        console.warn(`[cryptiq-ext] native port disconnected: ${lastError.message}`);
      } else {
        console.info('[cryptiq-ext] native port disconnected');
      }
    });

    return p;
  }

  /**
   * Run exactly ONE request over a FRESH native-messaging port, then always
   * disconnect it (BUG-5 fix — see the note above). `connectNative` spawns a
   * fresh sidecar per call; the sidecar already exits after one relay, so the
   * explicit `disconnect()` in the `finally` reaps it deterministically on the
   * happy path and is a harmless no-op when the sidecar already exited after
   * emitting a typed error.
   */
  async function withNativePort<T>(run: (port: chrome.runtime.Port) => Promise<T>): Promise<T> {
    const p = openNativePort();
    try {
      return await run(p);
    } finally {
      try {
        p.disconnect();
      } catch {
        // Already disconnected (sidecar exited after its one relay / typed error).
      }
    }
  }

  interface EchoResult {
    ok: boolean;
    appNotRunning?: boolean;
    payload?: unknown;
    error?: string;
  }

  function sendEcho(): Promise<EchoResult> {
    return withNativePort((p) => new Promise<EchoResult>((resolve) => {
      let settled = false;
      const id = crypto.randomUUID();

      // Pitfall 4 / BRIDGE-07: every send has an explicit client-side
      // timeout. If the reply never arrives (worker torn down mid-request,
      // sidecar hung, pipe dropped without a clean disconnect event), the
      // caller gets a typed failure instead of an indefinitely pending
      // promise.
      const timeoutHandle = setTimeout(() => {
        if (settled) return;
        settled = true;
        p.onMessage.removeListener(listener);
        resolve({ ok: false, error: 'timeout' });
      }, ECHO_TIMEOUT_MS);

      const listener = (msg: BridgeEnvelope) => {
        if (msg.id !== id) return;
        if (settled) return;
        settled = true;
        clearTimeout(timeoutHandle);
        p.onMessage.removeListener(listener);

        // D-19: app-not-running is handled structurally — resolved, not
        // thrown/hung — with a minimal signal the popup can render.
        if (
          msg.type === 'error' &&
          typeof msg.payload === 'object' &&
          msg.payload !== null &&
          (msg.payload as { code?: string }).code === 'app-not-running'
        ) {
          resolve({ ok: false, appNotRunning: true });
          return;
        }

        if (msg.type === 'error') {
          resolve({ ok: false, error: JSON.stringify(msg.payload) });
          return;
        }

        resolve({ ok: true, payload: msg.payload });
      };

      p.onMessage.addListener(listener);
      p.postMessage({
        protocolVersion: CURRENT_PROTOCOL_VERSION,
        type: 'echo',
        id,
        payload: { ping: 'hello' },
      });
    }));
  }

  // --- Plan 06: authenticated association wiring (BRIDGE-04/06/10) -------

  // Detect the browser for the auto-labeled association (D-02). Only
  // Chrome/Edge matter for v1 (STACK.md); anything else falls back to a
  // generic label rather than guessing.
  function detectBrowserLabel(): string {
    const ua = typeof navigator !== 'undefined' ? navigator.userAgent : '';
    if (ua.includes('Edg/')) return 'Edge';
    if (ua.includes('Chrome/')) return 'Chrome';
    return 'Browser';
  }

  // Last known bridge state, queryable by a freshly (re)opened popup via
  // 'cryptiq-get-bridge-state' — a popup can open AFTER the SW already
  // resolved the handshake, so it needs to be able to ask, not just listen.
  let lastKnownBridgeState: Record<string, unknown> = { type: 'cryptiq-bridge-state', state: 'unknown' };

  function broadcastBridgeState(message: Record<string, unknown>): void {
    lastKnownBridgeState = message;
    // No popup may be open to receive this — chrome.runtime.sendMessage
    // rejects with "Could not establish connection" in that case, which is
    // expected and safe to ignore (D-10: this carries no secrets anyway).
    chrome.runtime.sendMessage(message).catch(() => {});
  }

  /**
   * Ensure the extension has a persisted association before speaking any
   * authenticated RPC. Loads the PERSISTED identity keypair (never
   * regenerated — Pitfall 2) and, only when no association exists (or the
   * caller forces re-association after the app reports `not-associated`),
   * runs the one-time plaintext `associate` handshake and persists the
   * result. On an MV3 SW restart, `loadAssociation()` returns the SAME
   * stored record, so no re-approval is ever triggered (SC-1).
   */
  async function ensureAssociation(forceReassociate = false): Promise<{ ok: true } | BridgeErrorResult> {
    const identity = await getOrCreateIdentityKeypair();
    const existing = forceReassociate ? null : await loadAssociation();
    if (existing) return { ok: true };

    broadcastBridgeState({ type: 'cryptiq-bridge-state', state: 'waiting-for-approval' });

    const label = detectBrowserLabel();
    const result = await withNativePort((p) =>
      sendAssociate(p, {
        clientPublicKey: bytesToBase64(identity.publicKey),
        label,
      }),
    );

    if (!result.ok) {
      broadcastBridgeState({ type: 'cryptiq-bridge-state', state: 'error', code: result.code, message: result.message });
      return result;
    }

    await saveAssociation({ hostPublicKey: result.hostPublicKey, pairingToken: result.pairingToken, label });
    broadcastBridgeState({ type: 'cryptiq-bridge-state', state: 'associated' });
    return { ok: true };
  }

  /**
   * Route a real RPC through the authenticated channel: ensure an
   * association exists, send the box-wrapped `rpc`, and — fail closed —
   * forward ANY of the four error codes (not-associated/invalid-token/
   * app-outdated/extension-outdated) to the popup rather than silently
   * hanging or partially proceeding. A single `not-associated` response
   * from an already-"associated" extension (e.g. the app revoked it) is
   * retried once via re-association; this is the ONLY case that clears the
   * "association exists" fast path (per Task 2 acceptance criteria).
   */
  async function sendAuthenticatedRpc(
    innerPayload: Record<string, unknown>,
  ): Promise<{ ok: true; payload: unknown } | BridgeErrorResult> {
    const ensured = await ensureAssociation();
    if (!ensured.ok) return ensured;

    let result = await withNativePort((p) => sendRpc(p, innerPayload));

    if (!result.ok && result.code === 'not-associated') {
      const reassociated = await ensureAssociation(true);
      if (!reassociated.ok) return reassociated;
      result = await withNativePort((p) => sendRpc(p, innerPayload));
    }

    if (!result.ok) {
      broadcastBridgeState({ type: 'cryptiq-bridge-state', state: 'error', code: result.code, message: result.message });
    }

    return result;
  }

  // Kick off the association handshake on first SW load/wake. Fire-and-
  // forget (WXT's background main() cannot be async) — errors are
  // swallowed here because ensureAssociation() already broadcasts a typed
  // error state to the popup; there is no additional secret-free context to
  // log (D-10).
  void ensureAssociation();

  // Bridge for the popup (D-18/D-20): the popup's dev-only echo button
  // triggers sendEcho() via a runtime message rather than importing this
  // module directly (service worker and popup are separate JS contexts).
  //
  // Plan 16-04: the popup's D-10 status surface and its best-effort
  // "Unlock Cryptiq" button both need to speak an authenticated `rpc`
  // (match-origin / fill-entry / focus-app) but a popup script cannot reach
  // this module's native port directly (separate JS context) — 'cryptiq-rpc'
  // relays an arbitrary `{ method, params }` inner payload through the SAME
  // sendAuthenticatedRpc() used by sendEcho's sibling paths, which opens a
  // FRESH single-use port per request (withNativePort — BUG-5 fix, Pitfall 4 /
  // D-16) rather than letting the popup cache its own port.
  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message?.type === 'cryptiq-send-echo') {
      sendEcho().then(sendResponse);
      return true; // keep the message channel open for the async response
    }

    if (message?.type === 'cryptiq-get-bridge-state') {
      sendResponse(lastKnownBridgeState);
      return false; // synchronous response, no need to keep the channel open
    }

    if (message?.type === 'cryptiq-rpc') {
      const innerPayload = (message.payload ?? {}) as Record<string, unknown>;
      sendAuthenticatedRpc(innerPayload).then(sendResponse);
      return true; // keep the message channel open for the async response
    }

    // Plan 19-03 (CAP-01/CAP-03): fill.content.ts's capture-phase submit
    // listener posts this SYNCHRONOUSLY, fire-and-forget. This branch does
    // NOT call sendAuthenticatedRpc — per D-01/anti-clickjacking posture,
    // nothing crosses the authenticated bridge until the user opens the
    // popup and explicitly clicks Save/Update (Plan 04). It only buffers the
    // pair (memory-only, chrome.storage.session via the shared captureBuffer
    // module) and lights the toolbar badge.
    if (message?.type === 'cryptiq-capture') {
      const tabId = _sender.tab?.id;
      if (tabId === undefined) {
        // No addressable tab (e.g. message from a non-tab context) — drop
        // the capture; there is no badge/buffer key to write it under.
        sendResponse({ ok: false });
        return false;
      }
      writeCapture(tabId, {
        username: typeof message.username === 'string' ? message.username : '',
        password: typeof message.password === 'string' ? message.password : '',
        origin: typeof message.origin === 'string' ? message.origin : '',
        ts: Date.now(),
      })
        .then(() => sendResponse({ ok: true }))
        .catch(() => sendResponse({ ok: false }));
      return true; // writeCapture is async — keep the channel open
    }

    return false;
  });

  // Drop any buffered capture + un-badge the moment its tab closes, so a
  // captured credential never outlives the tab it was captured on (routed
  // through the SAME shared clear-together seam Plan 04's dismissal paths
  // use — never a partial/local clear). Needs no extra manifest permission:
  // chrome.tabs.onRemoved fires without the `tabs` permission (it carries
  // only tabId + removeInfo, no url/title).
  chrome.tabs.onRemoved.addListener((tabId) => {
    void clearCaptureForTab(tabId);
  });

  // --- Plan 18-02: context-menu fill/generate (UX-03) ---------------------
  //
  // Registration ONLY inside onInstalled (Pitfall 1) -- fires once per
  // install/update, never re-created on every SW wake, so a duplicate-id
  // create() error never fires on SW restart (T-18-10).
  chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({
      id: 'cryptiq-fill-focused',
      title: 'Fill from Cryptiq',
      contexts: ['editable'],
    });
    chrome.contextMenus.create({
      id: 'cryptiq-generate-focused',
      title: 'Generate password',
      contexts: ['editable'],
    });
  });

  /**
   * Right-click "Fill from Cryptiq": top-frame-only (T-18-07), reuses the
   * SAME ensureContentScript/sendAuthenticatedRpc paths the popup's own fill
   * flow uses -- never a second native-port path, never `executeScript({func})`
   * (T-18-08). Best-effort top candidate (Open Question 1 rec (a)) since a
   * context-menu click has no picker surface of its own. Silently no-ops on
   * locked/disconnected/empty-match/no-candidate -- the popup remains the
   * surface that shows status (RESEARCH Pattern 4).
   */
  async function handleContextFill(tab: chrome.tabs.Tab | undefined, frameId: number | undefined): Promise<void> {
    if (shouldRefuseFrame(frameId)) return;
    if (!tab || tab.id === undefined || !tab.url) return;
    const tabId = tab.id;

    let origin: string;
    try {
      origin = new URL(tab.url).origin;
    } catch {
      return; // e.g. a chrome:// page -- fail closed, never guess
    }

    const injected = await ensureContentScript(tabId);
    if (!injected) return;

    const matchOutcome = await sendAuthenticatedRpc({ method: 'match-origin', params: { origin } });
    if (!matchOutcome.ok) return;
    const candidates =
      typeof matchOutcome.payload === 'object' &&
      matchOutcome.payload !== null &&
      Array.isArray((matchOutcome.payload as { candidates?: unknown }).candidates)
        ? (matchOutcome.payload as { candidates: EntryMatchMetadata[] }).candidates
        : [];

    const top = pickTopCandidate(candidates);
    if (!top) return;

    const fillOutcome = await sendAuthenticatedRpc({ method: 'fill-entry', params: { entryId: top.id } });
    const secret =
      fillOutcome.ok && typeof fillOutcome.payload === 'object' && fillOutcome.payload !== null
        ? (fillOutcome.payload as { secret?: unknown }).secret
        : undefined;
    if (typeof secret !== 'string') return;

    try {
      await chrome.tabs.sendMessage(tabId, { type: 'cryptiq-fill-focused', secret, username: top.username });
    } catch {
      // Best-effort only -- e.g. the tab navigated away between the RPC and
      // this send; nothing further to do.
    }
  }

  /**
   * Right-click "Generate password": top-frame-only (T-18-07), no override
   * params (GEN-01/02, D-02/D-03 -- always the vault's saved generator
   * preset). Writes the generated secret into the focused field via the SAME
   * `cryptiq-fill-focused` content-script message the fill path uses.
   */
  async function handleContextGenerate(tab: chrome.tabs.Tab | undefined, frameId: number | undefined): Promise<void> {
    if (shouldRefuseFrame(frameId)) return;
    if (!tab || tab.id === undefined) return;
    const tabId = tab.id;

    const injected = await ensureContentScript(tabId);
    if (!injected) return;

    const outcome = await sendAuthenticatedRpc({ method: 'generate-password', params: {} });
    const generated =
      outcome.ok && typeof outcome.payload === 'object' && outcome.payload !== null
        ? (outcome.payload as { password?: unknown }).password
        : undefined;
    if (typeof generated !== 'string') return;

    try {
      await chrome.tabs.sendMessage(tabId, { type: 'cryptiq-fill-focused', secret: generated });
    } catch {
      // Best-effort only.
    }
  }

  chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (info.menuItemId === 'cryptiq-fill-focused') {
      void handleContextFill(tab, info.frameId);
    } else if (info.menuItemId === 'cryptiq-generate-focused') {
      void handleContextGenerate(tab, info.frameId);
    }
  });
});
