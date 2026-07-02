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
// exactly like the lazy getPort() pattern below already does for the pipe
// connection itself.

import { sendAssociate, sendRpc, bytesToBase64, type BridgeErrorResult } from '../src/lib/bridgeRpc';
import { getOrCreateIdentityKeypair, loadAssociation, saveAssociation } from '../src/lib/associationStore';

export default defineBackground(() => {
  const ECHO_TIMEOUT_MS = 5000; // Pitfall 4: never a silent hang.
  const CURRENT_PROTOCOL_VERSION = 1; // D-02

  interface BridgeEnvelope {
    protocolVersion: number;
    type: string;
    id: string | null;
    payload: unknown;
  }

  // Module-level port handle. Null means "not currently connected" — getPort()
  // lazily (re)opens it on demand rather than eagerly at worker startup
  // (D-16: lazy reconnect-on-demand, satisfies BRIDGE-07's SW-restart
  // recovery requirement).
  //
  // SC-4 observability fix: an in-memory "was previously disconnected" flag
  // cannot distinguish a real reconnect from the FIRST connect after an MV3
  // service-worker restart — the restart itself wipes all module state,
  // including the flag. So the "reconnected" signal could never fire on the
  // exact path SC-4 exercises. Instead, `getPort()` unconditionally logs a
  // connecting line every time it opens a fresh port — this fires both on
  // first-ever connect AND on every reconnect after SW restart/idle-teardown,
  // which is what a tester (or `chrome://extensions` service-worker console)
  // needs to see to confirm the lazy-reconnect path actually ran.
  let port: chrome.runtime.Port | null = null;

  function getPort(): chrome.runtime.Port {
    if (port) return port;

    // Always visible — not gated on any in-memory "previously connected"
    // state, which a SW restart would reset before this line could ever
    // observe it (see comment above).
    console.info('[cryptiq-ext] connecting to native host com.cryptiq.bridge');
    port = chrome.runtime.connectNative('com.cryptiq.bridge'); // D-07: exact host_name, treat as permanent.

    port.onDisconnect.addListener(() => {
      // D-16: null out the module-level handle so the NEXT getPort() call
      // reopens a fresh port rather than reusing a dead one. We distinguish
      // "host not found" (extension not registered / app never installed
      // the native-host manifest) from a normal disconnect via
      // chrome.runtime.lastError, but in both cases the recovery action is
      // identical: lazily reconnect on the next send.
      const lastError = chrome.runtime.lastError;
      if (lastError) {
        console.warn(`[cryptiq-ext] native port disconnected: ${lastError.message}`);
      } else {
        console.info('[cryptiq-ext] native port disconnected');
      }
      port = null;
    });

    return port;
  }

  interface EchoResult {
    ok: boolean;
    appNotRunning?: boolean;
    payload?: unknown;
    error?: string;
  }

  function sendEcho(): Promise<EchoResult> {
    return new Promise((resolve) => {
      let settled = false;
      const p = getPort();
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
    });
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
    const result = await sendAssociate(getPort(), {
      clientPublicKey: bytesToBase64(identity.publicKey),
      label,
    });

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

    let result = await sendRpc(getPort(), innerPayload);

    if (!result.ok && result.code === 'not-associated') {
      const reassociated = await ensureAssociation(true);
      if (!reassociated.ok) return reassociated;
      result = await sendRpc(getPort(), innerPayload);
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
  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message?.type === 'cryptiq-send-echo') {
      sendEcho().then(sendResponse);
      return true; // keep the message channel open for the async response
    }

    if (message?.type === 'cryptiq-get-bridge-state') {
      sendResponse(lastKnownBridgeState);
      return false; // synchronous response, no need to keep the channel open
    }

    return false;
  });
});
