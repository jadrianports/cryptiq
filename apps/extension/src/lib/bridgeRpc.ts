// apps/extension/src/lib/bridgeRpc.ts
//
// Extension-side speaking of the authenticated bridge protocol pinned by
// Plan 03 (app-side Rust handshake): a ONE-TIME plaintext `associate`
// (there is no shared secret yet — TOFU, RESEARCH.md Anti-Patterns), then
// every subsequent request is `crypto_box`-sealed via associationCrypto
// with the pairing token riding INSIDE the ciphertext (T-15-04) and NEVER
// in the outer envelope. Mirrors background.ts's existing sendEcho()
// shape: timeout-guarded, listener-cleanup, `id` correlation via
// crypto.randomUUID() (Phase 14 precedent).

import { sealForHost, bytesToBase64, base64ToBytes, openFromHost } from './associationCrypto';
import { getOrCreateIdentityKeypair, loadAssociation } from './associationStore';

const RPC_TIMEOUT_MS = 5000; // Pitfall 4 (Phase 14): never a silent hang.
// The `associate` handshake blocks on a HUMAN approval decision in the app,
// which gives the user 60s (Plan 03: tokio::time::timeout(60s, decision_rx)).
// A 5s RPC timeout would fire long before any real human approves — the app
// would then persist its side + send associate-ok, but the extension would
// already have given up and never call saveAssociation, leaving an asymmetric
// association (app trusts the extension; extension holds no token → it re-
// prompts on next use, breaking SC-1 "silently trusted"). Wait slightly past
// the app's 60s window so the associate-ok has time to traverse pipe→sidecar→SW.
// (Found via the live Phase-15 UAT; unit tests mock the transport and resolve
// instantly, so they never exercised the human-delay path.)
const ASSOCIATE_TIMEOUT_MS = 65000;
const CURRENT_PROTOCOL_VERSION = 1; // D-02

interface BridgeEnvelope {
  protocolVersion: number;
  type: string;
  id: string | null;
  payload: unknown;
}

/**
 * The error codes the app-side handshake (Plan 03) and the app-level
 * `error_response` (Plan 16-06) can return. `'vault-locked'` /
 * `'association-denied'` / `'not-found'` / `'invalid-request'` are the
 * app-level RPC error codes; the rest are handshake/transport codes.
 */
export type BridgeErrorCode =
  | 'not-associated'
  | 'invalid-token'
  | 'app-outdated'
  | 'extension-outdated'
  | 'protocol-error'
  | 'timeout'
  | 'vault-locked'
  | 'association-denied'
  | 'not-found'
  | 'invalid-request'
  | 'unknown';

export interface BridgeErrorResult {
  ok: false;
  code: BridgeErrorCode;
  message?: string;
}

export interface AssociateSuccess {
  ok: true;
  hostPublicKey: string; // base64
  pairingToken: string; // base64
}

export type AssociateOutcome = AssociateSuccess | BridgeErrorResult;

export interface RpcSuccess {
  ok: true;
  payload: unknown;
}

export type RpcOutcome = RpcSuccess | BridgeErrorResult;

/**
 * Map an incoming `{ type: 'error', payload: { code, message } }` envelope
 * to a typed result. Never throws — an unexpected/missing shape maps to
 * `'unknown'` so the caller can still fail closed.
 */
function mapErrorPayload(payload: unknown): BridgeErrorResult {
  const record = typeof payload === 'object' && payload !== null ? (payload as Record<string, unknown>) : {};
  const code = typeof record.code === 'string' ? (record.code as BridgeErrorCode) : 'unknown';
  const message = typeof record.message === 'string' ? record.message : undefined;
  return { ok: false, code, message };
}

/**
 * Send the ONE-TIME plaintext `associate` request. NEVER box-wrapped —
 * there is no shared secret to encrypt with yet (RESEARCH.md Anti-Patterns:
 * "Encrypting the associate/associate-ok handshake itself").
 */
export function sendAssociate(
  port: chrome.runtime.Port,
  request: { clientPublicKey: string; label: string },
): Promise<AssociateOutcome> {
  return new Promise((resolve) => {
    let settled = false;
    const id = crypto.randomUUID();

    const timeoutHandle = setTimeout(() => {
      if (settled) return;
      settled = true;
      port.onMessage.removeListener(listener);
      resolve({ ok: false, code: 'timeout' });
    }, ASSOCIATE_TIMEOUT_MS);

    const listener = (msg: BridgeEnvelope) => {
      if (msg.id !== id) return;
      if (settled) return;
      settled = true;
      clearTimeout(timeoutHandle);
      port.onMessage.removeListener(listener);

      if (msg.type === 'error') {
        resolve(mapErrorPayload(msg.payload));
        return;
      }

      const payload = (msg.payload ?? {}) as { hostPublicKey?: string; pairingToken?: string };
      resolve({
        ok: true,
        hostPublicKey: payload.hostPublicKey ?? '',
        pairingToken: payload.pairingToken ?? '',
      });
    };

    port.onMessage.addListener(listener);

    port.postMessage({
      protocolVersion: CURRENT_PROTOCOL_VERSION,
      type: 'associate',
      id,
      payload: { clientPublicKey: request.clientPublicKey, label: request.label },
    });
  });
}

/**
 * Send a box-wrapped `rpc` request. Loads the persisted association +
 * identity keypair (Plan 02), seals `{ pairingToken, ...innerPayload }`
 * with a FRESH nonce (associationCrypto.sealForHost — Pitfall 3), and
 * posts `{ type:'rpc', id, payload:{ nonce, box } }`. The pairing token
 * rides INSIDE the box; the outer envelope never carries it
 * (RESEARCH.md Anti-Patterns / T-15-04).
 */
export function sendRpc(port: chrome.runtime.Port, innerPayload: Record<string, unknown>): Promise<RpcOutcome> {
  return new Promise((resolve) => {
    // Single settle path: idempotent resolve + guaranteed cleanup, hoisted so
    // the setup try/catch below can also fail closed after the timeout/listener
    // are armed. `settled` blocks any double-resolve across timeout/listener/catch.
    let settled = false;
    let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
    let listener: ((msg: BridgeEnvelope) => void) | undefined;
    const settle = (outcome: RpcOutcome) => {
      if (settled) return;
      settled = true;
      if (timeoutHandle !== undefined) clearTimeout(timeoutHandle);
      if (listener) port.onMessage.removeListener(listener);
      resolve(outcome);
    };

    void (async () => {
      try {
        const association = await loadAssociation();
        if (!association) {
          settle({ ok: false, code: 'not-associated' });
          return;
        }

        const identity = await getOrCreateIdentityKeypair();
        const hostPublicKey = base64ToBytes(association.hostPublicKey);

        const id = crypto.randomUUID();

        timeoutHandle = setTimeout(() => settle({ ok: false, code: 'timeout' }), RPC_TIMEOUT_MS);

        listener = (msg: BridgeEnvelope) => {
          if (msg.id !== id) return;
          if (settled) return;

          if (msg.type === 'error') {
            settle(mapErrorPayload(msg.payload));
            return;
          }

          // Success payload is an authenticated-crypto box `{ nonce, box }` —
          // decrypt via openFromHost (T-16-01) and fail closed on any
          // authentication or parse failure (T-16-02). Never resolve ok:true
          // with unauthenticated/undecryptable bytes. The whole decode+open+
          // parse sequence is wrapped in one try/catch: a malformed/missing
          // base64 field would otherwise throw a DOMException out of
          // atob() synchronously inside this listener, uncaught.
          try {
            const responsePayload = (msg.payload ?? {}) as { nonce?: string; box?: string };
            const nonceBytes = base64ToBytes(responsePayload.nonce ?? '');
            const boxBytes = base64ToBytes(responsePayload.box ?? '');
            const opened = openFromHost(boxBytes, nonceBytes, hostPublicKey, identity.secretKey);
            // `!opened` (not `=== null`) so a falsy return of any shape — e.g. a
            // tweetnacl fork returning `false` on MAC failure — still fails closed.
            if (!opened) {
              settle({ ok: false, code: 'protocol-error' });
              return;
            }
            const parsed: unknown = JSON.parse(new TextDecoder().decode(opened));
            settle({ ok: true, payload: parsed });
          } catch {
            settle({ ok: false, code: 'protocol-error' });
          }
        };

        port.onMessage.addListener(listener);

        // Token rides INSIDE the plaintext that gets sealed — never in the
        // outer envelope (T-15-04).
        const plaintext = JSON.stringify({ pairingToken: association.pairingToken, ...innerPayload });
        const plaintextBytes = new TextEncoder().encode(plaintext);
        const sealed = sealForHost(plaintextBytes, hostPublicKey, identity.secretKey); // fresh nonce every call (Pitfall 3)

        port.postMessage({
          protocolVersion: CURRENT_PROTOCOL_VERSION,
          type: 'rpc',
          id,
          // clientPublicKey identifies WHICH cached peer is talking so the app can
          // look up the shared key + pairing-token hash and open the box. Each RPC
          // rides its own fresh pipe connection (the sidecar reconnects per message),
          // so the app is stateless per-connection and needs the key every time —
          // exactly as the `associate` envelope sends it (background.ts ensureAssociation).
          payload: { clientPublicKey: bytesToBase64(identity.publicKey), nonce: sealed.nonce, box: sealed.box },
        });
      } catch {
        // MED-1: any setup/seal throw — e.g. an invalid-base64
        // `association.hostPublicKey` making `base64ToBytes` (atob) throw, or a
        // `sealForHost` failure — fails closed here instead of leaving the outer
        // Promise to hang the popup forever with no resolve and no timeout.
        settle({ ok: false, code: 'protocol-error' });
      }
    })();
  });
}

export { bytesToBase64 };
