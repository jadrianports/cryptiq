// apps/site/src/demo/useCryptoWorker.ts
//
// DEMO-03/04/05/06/08 (39-02 Task 1). The main-thread wrapper around the real
// crypto Worker (./cryptoWorker.ts, 39-01) — a lazy, reused singleton (D-04/
// D-05: re-derive / "Try again" reuse the SAME worker instance, never
// respawn). Every call is promise-based; every rejection carries a plain
// `{code, name, message}`-shaped CryptoWorkerError reconstructed from the
// worker's manually-serialized payload — NEVER `instanceof` on the ORIGINAL
// `@cryptiq/core` error classes across the postMessage boundary (Pitfall 3,
// 39-RESEARCH.md; the same discrimination pattern cryptoWorker.ts documents
// on its side of the boundary). Callers branch on `.code` (VAULT_CORRUPT /
// KDF_RESOURCE) only.
//
// Calls are serialized through a promise chain so two overlapping requests
// (e.g. a fast double hex-cell click, once Task 2 wires tamper) never race
// for the Worker's single `onmessage` handler — the next request's handler
// is only attached after the previous one has settled.

let worker: Worker | null = null;

function getWorker(): Worker {
  if (!worker) {
    worker = new Worker(new URL('./cryptoWorker.ts', import.meta.url), { type: 'module' });
  }
  return worker;
}

/** Reconstructed, main-thread-local representation of a worker-side typed error. */
export class CryptoWorkerError extends Error {
  readonly code: string;

  constructor(payload: { code: string; name: string; message: string }) {
    super(payload.message);
    // Mirrors the worker's manually-serialized `name` (e.g. 'VaultCorruptError'
    // / 'KdfResourceError') so this reconstructed, same-realm instance carries
    // a meaningful `.name` for logging/devtools. Callers still branch on
    // `.code` (VAULT_CORRUPT / KDF_RESOURCE), never on `instanceof` against
    // the original @cryptiq/core classes — those never cross the boundary.
    this.name = payload.name;
    this.code = payload.code;
  }
}

interface WorkerErrorPayload {
  type: string;
  code: string;
  name: string;
  message: string;
}

function isWorkerErrorPayload(data: unknown): data is WorkerErrorPayload {
  return (
    typeof data === 'object' &&
    data !== null &&
    typeof (data as { code?: unknown }).code === 'string' &&
    typeof (data as { name?: unknown }).name === 'string' &&
    typeof (data as { message?: unknown }).message === 'string'
  );
}

let chain: Promise<unknown> = Promise.resolve();

function send<T>(request: unknown, successType: string): Promise<T> {
  const result = chain.then(
    () =>
      new Promise<T>((resolve, reject) => {
        const w = getWorker();
        w.onmessage = (e: MessageEvent) => {
          const data: unknown = e.data;
          const type = (data as { type?: unknown } | null)?.type;
          if (type === successType) {
            resolve(data as T);
          } else if (isWorkerErrorPayload(data)) {
            reject(new CryptoWorkerError(data));
          } else {
            reject(
              new Error(`useCryptoWorker: unexpected worker message type "${String(type)}"`),
            );
          }
        };
        w.onerror = (e: ErrorEvent) => {
          reject(e.error instanceof Error ? e.error : new Error(e.message));
        };
        w.postMessage(request);
      }),
  );
  // Keep the chain alive regardless of this call's outcome so a rejection
  // never wedges every subsequent Worker call.
  chain = result.then(
    () => undefined,
    () => undefined,
  );
  return result;
}

/** Runs the real 256 MiB/3-ops Argon2id derivation (D-02: only ever called on explicit click). */
export function derive(passphrase: string, memLimitOverride?: number): Promise<{ elapsedMs: number }> {
  return send({ type: 'derive', passphrase, memLimitOverride }, 'derive-complete');
}

/** Seals `plaintext` under the derived key with a fresh nonce (DEMO-06). */
export function encrypt(
  plaintext: Uint8Array,
): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array }> {
  return send({ type: 'encrypt', plaintext }, 'encrypt-complete');
}

/** Opens `ciphertext`/`nonce` under the derived key; rejects with CryptoWorkerError on any AEAD failure. */
export function decrypt(ciphertext: Uint8Array, nonce: Uint8Array): Promise<void> {
  return send<void>({ type: 'decrypt', ciphertext, nonce }, 'decrypt-success');
}
