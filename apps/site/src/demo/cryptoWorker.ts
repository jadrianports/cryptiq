// apps/site/src/demo/cryptoWorker.ts
//
// DEMO-03/04/05/06/08 (39-01 Task 2). The real, UNMODIFIED @cryptiq/core
// Argon2id (256 MiB / 3 ops floor, never lowered) + XChaCha20-Poly1305 run
// here, off the main thread, so DEMO-04's live stopwatch never blocks the UI.
// The 32-byte derived key is held in this Worker's closure and NEVER posted
// back to the main thread (T-39-01-I) — encrypt AND decrypt both happen here.
//
// DOC CORRECTION (39-RESEARCH.md Pitfall 4, 39-PATTERNS.md): there is NO
// AeadAuthError class in packages/core. The real tamper error is
// VaultCorruptError (code VAULT_CORRUPT), thrown by aead.ts's openData() on
// ANY AEAD authentication failure.
//
// Pitfall 3 (39-RESEARCH.md): postMessage/structured clone does NOT reliably
// preserve custom Error subclass identity or the `.code` property. Every
// error crossing this boundary is therefore manually serialized to a plain
// { code, name, message } object — never a live Error instance, never
// branched on via `instanceof` on the far side.

import {
  deriveKey,
  sealData,
  openData,
  getSodium,
  KdfResourceError,
  VaultCorruptError,
} from '@cryptiq/core/internal';

const FLOOR_OPS = 3;
const FLOOR_MEM = 268_435_456; // 256 MiB — LOCKED floor (CLAUDE.md); the only
// permitted variation is an explicit UPWARD memLimitOverride for the DEMO-08
// OOM proof — never below the floor.

// apps/site/tsconfig.json's `lib` is DOM-only (no "webworker" — mixing the DOM
// and WebWorker libs in one TS program produces conflicting global `self`/
// `postMessage` declarations project-wide). This file is a module (it has
// imports), so a top-level `declare const self` shadows the ambient DOM
// `self` ONLY within this file, giving the narrow dedicated-worker shape this
// module actually needs at RUNTIME (a real Worker's `self` is a
// DedicatedWorkerGlobalScope regardless of what TS sees here).
declare const self: {
  onmessage: ((event: MessageEvent<InboundMessage>) => unknown) | null;
  postMessage(message: unknown, transfer?: Transferable[]): void;
};

// NEVER posted back to the main thread (T-39-01-I).
let heldKey: Uint8Array | null = null;

interface DeriveMessage {
  type: 'derive';
  passphrase: string;
  memLimitOverride?: number;
}
interface EncryptMessage {
  type: 'encrypt';
  plaintext: Uint8Array;
}
interface DecryptMessage {
  type: 'decrypt';
  ciphertext: Uint8Array;
  nonce: Uint8Array;
}
type InboundMessage = DeriveMessage | EncryptMessage | DecryptMessage;

function errorName(err: unknown): 'KdfResourceError' | 'VaultCorruptError' | 'Error' {
  if (err instanceof KdfResourceError) return 'KdfResourceError';
  if (err instanceof VaultCorruptError) return 'VaultCorruptError';
  return 'Error';
}

self.onmessage = async (e: MessageEvent<InboundMessage>) => {
  const msg = e.data;
  try {
    if (msg.type === 'derive') {
      const sodium = await getSodium();
      // Fresh salt every run (DEMO-06 — visibly different ciphertext per run).
      const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
      const t0 = performance.now();
      heldKey = await deriveKey(new TextEncoder().encode(msg.passphrase), {
        algorithm: 2,
        opsLimit: FLOOR_OPS,
        memLimit: msg.memLimitOverride ?? FLOOR_MEM,
        salt,
      });
      self.postMessage({ type: 'derive-complete', elapsedMs: performance.now() - t0 });
    } else if (msg.type === 'encrypt') {
      if (!heldKey) throw new Error('derive before encrypt');
      const { ciphertext, nonce } = await sealData(msg.plaintext, heldKey);
      self.postMessage({ type: 'encrypt-complete', ciphertext, nonce }, [
        ciphertext.buffer,
        nonce.buffer,
      ]);
    } else if (msg.type === 'decrypt') {
      if (!heldKey) throw new Error('derive before decrypt');
      await openData(msg.ciphertext, msg.nonce, heldKey);
      self.postMessage({ type: 'decrypt-success' });
    }
  } catch (err) {
    // MUST manually serialize — structured clone does not reliably preserve
    // custom Error subclass identity or `.code` (Pitfall 3).
    self.postMessage({
      type: `${msg.type}-error`,
      code: (err as { code?: string }).code ?? 'UNKNOWN',
      name: errorName(err),
      message: (err as Error).message,
    });
  }
};
