// apps/site/src/tests/cryptoWorker.spec.ts
//
// DEMO-03/04/05/06/08 (39-01 Task 3). Drives the REAL cryptoWorker.ts over a
// REAL postMessage/structured-clone boundary in real browser mode — never a
// mock (39-RESEARCH.md Pitfall 3's failure mode only reproduces with a real
// structured-clone boundary; a Node-only mock of postMessage would not catch
// it). Mirrors roundTrip.spec.ts's real-browser/real-core philosophy and its
// 30_000ms timeout override for a real ~1s Argon2id run.
//
// DOC CORRECTION (39-RESEARCH.md Pitfall 4): there is NO AeadAuthError class
// in packages/core. The tamper test below asserts the REAL tamper error,
// VaultCorruptError/VAULT_CORRUPT.
//
// Assertions branch on `.code`/`.name` strings only, never `instanceof`
// across the postMessage boundary (Pitfall 3 — structured clone does not
// reliably preserve custom Error subclass identity).

import { describe, expect, it } from 'vitest';

type DeriveComplete = { type: 'derive-complete'; elapsedMs: number };
type EncryptComplete = { type: 'encrypt-complete'; ciphertext: Uint8Array; nonce: Uint8Array };
type DecryptSuccess = { type: 'decrypt-success' };
type WorkerErrorMessage = { type: string; code: string; name: string; message: string };
type WorkerMessage = DeriveComplete | EncryptComplete | DecryptSuccess | WorkerErrorMessage;

function spawnWorker(): Worker {
  return new Worker(new URL('../demo/cryptoWorker.ts', import.meta.url), { type: 'module' });
}

function waitForMessage(worker: Worker): Promise<WorkerMessage> {
  return new Promise((resolve, reject) => {
    worker.onmessage = (e: MessageEvent<WorkerMessage>) => resolve(e.data);
    worker.onerror = (e: ErrorEvent) => reject(e.error ?? new Error(e.message));
  });
}

const DEMO_PASSPHRASE = 'correct horse battery staple';

describe('crypto worker — real Argon2id/AEAD off the main thread (DEMO-03..06,08)', () => {
  it(
    'derive: worker returns a real, usable non-zero key at 256 MiB/3 ops',
    async () => {
      const worker = spawnWorker();
      try {
        const derivePromise = waitForMessage(worker);
        worker.postMessage({ type: 'derive', passphrase: DEMO_PASSPHRASE });
        const deriveResult = await derivePromise;

        expect(deriveResult.type).toBe('derive-complete');
        expect((deriveResult as DeriveComplete).elapsedMs).toBeGreaterThan(0);

        // Round trip proves the derivation actually produced a usable key
        // (doubles as the Assumptions-Log-A2 getSodium-in-worker validation).
        const encryptPromise = waitForMessage(worker);
        const plaintext = new TextEncoder().encode('hello, cryptiq');
        worker.postMessage({ type: 'encrypt', plaintext }, [plaintext.buffer]);
        const encryptResult = (await encryptPromise) as EncryptComplete;
        expect(encryptResult.type).toBe('encrypt-complete');

        const decryptPromise = waitForMessage(worker);
        worker.postMessage(
          {
            type: 'decrypt',
            ciphertext: encryptResult.ciphertext,
            nonce: encryptResult.nonce,
          },
          [encryptResult.ciphertext.buffer, encryptResult.nonce.buffer],
        );
        const decryptResult = await decryptPromise;
        expect(decryptResult.type).toBe('decrypt-success');
      } finally {
        worker.terminate();
      }
    },
    30_000,
  );

  it(
    'responsive: main thread stays responsive during derivation',
    async () => {
      const worker = spawnWorker();
      try {
        let ticks = 0;
        const interval = setInterval(() => {
          ticks++;
        }, 10);

        const derivePromise = waitForMessage(worker);
        worker.postMessage({ type: 'derive', passphrase: DEMO_PASSPHRASE });
        await derivePromise;

        clearInterval(interval);

        // DEMO-04: the tick counter must have advanced multiple times WHILE
        // the ~1s Argon2id derivation ran in the Worker — proof the main
        // thread was never blocked.
        expect(ticks).toBeGreaterThan(1);
      } finally {
        worker.terminate();
      }
    },
    30_000,
  );

  it(
    'tamper: flipping a ciphertext byte surfaces VaultCorruptError/VAULT_CORRUPT (NOT AeadAuthError)',
    async () => {
      const worker = spawnWorker();
      try {
        const derivePromise = waitForMessage(worker);
        worker.postMessage({ type: 'derive', passphrase: DEMO_PASSPHRASE });
        await derivePromise;

        const encryptPromise = waitForMessage(worker);
        const plaintext = new TextEncoder().encode('tamper me');
        worker.postMessage({ type: 'encrypt', plaintext }, [plaintext.buffer]);
        const encryptResult = (await encryptPromise) as EncryptComplete;

        // Flip one byte of a COPY of the ciphertext (DEMO-05, D-03's "pick ANY
        // byte, break it yourself").
        const tampered = new Uint8Array(encryptResult.ciphertext);
        tampered[0] = tampered[0]! ^ 0xff;

        const decryptPromise = waitForMessage(worker);
        worker.postMessage(
          { type: 'decrypt', ciphertext: tampered, nonce: encryptResult.nonce },
          [tampered.buffer, encryptResult.nonce.buffer],
        );
        const result = (await decryptPromise) as WorkerErrorMessage;

        expect(result.type).toBe('decrypt-error');
        expect(result.code).toBe('VAULT_CORRUPT');
        expect(result.name).toBe('VaultCorruptError');
      } finally {
        worker.terminate();
      }
    },
    30_000,
  );

  it(
    'fresh: encrypting the same plaintext twice yields two different ciphertexts (fresh salt+nonce)',
    async () => {
      const worker = spawnWorker();
      try {
        const derivePromise = waitForMessage(worker);
        worker.postMessage({ type: 'derive', passphrase: DEMO_PASSPHRASE });
        await derivePromise;

        const plaintext = new TextEncoder().encode('same plaintext, twice');

        const encryptPromise1 = waitForMessage(worker);
        worker.postMessage({ type: 'encrypt', plaintext: plaintext.slice() });
        const result1 = (await encryptPromise1) as EncryptComplete;

        const encryptPromise2 = waitForMessage(worker);
        worker.postMessage({ type: 'encrypt', plaintext: plaintext.slice() });
        const result2 = (await encryptPromise2) as EncryptComplete;

        // DEMO-06: fresh nonce per sealData call means the two ciphertexts
        // (same key, same plaintext) must differ.
        expect(Array.from(result1.ciphertext)).not.toEqual(Array.from(result2.ciphertext));
        expect(Array.from(result1.nonce)).not.toEqual(Array.from(result2.nonce));
      } finally {
        worker.terminate();
      }
    },
    30_000,
  );

  it(
    'oom: an oversized memLimit triggers a REAL KdfResourceError, never a param downgrade',
    async () => {
      const worker = spawnWorker();
      try {
        const derivePromise = waitForMessage(worker);
        // 16 GiB — well above the 256 MiB floor (never below), real OOM.
        worker.postMessage({
          type: 'derive',
          passphrase: DEMO_PASSPHRASE,
          memLimitOverride: 17_179_869_184,
        });
        const result = (await derivePromise) as WorkerErrorMessage;

        expect(result.type).toBe('derive-error');
        expect(result.code).toBe('KDF_RESOURCE');
        expect(result.name).toBe('KdfResourceError');
      } finally {
        worker.terminate();
      }
    },
    30_000,
  );
});
