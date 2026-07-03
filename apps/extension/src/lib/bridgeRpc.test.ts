// apps/extension/src/lib/bridgeRpc.test.ts
//
// Covers the four behaviors from 15-06-PLAN.md Task 1: plaintext
// associate, token sealed INSIDE the box (never the outer envelope),
// fresh nonce per sendRpc call, and error-code mapping.

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fakeBrowser } from 'wxt/testing/fake-browser';
import nacl from 'tweetnacl';
import { base64ToBytes, bytesToBase64 } from './associationCrypto';
import { getOrCreateIdentityKeypair, saveAssociation } from './associationStore';
import { sendAssociate, sendRpc } from './bridgeRpc';

/**
 * Seal a plaintext object app-secret -> extension-public, mirroring the real
 * app's response direction (the reverse of sealForHost, which is
 * extension-secret -> host-public). Used to construct genuine `rpc-ok`
 * `{ nonce, box }` payloads in tests.
 */
function sealAppResponse(
  plaintextObj: unknown,
  extensionPublicKey: Uint8Array,
  hostSecretKey: Uint8Array,
): { nonce: string; box: string } {
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const plaintextBytes = new TextEncoder().encode(JSON.stringify(plaintextObj));
  const box = nacl.box(plaintextBytes, nonce, extensionPublicKey, hostSecretKey);
  return { nonce: bytesToBase64(nonce), box: bytesToBase64(box) };
}

interface FakePort {
  port: chrome.runtime.Port;
  sent: Array<{ id: string; type: string; payload: Record<string, unknown> }>;
  listeners: Array<(msg: unknown) => void>;
  emit: (msg: unknown) => void;
}

function createFakePort(): FakePort {
  const sent: Array<{ id: string; type: string; payload: Record<string, unknown> }> = [];
  const listeners: Array<(msg: unknown) => void> = [];

  const port = {
    postMessage: (msg: { id: string; type: string; payload: Record<string, unknown> }) => {
      sent.push(msg);
    },
    onMessage: {
      addListener: (fn: (msg: unknown) => void) => {
        listeners.push(fn);
      },
      removeListener: (fn: (msg: unknown) => void) => {
        const idx = listeners.indexOf(fn);
        if (idx >= 0) listeners.splice(idx, 1);
      },
    },
  } as unknown as chrome.runtime.Port;

  return {
    port,
    sent,
    listeners,
    emit: (msg: unknown) => {
      // Snapshot before iterating — a listener may remove itself mid-call.
      for (const listener of [...listeners]) listener(msg);
    },
  };
}

describe('bridgeRpc', () => {
  beforeEach(() => {
    fakeBrowser.reset();
  });

  it('sendAssociate posts a PLAINTEXT associate envelope (no nonce/box)', async () => {
    const { port, sent, emit } = createFakePort();

    const promise = sendAssociate(port, { clientPublicKey: 'abc-pubkey', label: 'Chrome' });

    expect(sent).toHaveLength(1);
    expect(sent[0].type).toBe('associate');
    expect(sent[0].payload).toEqual({ clientPublicKey: 'abc-pubkey', label: 'Chrome' });
    expect((sent[0].payload as Record<string, unknown>).nonce).toBeUndefined();
    expect((sent[0].payload as Record<string, unknown>).box).toBeUndefined();

    emit({
      protocolVersion: 1,
      type: 'associate-ok',
      id: sent[0].id,
      payload: { hostPublicKey: 'host-pubkey-b64', pairingToken: 'token-b64' },
    });

    const result = await promise;
    expect(result).toEqual({ ok: true, hostPublicKey: 'host-pubkey-b64', pairingToken: 'token-b64' });
  });

  it('sendRpc seals { pairingToken, ...inner }; outer envelope carries { clientPublicKey, nonce, box } — token never in the outer envelope', async () => {
    const hostKeypair = nacl.box.keyPair();
    await saveAssociation({
      hostPublicKey: bytesToBase64(hostKeypair.publicKey),
      pairingToken: 'super-secret-pairing-token',
      label: 'Chrome',
    });
    const identity = await getOrCreateIdentityKeypair();

    const { port, sent, emit } = createFakePort();

    const promise = sendRpc(port, { rpcType: 'match-origin', origin: 'https://example.com' });

    await vi.waitFor(() => expect(sent).toHaveLength(1));

    const envelope = sent[0];
    expect(envelope.type).toBe('rpc');
    const payload = envelope.payload as {
      clientPublicKey: string;
      nonce: string;
      box: string;
      pairingToken?: unknown;
    };
    expect(typeof payload.nonce).toBe('string');
    expect(typeof payload.box).toBe('string');
    // clientPublicKey rides the OUTER envelope (public, non-secret peer identifier the
    // app uses to look up the cached shared key + token hash and open the box) — it
    // equals this extension's identity public key, matching the associate envelope.
    expect(payload.clientPublicKey).toBe(bytesToBase64(identity.publicKey));
    // The outer envelope has clientPublicKey+nonce+box — and crucially NO pairingToken
    // (the token rides INSIDE the sealed box only — T-15-04).
    expect(payload.pairingToken).toBeUndefined();
    expect(Object.keys(payload).sort()).toEqual(['box', 'clientPublicKey', 'nonce']);

    // Decrypt with the host's secret key to prove the token rides INSIDE
    // the box.
    const nonceBytes = base64ToBytes(payload.nonce);
    const boxBytes = base64ToBytes(payload.box);
    const opened = nacl.box.open(boxBytes, nonceBytes, identity.publicKey, hostKeypair.secretKey);
    expect(opened).not.toBeNull();
    const plaintext = JSON.parse(new TextDecoder().decode(opened as Uint8Array));
    expect(plaintext.pairingToken).toBe('super-secret-pairing-token');
    expect(plaintext.rpcType).toBe('match-origin');
    expect(plaintext.origin).toBe('https://example.com');

    const sealedResponse = sealAppResponse({ ok: true }, identity.publicKey, hostKeypair.secretKey);
    emit({ protocolVersion: 1, type: 'rpc-ok', id: envelope.id, payload: sealedResponse });
    const result = await promise;
    expect(result).toEqual({ ok: true, payload: { ok: true } });
  });

  it('sendRpc uses a FRESH nonce per call', async () => {
    const hostKeypair = nacl.box.keyPair();
    await saveAssociation({
      hostPublicKey: bytesToBase64(hostKeypair.publicKey),
      pairingToken: 'token-b64',
      label: 'Chrome',
    });
    const identity = await getOrCreateIdentityKeypair();

    const { port, sent, emit } = createFakePort();

    const first = sendRpc(port, { rpcType: 'match-origin' });
    await vi.waitFor(() => expect(sent).toHaveLength(1));
    emit({ type: 'rpc-ok', id: sent[0].id, payload: sealAppResponse({}, identity.publicKey, hostKeypair.secretKey) });
    await first;

    const second = sendRpc(port, { rpcType: 'match-origin' });
    await vi.waitFor(() => expect(sent).toHaveLength(2));
    emit({ type: 'rpc-ok', id: sent[1].id, payload: sealAppResponse({}, identity.publicKey, hostKeypair.secretKey) });
    await second;

    const nonceOne = (sent[0].payload as { nonce: string }).nonce;
    const nonceTwo = (sent[1].payload as { nonce: string }).nonce;
    expect(nonceOne).not.toBe(nonceTwo);
  });

  it('maps an incoming error envelope to a typed result carrying code + message (sendAssociate)', async () => {
    const { port, sent, emit } = createFakePort();

    const promise = sendAssociate(port, { clientPublicKey: 'abc', label: 'Chrome' });
    emit({
      protocolVersion: 1,
      type: 'error',
      id: sent[0].id,
      payload: { code: 'extension-outdated', message: 'Update the Cryptiq extension.' },
    });

    const result = await promise;
    expect(result).toEqual({ ok: false, code: 'extension-outdated', message: 'Update the Cryptiq extension.' });
  });

  it('maps an incoming error envelope to a typed result carrying code + message (sendRpc)', async () => {
    const hostKeypair = nacl.box.keyPair();
    await saveAssociation({
      hostPublicKey: bytesToBase64(hostKeypair.publicKey),
      pairingToken: 'token-b64',
      label: 'Chrome',
    });

    const { port, sent, emit } = createFakePort();
    const promise = sendRpc(port, { rpcType: 'match-origin' });
    await vi.waitFor(() => expect(sent).toHaveLength(1));

    emit({
      protocolVersion: 1,
      type: 'error',
      id: sent[0].id,
      payload: { code: 'invalid-token', message: 'Pairing check failed.' },
    });

    const result = await promise;
    expect(result).toEqual({ ok: false, code: 'invalid-token', message: 'Pairing check failed.' });
  });

  it('sendRpc resolves not-associated when no association is stored', async () => {
    const { port } = createFakePort();
    const result = await sendRpc(port, { rpcType: 'match-origin' });
    expect(result).toEqual({ ok: false, code: 'not-associated' });
  });

  // --- 16-06-PLAN.md Task 1: decrypt the rpc-ok success box, fail closed. ---

  it('sendRpc decrypts an authentic rpc-ok box to ok:true with the parsed payload (BUG-2)', async () => {
    const hostKeypair = nacl.box.keyPair();
    await saveAssociation({
      hostPublicKey: bytesToBase64(hostKeypair.publicKey),
      pairingToken: 'token-b64',
      label: 'Chrome',
    });
    const identity = await getOrCreateIdentityKeypair();

    const { port, sent, emit } = createFakePort();
    const promise = sendRpc(port, { rpcType: 'match-origin' });
    await vi.waitFor(() => expect(sent).toHaveLength(1));

    const candidatesPayload = { candidates: [{ id: 'e1', title: 'Example', username: 'me', domainHint: 'example.com' }] };
    const sealedResponse = sealAppResponse(candidatesPayload, identity.publicKey, hostKeypair.secretKey);
    emit({ protocolVersion: 1, type: 'rpc-ok', id: sent[0].id, payload: sealedResponse });

    const result = await promise;
    expect(result).toEqual({ ok: true, payload: candidatesPayload });
  });

  it('sendRpc fails closed with protocol-error when the rpc-ok box fails authentication (tampered/wrong key)', async () => {
    const hostKeypair = nacl.box.keyPair();
    await saveAssociation({
      hostPublicKey: bytesToBase64(hostKeypair.publicKey),
      pairingToken: 'token-b64',
      label: 'Chrome',
    });
    const identity = await getOrCreateIdentityKeypair();

    const { port, sent, emit } = createFakePort();
    const promise = sendRpc(port, { rpcType: 'match-origin' });
    await vi.waitFor(() => expect(sent).toHaveLength(1));

    // Seal toward a mismatched keypair so openFromHost (nacl.box.open) fails
    // authentication and returns null.
    const wrongKeypair = nacl.box.keyPair();
    const sealedResponse = sealAppResponse({ candidates: [] }, identity.publicKey, wrongKeypair.secretKey);
    emit({ protocolVersion: 1, type: 'rpc-ok', id: sent[0].id, payload: sealedResponse });

    const result = await promise;
    expect(result).toEqual({ ok: false, code: 'protocol-error' });
  });

  it('sendRpc fails closed with protocol-error when the opened box is not valid JSON', async () => {
    const hostKeypair = nacl.box.keyPair();
    await saveAssociation({
      hostPublicKey: bytesToBase64(hostKeypair.publicKey),
      pairingToken: 'token-b64',
      label: 'Chrome',
    });
    const identity = await getOrCreateIdentityKeypair();

    const { port, sent, emit } = createFakePort();
    const promise = sendRpc(port, { rpcType: 'match-origin' });
    await vi.waitFor(() => expect(sent).toHaveLength(1));

    // Seal correctly (authenticates fine) but the plaintext is not JSON.
    const nonce = nacl.randomBytes(nacl.box.nonceLength);
    const plaintextBytes = new TextEncoder().encode('not-json{{{');
    const box = nacl.box(plaintextBytes, nonce, identity.publicKey, hostKeypair.secretKey);
    emit({
      protocolVersion: 1,
      type: 'rpc-ok',
      id: sent[0].id,
      payload: { nonce: bytesToBase64(nonce), box: bytesToBase64(box) },
    });

    const result = await promise;
    expect(result).toEqual({ ok: false, code: 'protocol-error' });
  });

  it('sendRpc maps a vault-locked error envelope to ok:false code:vault-locked WITHOUT running the decrypt path (BUG-3 contract)', async () => {
    const hostKeypair = nacl.box.keyPair();
    await saveAssociation({
      hostPublicKey: bytesToBase64(hostKeypair.publicKey),
      pairingToken: 'token-b64',
      label: 'Chrome',
    });

    const { port, sent, emit } = createFakePort();
    const promise = sendRpc(port, { rpcType: 'match-origin' });
    await vi.waitFor(() => expect(sent).toHaveLength(1));

    // A plaintext error envelope — no nonce/box at all, proving the
    // decrypt path is never touched for this case.
    emit({
      protocolVersion: 1,
      type: 'error',
      id: sent[0].id,
      payload: { code: 'vault-locked', message: 'Unlock Cryptiq to continue.' },
    });

    const result = await promise;
    expect(result).toEqual({ ok: false, code: 'vault-locked', message: 'Unlock Cryptiq to continue.' });
  });

  it('sendRpc fails closed with protocol-error when the rpc-ok nonce/box are not valid base64 (atob throw path)', async () => {
    const hostKeypair = nacl.box.keyPair();
    await saveAssociation({
      hostPublicKey: bytesToBase64(hostKeypair.publicKey),
      pairingToken: 'token-b64',
      label: 'Chrome',
    });

    const { port, sent, emit } = createFakePort();
    const promise = sendRpc(port, { rpcType: 'match-origin' });
    await vi.waitFor(() => expect(sent).toHaveLength(1));

    // Non-base64 characters make base64ToBytes -> atob() throw a DOMException
    // synchronously inside the listener (NOT a JSON.parse failure). The
    // decode+open+parse try/catch must catch it and fail closed rather than
    // let it escape uncaught.
    emit({ protocolVersion: 1, type: 'rpc-ok', id: sent[0].id, payload: { nonce: '!!!not-base64!!!', box: '@@@' } });

    const result = await promise;
    expect(result).toEqual({ ok: false, code: 'protocol-error' });
  });
});
