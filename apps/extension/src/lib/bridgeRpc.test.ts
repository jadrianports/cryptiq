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

  it('sendRpc seals { pairingToken, ...inner } and the outer envelope has ONLY { nonce, box } — token never in the outer envelope', async () => {
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
    const payload = envelope.payload as { nonce: string; box: string; pairingToken?: unknown };
    expect(typeof payload.nonce).toBe('string');
    expect(typeof payload.box).toBe('string');
    // The outer envelope payload has ONLY nonce+box — no pairingToken key.
    expect(payload.pairingToken).toBeUndefined();
    expect(Object.keys(payload).sort()).toEqual(['box', 'nonce']);

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

    emit({ protocolVersion: 1, type: 'rpc-ok', id: envelope.id, payload: { ok: true } });
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

    const { port, sent, emit } = createFakePort();

    const first = sendRpc(port, { rpcType: 'match-origin' });
    await vi.waitFor(() => expect(sent).toHaveLength(1));
    emit({ type: 'rpc-ok', id: sent[0].id, payload: {} });
    await first;

    const second = sendRpc(port, { rpcType: 'match-origin' });
    await vi.waitFor(() => expect(sent).toHaveLength(2));
    emit({ type: 'rpc-ok', id: sent[1].id, payload: {} });
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
});
