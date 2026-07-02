// apps/extension/src/lib/associationStore.test.ts
//
// fake-browser (wxt/testing/fake-browser) provides an in-memory
// chrome.storage.local implementation. Reset between tests per the WXT
// unit-testing guide so each test starts with empty storage.

import { beforeEach, describe, expect, it } from 'vitest';
import { fakeBrowser } from 'wxt/testing/fake-browser';
import { getOrCreateIdentityKeypair, loadAssociation, saveAssociation } from './associationStore';

describe('associationStore', () => {
  beforeEach(() => {
    fakeBrowser.reset();
  });

  it('getOrCreateIdentityKeypair() on empty storage generates a keypair and persists it', async () => {
    const keypair = await getOrCreateIdentityKeypair();

    expect(keypair.publicKey.length).toBe(32);
    expect(keypair.secretKey.length).toBe(32);

    const stored = await chrome.storage.local.get('cryptiq-identity-keypair');
    expect(stored['cryptiq-identity-keypair']).toBeDefined();
  });

  it('a second getOrCreateIdentityKeypair() call (simulated SW restart) returns the SAME keypair', async () => {
    const first = await getOrCreateIdentityKeypair();
    const second = await getOrCreateIdentityKeypair();

    expect(second.publicKey).toEqual(first.publicKey);
    expect(second.secretKey).toEqual(first.secretKey);
  });

  it('saveAssociation / loadAssociation round-trips the association record', async () => {
    const record = {
      hostPublicKey: 'aGVsbG8=',
      pairingToken: 'dG9rZW4tYmFzZTY0',
      label: 'Chrome',
    };

    await saveAssociation(record);
    const loaded = await loadAssociation();

    expect(loaded).toEqual(record);
  });

  it('loadAssociation() on empty storage returns null', async () => {
    const loaded = await loadAssociation();
    expect(loaded).toBeNull();
  });
});
