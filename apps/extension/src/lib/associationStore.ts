// apps/extension/src/lib/associationStore.ts
//
// Wraps chrome.storage.local for the extension's two persisted trust
// artifacts:
//
//   1. The PERMANENT identification keypair (Pitfall 2, CRITICAL): loaded
//      once, generated only if absent, and never regenerated on a
//      subsequent call — including after an MV3 service-worker teardown.
//      Regenerating this keypair per SW wake would make every reconnect
//      look like a brand-new extension to the app, breaking SC-1's
//      "subsequent connections are silently trusted" requirement.
//   2. The association record `{ hostPublicKey, pairingToken, label }`
//      returned by the app at `associate-ok` (consumed by Plan 06's
//      background wiring).
//
// Pure of DOM/Svelte; depends only on chrome.storage.local and
// associationCrypto's base64 helpers. No vault key ever touches this
// module (T-15-06 thin-client boundary) — it is a transport-only store.

import nacl from 'tweetnacl';
import { base64ToBytes, bytesToBase64 } from './associationCrypto';

const IDENTITY_KEYPAIR_STORAGE_KEY = 'cryptiq-identity-keypair';
const ASSOCIATION_STORAGE_KEY = 'cryptiq-association';

export interface IdentityKeypair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

interface StoredIdentityKeypair {
  publicKey: string; // base64
  secretKey: string; // base64
}

export interface AssociationRecord {
  hostPublicKey: string; // base64 — the app's box public key
  pairingToken: string; // base64 — bearer token minted at approval
  label: string; // auto-labeled from detected browser (D-02), renamable later
}

/**
 * Load the permanent identification keypair from chrome.storage.local,
 * generating and persisting ONE the first time this is ever called. Every
 * subsequent call (including after a fresh SW start) returns the SAME
 * keypair — never a freshly generated one.
 */
export async function getOrCreateIdentityKeypair(): Promise<IdentityKeypair> {
  const existing = await chrome.storage.local.get(IDENTITY_KEYPAIR_STORAGE_KEY);
  const stored = existing[IDENTITY_KEYPAIR_STORAGE_KEY] as StoredIdentityKeypair | undefined;

  if (stored) {
    return {
      publicKey: base64ToBytes(stored.publicKey),
      secretKey: base64ToBytes(stored.secretKey),
    };
  }

  const generated = nacl.box.keyPair();
  const toStore: StoredIdentityKeypair = {
    publicKey: bytesToBase64(generated.publicKey),
    secretKey: bytesToBase64(generated.secretKey),
  };
  await chrome.storage.local.set({ [IDENTITY_KEYPAIR_STORAGE_KEY]: toStore });

  return {
    publicKey: generated.publicKey,
    secretKey: generated.secretKey,
  };
}

/** Persist the association record returned by the app at `associate-ok`. */
export async function saveAssociation(record: AssociationRecord): Promise<void> {
  await chrome.storage.local.set({ [ASSOCIATION_STORAGE_KEY]: record });
}

/**
 * Load the persisted association record. Returns null (never
 * undefined/throw) when no association exists — the extension treats
 * itself as un-associated and re-runs the `associate` handshake.
 */
export async function loadAssociation(): Promise<AssociationRecord | null> {
  const existing = await chrome.storage.local.get(ASSOCIATION_STORAGE_KEY);
  const stored = existing[ASSOCIATION_STORAGE_KEY] as AssociationRecord | undefined;
  return stored ?? null;
}
