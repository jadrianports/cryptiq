// apps/desktop/src/lib/sync/__tests__/syncOrchestration.test.ts
//
// Plan 11-04 — behavioral Vitest suite for the Phase-11 merge continuation.
//
// Test environment: node (same as saveMutex.test.ts).
// Crypto:           real @cryptiq/core WASM (libsodium aliased to CJS build in vitest.config.ts).
// Tauri:            vi.mock('@tauri-apps/api/core') + vi.mock('@tauri-apps/plugin-fs')
//                   — same mock idiom as saveMutex.test.ts.
//
// Tests:
//   Task 2 — applyRemoteMergedBlob (A-side, D-11):
//   1. 'does not invoke save when cold-verify fails (SAFE-03 abort-before-write)'
//      — saveBBlob AND saveABlob spies are NOT called on cold-verify failure.
//   2. 'saves B then A in order on the happy path (D-01 ordering)'
//      — calls=['B','A'] asserted; returned counts match expected.
//
//   Task 3 — handleMergedBlobForB (B-side, D-01/D-07):
//   3. 'B handler confirms true and reloads on success'
//      — confirmSave(true) called once, reloadSession called once.
//   4. 'B handler confirms false and does not reload on forced failure'
//      — confirmSave(false) called, reloadSession NOT called.
//
// SAFE-03 note: Test 1 proves the abort-before-write invariant: when the cold-verify
// step fails (SyncTransportError), neither save callback is ever invoked. This is the
// behavioral proof that no disk write occurs on a verification failure.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  createVault,
  resealInnerDoc,
  mergeInnerDocs,
  parseOuter,
  decryptInner,
  SyncTransportError,
} from '@cryptiq/core';
import type { InnerDoc, MergeContext } from '@cryptiq/core';
import { getSodium } from '@cryptiq/core/internal';
import {
  applyRemoteMergedBlob,
  handleMergedBlobForB,
} from '../syncOrchestration';

// ---------------------------------------------------------------------------
// Module mocks — same idiom as saveMutex.test.ts
// ---------------------------------------------------------------------------

vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(),
}));

vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn(async () => () => {}),
}));

vi.mock('@tauri-apps/plugin-fs', () => ({
  exists: vi.fn(),
  readFile: vi.fn(),
  stat: vi.fn(),
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const FLOOR_OPS = 3;
const FLOOR_MEM = 268_435_456; // 256 MiB

function pw(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

async function floorParams() {
  const sodium = await getSodium();
  return {
    algorithm: 2 as const,
    opsLimit: FLOOR_OPS,
    memLimit: FLOOR_MEM,
    salt: sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES),
  };
}

/**
 * Build a real vault fixture with floor KDF params.
 * Returns { bytes, vaultKey, doc, innerDoc }.
 */
async function makeVaultFixture(masterPw: Uint8Array) {
  const result = await createVault({
    masterPassword: masterPw,
    withRecoveryKey: false,
    kdfParams: await floorParams(),
  });
  const { vault, vaultKey } = result;
  const bytes = await (await import('@cryptiq/core')).saveVault(vault, vaultKey);
  const doc = parseOuter(bytes);
  const innerBytes = await decryptInner(doc.data, vaultKey);
  const innerDoc = JSON.parse(new TextDecoder().decode(innerBytes)) as InnerDoc;
  return { bytes, vaultKey, doc, innerDoc };
}

// ---------------------------------------------------------------------------
// Task 2: A-side applyRemoteMergedBlob
// ---------------------------------------------------------------------------

describe('applyRemoteMergedBlob', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it(
    'does not invoke save when cold-verify fails (SAFE-03 abort-before-write)',
    async () => {
      // Build two real vault fixtures with the SAME master password (SYNC-05).
      const masterPw = pw('shared-master-password-for-test!');
      const [aFixture, bFixture] = await Promise.all([
        makeVaultFixture(masterPw),
        makeVaultFixture(masterPw),
      ]);

      const saveB = vi.fn(async () => {});
      const saveA = vi.fn(async () => {});

      const mergeCtx: MergeContext = {
        localDeviceId: 'device-a',
        remoteDeviceId: 'device-b',
        localNowMs: 1_700_000_000_000,
        remoteNowMs: 1_700_000_000_000,
      };

      // Provide a WRONG masterPassword for cold-verify — unlockVault will fail (MAC error),
      // which applyRemoteMergedBlob wraps as SyncTransportError (abort-before-write).
      const wrongPw = pw('this-is-the-WRONG-master-password!');

      await expect(
        applyRemoteMergedBlob({
          aInner: aFixture.innerDoc,
          aVaultKey: aFixture.vaultKey,
          aDoc: aFixture.doc,
          bInner: bFixture.innerDoc,
          bVaultKey: bFixture.vaultKey,
          bDoc: bFixture.doc,
          mergeCtx,
          saveBBlob: saveB,
          saveABlob: saveA,
          masterPassword: wrongPw,
        }),
      ).rejects.toThrow(SyncTransportError);

      // SAFE-03 abort-before-write: neither save callback must have been called.
      expect(saveB).not.toHaveBeenCalled();
      expect(saveA).not.toHaveBeenCalled();
    },
    30_000, // real Argon2id runs — generous timeout
  );

  it(
    'saves B then A in order on the happy path (D-01 ordering)',
    async () => {
      const masterPw = pw('shared-master-password-happy-path!');
      const [aFixture, bFixture] = await Promise.all([
        makeVaultFixture(masterPw),
        makeVaultFixture(masterPw),
      ]);

      const calls: string[] = [];
      const saveB = vi.fn(async (_bytes: Uint8Array) => {
        calls.push('B');
      });
      const saveA = vi.fn(async (_bytes: Uint8Array) => {
        calls.push('A');
      });

      const mergeCtx: MergeContext = {
        localDeviceId: 'device-a',
        remoteDeviceId: 'device-b',
        localNowMs: 1_700_000_000_000,
        remoteNowMs: 1_700_000_000_000,
      };

      const counts = await applyRemoteMergedBlob({
        aInner: aFixture.innerDoc,
        aVaultKey: aFixture.vaultKey,
        aDoc: aFixture.doc,
        bInner: bFixture.innerDoc,
        bVaultKey: bFixture.vaultKey,
        bDoc: bFixture.doc,
        mergeCtx,
        saveBBlob: saveB,
        saveABlob: saveA,
        masterPassword: masterPw,
      });

      // D-01 ordering: B saves first, then A.
      expect(calls).toEqual(['B', 'A']);

      // Both callbacks called exactly once.
      expect(saveB).toHaveBeenCalledTimes(1);
      expect(saveA).toHaveBeenCalledTimes(1);

      // Returns MergeCounts (both vaults have no entries → zero counts).
      expect(counts).toMatchObject({
        added: 0,
        updated: 0,
        deleted: 0,
        unchanged: 0,
      });
    },
    60_000, // two cold-verifies with real Argon2id
  );
});

// ---------------------------------------------------------------------------
// Task 3: B-side handleMergedBlobForB
// ---------------------------------------------------------------------------

describe('handleMergedBlobForB', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it(
    'B handler confirms true and reloads on success (D-01/D-07)',
    async () => {
      const masterPw = pw('b-handler-test-master-password!');
      const bFixture = await makeVaultFixture(masterPw);

      // Build a merged blob: use the B fixture's own inner doc merged with itself
      // (idempotent re-merge from syncRemerge.test.ts: same doc = no-op).
      const mergeCtx: MergeContext = {
        localDeviceId: 'device-b',
        remoteDeviceId: 'device-a',
        localNowMs: 1_700_000_000_000,
        remoteNowMs: 1_700_000_000_000,
      };
      const mergeResult = mergeInnerDocs(bFixture.innerDoc, bFixture.innerDoc, mergeCtx);
      // Re-seal the merged doc under B's key to simulate the blob A would send.
      const blobBytes = await resealInnerDoc(mergeResult.merged, bFixture.vaultKey, bFixture.doc);

      // Set up DI seam spies.
      const confirmSave = vi.fn(async (_saveOk: boolean) => {});
      const reloadSession = vi.fn(async (_entries: object) => {});
      const saveBlob = vi.fn(async (_sealedBytes: Uint8Array) => {});

      await handleMergedBlobForB(blobBytes, {
        getBSessionKey: () => bFixture.vaultKey,
        getBCurrentInner: () => bFixture.innerDoc,
        getBDoc: () => bFixture.doc,
        saveBlob,
        reloadSession,
        confirmSave,
      });

      // D-01: confirmSave(true) called exactly once.
      expect(confirmSave).toHaveBeenCalledWith(true);
      expect(confirmSave).not.toHaveBeenCalledWith(false);

      // D-07: reloadSession called exactly once with the merged entries.
      expect(reloadSession).toHaveBeenCalledTimes(1);

      // Save path executed.
      expect(saveBlob).toHaveBeenCalledTimes(1);
    },
    30_000,
  );

  it(
    'B handler confirms false and does not reload on forced failure',
    async () => {
      const masterPw = pw('b-handler-failure-test-password!');
      const bFixture = await makeVaultFixture(masterPw);

      // Build a valid merged blob.
      const mergeCtx: MergeContext = {
        localDeviceId: 'device-b',
        remoteDeviceId: 'device-a',
        localNowMs: 1_700_000_000_000,
        remoteNowMs: 1_700_000_000_000,
      };
      const mergeResult = mergeInnerDocs(bFixture.innerDoc, bFixture.innerDoc, mergeCtx);
      const blobBytes = await resealInnerDoc(mergeResult.merged, bFixture.vaultKey, bFixture.doc);

      // Force save to throw — simulates disk full / save failure.
      const confirmSave = vi.fn(async (_saveOk: boolean) => {});
      const reloadSession = vi.fn(async (_entries: object) => {});
      const saveBlob = vi.fn(async (_sealedBytes: Uint8Array) => {
        throw new Error('disk full — save failure forced');
      });

      await handleMergedBlobForB(blobBytes, {
        getBSessionKey: () => bFixture.vaultKey,
        getBCurrentInner: () => bFixture.innerDoc,
        getBDoc: () => bFixture.doc,
        saveBlob,
        reloadSession,
        confirmSave,
      });

      // On failure: confirmSave(false) called.
      expect(confirmSave).toHaveBeenCalledWith(false);
      expect(confirmSave).not.toHaveBeenCalledWith(true);

      // B's session is NOT reloaded when the save failed (plan requirement: "no reload"
      // on any failure path — saveBlob throws before reloadSession is reached).
      expect(reloadSession).not.toHaveBeenCalled();
    },
    30_000,
  );
});
