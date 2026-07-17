// apps/desktop/src/lib/state/__tests__/updateApplySeamOrdering.test.ts
//
// Phase 36 (UPD-05 apply-seam guard, Plan 07) — CALL-ORDER test.
//
// Pins the BEFORE-derive / AFTER-wipe call ORDER (not merely presence) that IS the safety
// argument for VaultLockState — see vault.svelte.ts's unlock()/create()/lock() comments and
// update.rs's VaultLockState doc comment for the full rationale. An ordering test that only
// checks both calls happened would pass against a reordered, unsafe version.
//
// Mechanism: Vitest's `mock.invocationCallOrder` is a monotonic counter shared GLOBALLY
// across every vi.fn() in the process — comparable across DIFFERENT mocked functions, not
// just calls within the same mock. That lets this test assert the true relative order of
// `invoke('vault_lock_state_set', ...)` versus `unlockVault`/`createVault`/`secureWipe`
// WITHOUT needing any application-level "call log" seam.
//
// Node environment (vitest.config.ts: environment: 'node') — mirrors saveLockRace.test.ts's
// mock strategy: invoke is a bare vi.fn() stub; unlockVault/createVault/secureWipe are REAL
// implementations wrapped in vi.fn() spies (real Argon2id/AEAD still runs — this test drives
// the genuine create()/unlock()/lock() flows, not a stand-in) purely to capture their
// invocationCallOrder.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(),
}));

vi.mock('@cryptiq/core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cryptiq/core')>();
  return {
    ...actual,
    unlockVault: vi.fn(actual.unlockVault),
    createVault: vi.fn(actual.createVault),
    secureWipe: vi.fn(actual.secureWipe),
  };
});

import { invoke } from '@tauri-apps/api/core';
import { unlockVault, createVault, secureWipe } from '@cryptiq/core';
import { FakeVaultStorageAdapter } from '../../../tests/fixtures/fakeAdapter';
import { getSodium } from '@cryptiq/core/internal';
import type { TauriVaultStorageAdapter } from '../../adapters/TauriVaultStorageAdapter';

const mockInvoke = vi.mocked(invoke);
const mockUnlockVault = vi.mocked(unlockVault);
const mockCreateVault = vi.mocked(createVault);
const mockSecureWipe = vi.mocked(secureWipe);

/** Fixed test master password bytes. Not a real secret. */
const TEST_MASTER_PW = new TextEncoder().encode('test-master-pw-ordering');

/** Floor Argon2id params (256 MiB / 3 ops) — skips the calibration ladder for test speed. */
async function floorKdfParams() {
  const sodium = await getSodium();
  return {
    algorithm: 2 as const,
    opsLimit: 3,
    memLimit: 268_435_456,
    salt: sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES),
  };
}

/**
 * The `invocationCallOrder` of the FIRST `invoke()` call matching `(command, unlocked)`.
 * Fails the assertion (not silently returns -1) if no such call was recorded — an ordering
 * test that can't find the call it's meant to order is a broken test, not a passing one.
 */
function firstSetInvokeOrder(unlocked: boolean): number {
  const idx = mockInvoke.mock.calls.findIndex(([cmd, args]) => {
    if (cmd !== 'vault_lock_state_set') return false;
    const a = args as { unlocked?: boolean } | undefined;
    return a?.unlocked === unlocked;
  });
  expect(idx).toBeGreaterThanOrEqual(0);
  return mockInvoke.mock.invocationCallOrder[idx]!;
}

describe('VaultLockState mirror ordering — Phase 36 UPD-05', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockInvoke.mockResolvedValue(undefined);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('create(): vault_lock_state_set(unlocked=true) fires BEFORE createVault (the Argon2id derive)', async () => {
    const { vaultSession } = await import('../vault.svelte');
    const adapter = new FakeVaultStorageAdapter('/fake/vault-ordering-create.cryptiq');

    await vaultSession.create(
      adapter as unknown as TauriVaultStorageAdapter,
      TEST_MASTER_PW,
      false,
      await floorKdfParams(),
    );

    expect(mockCreateVault.mock.invocationCallOrder.length).toBeGreaterThan(0);
    const setUnlockedOrder = firstSetInvokeOrder(true);
    const createVaultOrder = mockCreateVault.mock.invocationCallOrder[0]!;
    expect(setUnlockedOrder).toBeLessThan(createVaultOrder);

    await vaultSession.lock();
  });

  it('unlock(): vault_lock_state_set(unlocked=true) fires BEFORE unlockVault (the Argon2id derive)', async () => {
    const { vaultSession } = await import('../vault.svelte');

    // First, create + lock a real vault so there are real bytes to unlock.
    const createAdapter = new FakeVaultStorageAdapter('/fake/vault-ordering-unlock.cryptiq');
    await vaultSession.create(
      createAdapter as unknown as TauriVaultStorageAdapter,
      TEST_MASTER_PW,
      false,
      await floorKdfParams(),
    );
    const savedBytes = createAdapter.lastSavedBytes;
    expect(savedBytes).not.toBeNull();
    await vaultSession.lock();

    // Reset call tracking so THIS unlock() attempt's ordering is isolated from create()'s.
    vi.clearAllMocks();
    mockInvoke.mockResolvedValue(undefined);

    const unlockAdapter = new FakeVaultStorageAdapter(
      '/fake/vault-ordering-unlock.cryptiq',
      savedBytes!,
    );

    await vaultSession.unlock(unlockAdapter as unknown as TauriVaultStorageAdapter, {
      masterPassword: TEST_MASTER_PW,
    });

    const setUnlockedOrder = firstSetInvokeOrder(true);
    const unlockVaultOrder = mockUnlockVault.mock.invocationCallOrder[0]!;
    expect(setUnlockedOrder).toBeLessThan(unlockVaultOrder);

    await vaultSession.lock();
  });

  it('lock(): vault_lock_state_set(unlocked=false) fires AFTER secureWipe', async () => {
    const { vaultSession } = await import('../vault.svelte');
    const adapter = new FakeVaultStorageAdapter('/fake/vault-ordering-lock.cryptiq');

    await vaultSession.create(
      adapter as unknown as TauriVaultStorageAdapter,
      TEST_MASTER_PW,
      false,
      await floorKdfParams(),
    );

    // Reset call tracking so lock()'s ordering is isolated from create()'s own invoke calls.
    vi.clearAllMocks();
    mockInvoke.mockResolvedValue(undefined);

    await vaultSession.lock();

    expect(mockSecureWipe.mock.invocationCallOrder.length).toBeGreaterThan(0);
    const secureWipeOrder = mockSecureWipe.mock.invocationCallOrder[0]!;
    const setLockedOrder = firstSetInvokeOrder(false);
    expect(setLockedOrder).toBeGreaterThan(secureWipeOrder);
  });
});
