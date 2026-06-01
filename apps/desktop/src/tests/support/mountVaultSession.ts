// apps/desktop/src/tests/support/mountVaultSession.ts
//
// Single seam for component tests that need an unlocked VaultSession.
//
// ROLE: This is the ONLY place test specs should set up an unlocked session.
// Specs MUST NOT re-implement vault setup — import and call mountVaultSession()
// instead. This keeps the seam in one place and reduces test maintenance.
//
// HOW IT WORKS:
//   1. Creates a FakeVaultStorageAdapter (in-memory, no FS, no crypto output).
//   2. Calls vaultSession.create() with floor KDF params (256 MiB / 3 ops) to
//      produce a real UnlockedVault + mount it into the singleton VaultSession.
//      - createVault() uses libsodium WASM (available in the CT browser via vite-plugin-wasm).
//      - The floor params run real Argon2id (~1 s on a dev machine); acceptable for
//        test setup. Production vaults calibrate up from there.
//   3. vault_lock_acquire / vault_lock_release / vault_lock_check invoke calls are
//      intercepted by the @tauri-apps/api/core alias in playwright.config.ts
//      (mockTauriInvoke.ts) — no Tauri backend is needed.
//   4. Resets the adapter's save counters AFTER setup so specs start with a clean
//      (saveCount=0) spy state.
//
// SECURITY NOTE:
//   The test master password is a fixed ASCII string. No real secrets are involved.
//   The vault bytes produced are stored only in the FakeAdapter's in-memory buffer —
//   never written to disk, never logged.
//
// USAGE:
//   import { mountVaultSession } from '../support/mountVaultSession';
//
//   test('my component test', async ({ mount }) => {
//     const { session, adapter } = await mountVaultSession();
//     // session is now unlocked; adapter.saveCount / adapter.lastSavedBytes for assertions
//     const component = await mount(MyComponent, { props: {} });
//     // ...
//   });

import { vaultSession } from '../../lib/state/vault.svelte';
import { FakeVaultStorageAdapter } from '../fixtures/fakeAdapter';
import { getSodium } from '@cryptiq/core/internal';
import type { KdfParams } from '@cryptiq/core/internal';
import type { TauriVaultStorageAdapter } from '../../lib/adapters/TauriVaultStorageAdapter';

/** Fixed test master password bytes (ASCII "test-master-pw"). Not a real secret. */
const TEST_MASTER_PW = new TextEncoder().encode('test-master-pw');

/**
 * Build the floor Argon2id KDF params. Minimum params that pass core's floor check.
 * 256 MiB / 3 ops — still runs real Argon2id but skips the calibration ladder.
 */
async function floorKdfParams(): Promise<KdfParams> {
  const sodium = await getSodium();
  return {
    algorithm: 2 as const,
    opsLimit: 3,
    memLimit: 268_435_456, // 256 MiB — the non-negotiable floor (DC-1)
    salt: sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES),
  };
}

export interface MountedVaultSession {
  /** The module-level VaultSession singleton, now unlocked with a test vault. */
  session: typeof vaultSession;
  /** The in-memory fake adapter injected into the session. Use for save assertions. */
  adapter: FakeVaultStorageAdapter;
  /**
   * The serialized vault bytes that create() wrote on first save. Captured here
   * because a later `vaultSession.save()` would be skipped by the content-hash dedup
   * (the vault is unchanged since creation), leaving the caller with no bytes. Unlock
   * specs seed these into the FS mock so a fresh adapter can load + unlock the vault.
   */
  vaultBytes: Uint8Array | null;
}

/**
 * Mount a freshly-created test vault into the VaultSession singleton.
 *
 * Call this at the start of each component test (or in a beforeEach) that needs
 * an unlocked session. The session is left unlocked; call `session.lock()` in
 * afterEach if tests need a clean-lock state.
 *
 * @param vaultPath   Optional fake vault path label (default '/fake/vault.cryptiq').
 * @param seedEntries Optional: not used for creation but documented for future use
 *                    when mountVaultSession grows a "seed with entries" option.
 */
export async function mountVaultSession(
  vaultPath = '/fake/vault.cryptiq',
): Promise<MountedVaultSession> {
  // Lock any existing session first (idempotent if already locked).
  if (vaultSession.isUnlocked) {
    await vaultSession.lock();
  }

  const adapter = new FakeVaultStorageAdapter(vaultPath);

  // createVault runs real Argon2id (floor params) but writes to the in-memory adapter.
  // vault_lock_acquire invoke is intercepted by the @tauri-apps/api/core mock.
  // The cast is safe: FakeVaultStorageAdapter exposes every member VaultSession reads
  // from TauriVaultStorageAdapter (structural duck-typing).
  await vaultSession.create(
    adapter as unknown as TauriVaultStorageAdapter,
    TEST_MASTER_PW,
    false, // no recovery key — not needed for component tests
    await floorKdfParams(),
  );

  // Capture the bytes create() wrote BEFORE resetting the spy fields below — a later
  // vaultSession.save() would be deduped (unchanged content) and never re-emit them.
  const vaultBytes = adapter.lastSavedBytes
    ? new Uint8Array(adapter.lastSavedBytes)
    : null;

  // Reset save counter so test assertions start from 0.
  // (create() itself calls adapter.save() once during setup — we ignore that.)
  adapter.saveCount = 0;
  adapter.lastSavedBytes = null;
  adapter.lastContentHash = null;
  adapter.initHashCalls = 0;

  return { session: vaultSession, adapter, vaultBytes };
}
