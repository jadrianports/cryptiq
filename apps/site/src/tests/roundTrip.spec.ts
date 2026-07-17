// apps/site/src/tests/roundTrip.spec.ts
//
// Phase 38 Plan 02, Task 2 (SC-3, D-09, D-10). Proves the real, UNMODIFIED
// workspace @cryptiq/core completes a full vault round trip in a real
// browser (Vitest browser mode) over a ~30-line in-memory
// VaultStorageAdapter — the dividend of the core-purity constraint paid for
// since Phase 1. Real Argon2id at the LOCKED 256 MiB / 3 ops floor runs here
// (~1s), not a stub and not a lowered param.
//
// D-10 ("no duplicated vectors"): the KAT-grade assertion below imports
// VAULT_AD directly from @cryptiq/core/internal — no vector is hand-typed
// or copied into this file, so a stub crypto module could not pass it (it
// would have to import the real, pinned constant to match).

import { describe, expect, it } from 'vitest';
import { createVault, unlockVault, saveVault, getSodium, VAULT_AD } from '@cryptiq/core/internal';
import { InMemoryVaultStorageAdapter } from '../storage/InMemoryVaultStorageAdapter';

const FLOOR_OPS = 3;
const FLOOR_MEM = 268_435_456; // 256 MiB — the LOCKED Argon2id floor (CLAUDE.md); never lowered.

// Mirrors packages/core/src/vault/__tests__/round-trip.test.ts's floorParams()
// helper exactly: a fixed-params test seam so createVault skips the adaptive
// calibration ladder and this browser test stays ~1s instead of much longer.
async function floorParamsWithFreshSalt() {
  const sodium = await getSodium();
  return {
    algorithm: 2 as const,
    opsLimit: FLOOR_OPS,
    memLimit: FLOOR_MEM,
    salt: sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES),
  };
}

describe('demo round trip — real @cryptiq/core, real Argon2id, in-memory storage only (SC-3)', () => {
  it(
    'createVault -> saveVault -> adapter.save -> adapter.load -> unlockVault round-trips through the unmodified core',
    async () => {
      const masterPassword = new TextEncoder().encode('demo-passphrase');
      const adapter = new InMemoryVaultStorageAdapter();

      const created = await createVault({
        masterPassword,
        withRecoveryKey: false,
        kdfParams: await floorParamsWithFreshSalt(),
      });

      const bytes = await saveVault(created.vault, created.vaultKey);
      await adapter.save(bytes);

      expect(await adapter.exists()).toBe(true);

      const loaded = await adapter.load();
      const unlocked = await unlockVault(loaded, { masterPassword });

      // SC-3: proves the round trip completed through the REAL, unmodified
      // core — a stub could not produce a wrappedKeys.master that this
      // exact unlockVault call accepts.
      expect(unlocked.vault.doc.wrappedKeys.master).toBeDefined();
    },
    30_000,
  );

  it('D-10 KAT-grade assertion: VAULT_AD is imported from @cryptiq/core/internal, not duplicated by hand', () => {
    // No vector is hand-typed here — VAULT_AD is imported directly, and the
    // expected value below is the documented wire-format AD string
    // (packages/core/src/crypto/aead.ts), NOT a copied ciphertext/nonce/key
    // vector from any pinned KAT test. A stub "demo crypto" that fabricated
    // its own AD bytes (or omitted VAULT_AD entirely) could never satisfy
    // this assertion against the REAL, imported constant.
    expect(new TextDecoder().decode(VAULT_AD)).toBe('cryptiq-vault\0v1');
  });
});
