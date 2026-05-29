import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { createVault, unlockVault, saveVault } from '../vault';
import { encryptInner, decryptInner } from '../serialize';
import { getSodium } from '../../crypto/sodium';
import type { KdfParams } from '../../crypto/kdf';

// DC-11 PROPERTY SUITE (TEST-02): random (password, entries[]) pairs must serialize →
// unlock LOSSLESSLY. fast-check fuzzes the inputs; the invariant is round-trip equality.
//
// RUNTIME BUDGET (the central design constraint): each Argon2id derivation at the 256 MiB
// floor costs ~1s. A naive "100× full createVault + unlockVault" property would run ~200
// derivations → minutes, blowing the 30s suite budget (singleFork serializes everything).
// We split the proof into two complementary properties so the ~100-pair fuzz never pays the
// Argon2id tax per run, while the full verb-first password path still gets fuzzed:
//
//   Property A — FULL-PATH (random password + entries, FEW runs): real createVault →
//     saveVault → unlockVault({ masterPassword }). Proves the password derivation +
//     wrap/unwrap + data seal/open path round-trips for arbitrary passwords. Kept to a
//     small numRuns because every run pays ~2 Argon2id derivations (create + unlock).
//
//   Property B — PAYLOAD FUZZ (~100 runs, ZERO per-run Argon2id): derive ONE vault key up
//     front (a single random 32-byte key — encryptInner/decryptInner operate on the vault
//     KEY directly, never the password), then fuzz ~100 random entries arrays through the
//     exact data-blob path saveVault/unlockVault use (padToTieredBucket → seal under VAULT_AD
//     → open → unpad → JSON). This is the ~100-pair losslessness fuzz from DC-11; it cannot
//     lose data anywhere the full path could, because padding + AEAD + JSON are precisely the
//     stages that could mangle bytes. Argon2id is deterministic and exercised in kdf.test.ts,
//     so excluding it from the high-run-count property loses no real coverage.
//
// FIXED FLOOR PARAMS for Property A (256 MiB / 3 ops): createVault's kdfParams test seam
// skips the adaptive calibration ladder — real Argon2id, just not auto-tuned.

const FLOOR_OPS = 3;
const FLOOR_MEM = 268_435_456; // 256 MiB

async function floorParams(): Promise<KdfParams> {
  const sodium = await getSodium();
  return {
    algorithm: 2,
    opsLimit: FLOOR_OPS,
    memLimit: FLOOR_MEM,
    salt: sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES),
  };
}

/** A single entry-shaped record (Phase 2 treats entries as opaque round-tripping JSON). */
const entryArb = fc.record({
  title: fc.string({ minLength: 0, maxLength: 64 }),
  username: fc.string({ minLength: 0, maxLength: 64 }),
  secret: fc.string({ minLength: 0, maxLength: 128 }),
  url: fc.string({ minLength: 0, maxLength: 96 }),
  notes: fc.string({ minLength: 0, maxLength: 256 }),
});

/** An entries object: { entries: Entry[] } — the opaque blob shape the vault round-trips. */
const entriesArb = fc.record({
  entries: fc.array(entryArb, { minLength: 0, maxLength: 12 }),
});

/** A non-empty password as raw UTF-8 bytes (passwords are bytes-in to deriveKey, SEC-08). */
const passwordArb = fc.uint8Array({ minLength: 1, maxLength: 64 });

describe('vault/property — random (password, entries) round-trips losslessly (DC-11, TEST-02)', () => {
  // PROPERTY A: full verb-first path with arbitrary passwords. Few runs (each pays ~2
  // Argon2id derivations); proves the password + wrap/unwrap + data path is lossless.
  it('Property A: full createVault → saveVault → unlockVault round-trips arbitrary passwords', async () => {
    await fc.assert(
      fc.asyncProperty(passwordArb, entriesArb, async (pwBytes, entries) => {
        // Fresh copies — createVault/unlockVault may memzero buffers handed to them.
        const created = await createVault({
          masterPassword: pwBytes.slice(),
          withRecoveryKey: false,
          kdfParams: await floorParams(),
        });
        created.vault.entries = entries;
        const bytes = await saveVault(created.vault, created.vaultKey);

        const unlocked = await unlockVault(bytes, { masterPassword: pwBytes.slice() });
        expect(unlocked.vault.entries).toEqual(entries);
      }),
      // Each run pays ~2 Argon2id derivations (create + unlock) at the 256 MiB floor (~2.6s).
      // Kept low so the file stays well within budget; Property B carries the DC-11 ~100-pair
      // intent. Raise this for an exhaustive local soak (it scales linearly in derivations).
      { numRuns: 4 },
    );
  });

  // PROPERTY B: ~100-run payload fuzz with a single up-front vault key (no per-run Argon2id).
  // Exercises the EXACT data-blob path (padding + AEAD-under-VAULT_AD + JSON) that the full
  // round-trip relies on, at the DC-11 ~100-pair count, well within budget.
  it('Property B: ~100 random entries arrays seal → open losslessly under a fixed vault key', async () => {
    const sodium = await getSodium();
    const vaultKey = sodium.randombytes_buf(32); // derived ONCE — no per-run Argon2id
    await fc.assert(
      fc.asyncProperty(entriesArb, async (entries) => {
        const json = JSON.stringify(entries);
        const sealed = await encryptInner(new TextEncoder().encode(json), vaultKey);
        const opened = await decryptInner(sealed, vaultKey);
        const restored = JSON.parse(new TextDecoder().decode(opened)) as unknown;
        expect(restored).toEqual(entries);
      }),
      { numRuns: 100 },
    );
  });
});
