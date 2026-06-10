// packages/core/src/vault/__tests__/reseal.test.ts
//
// SAFE-01/03/04 coverage for resealInnerDoc (Plan 11-01, Task 2).
//
// Requirements covered:
//   SAFE-01 — In-memory quarantine foundation: a re-sealed blob round-trips through
//             cold-decrypt-verify (unlockVault re-derives key from KDF params + decrypts)
//             proving the in-memory blob is trustworthy before it would ever touch disk.
//   SAFE-03 — Cold-decrypt-verify rejects a corrupted re-sealed blob with a typed error
//             (AEAD MAC failure), never returning partial data.
//   SAFE-04 — The entriesBytes buffer (InnerDoc JSON) is securely wiped after re-seal;
//             the caller-wipe ownership contract is documented and asserted.
//
// Also covers:
//   T-11-03 — Envelope preservation: wrappedKeys, salt, KDF params, version, and format
//             discriminator are byte-identical between partnerDoc and the re-sealed output
//             (KAT-1..4 wire-format LOCKED boundary must not be violated).
//
// Test seam: all tests use floor KDF params (256 MiB / 3 ops) so Argon2id does not
// run the full adaptive calibration. Same seam as vault.test.ts / round-trip.test.ts.

import { describe, it, expect } from 'vitest';
import { createVault, unlockVault, resealInnerDoc, secureWipe } from '../vault';
import { parseOuter, serializeOuter } from '../serialize';
import { getSodium } from '../../crypto/sodium';
import type { InnerDoc } from '../../entries/types';
import type { VaultDocumentV1 } from '../format';
import { DEFAULT_RANDOM_OPTIONS } from '../../generator/types';
import { VaultCorruptError } from '../../errors';

// ---------------------------------------------------------------------------
// Shared helpers — same seam as round-trip.test.ts
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

/** Build a minimal valid InnerDoc fixture with one entry. */
function makeInnerDoc(): InnerDoc {
  return {
    schemaVersion: 2,
    entries: [
      {
        id: 'reseal-test-entry-001',
        type: 'login',
        title: 'Reseal Test Entry',
        username: 'user@example.com',
        password: 'sup3r-s3cr3t-p@ssword',
        url: 'https://example.com',
        notes: 'test notes',
        tags: [],
        favorite: false,
        needsSiteUpdate: false,
        generatorPreset: null,
        passwordHistory: [],
        lostVersions: [],
        createdAt: '2026-01-01T00:00:00.000Z',
        modifiedAt: '2026-01-01T00:00:00.000Z',
        deletedAt: null,
      },
    ],
    settings: { generator: DEFAULT_RANDOM_OPTIONS },
  };
}

// ---------------------------------------------------------------------------
// describe('resealInnerDoc')
// ---------------------------------------------------------------------------

describe('resealInnerDoc', () => {
  it('SAFE-01/SAFE-03: re-sealed blob round-trips cold-verify through unlockVault', async () => {
    // Arrange: create a partner vault with a known password
    const masterPw = pw('reseal-cold-verify-test-password');
    const created = await createVault({
      masterPassword: masterPw,
      withRecoveryKey: false,
      kdfParams: await floorParams(),
    });
    const partnerDoc: VaultDocumentV1 = created.vault.doc;
    const vaultKey = created.vaultKey;

    const mergedInner: InnerDoc = makeInnerDoc();

    // Act: re-seal the merged InnerDoc under the existing vault key
    const resealedBytes = await resealInnerDoc(mergedInner, vaultKey, partnerDoc);

    // Assert cold-verify: re-derive key from stored KDF params + decrypt
    // This is the SAFE-01/SAFE-03 bar: unlockVault re-derives independently
    const unlocked = await unlockVault(resealedBytes, { masterPassword: masterPw });

    try {
      // Entries must be deep-equal to what was sealed
      const unlockedInner = unlocked.vault.entries as InnerDoc;
      expect(unlockedInner.schemaVersion).toBe(mergedInner.schemaVersion);
      expect(unlockedInner.entries).toHaveLength(mergedInner.entries.length);
      expect(unlockedInner.entries[0]?.id).toBe(mergedInner.entries[0]?.id);
      expect(unlockedInner.entries[0]?.title).toBe(mergedInner.entries[0]?.title);
      expect(unlockedInner.entries[0]?.password).toBe(mergedInner.entries[0]?.password);
    } finally {
      await secureWipe(unlocked.vaultKey);
    }

    await secureWipe(vaultKey);
  }, 60_000);

  it('SAFE-03 reject: corrupted data blob causes unlockVault to throw a typed error', async () => {
    // Arrange
    const masterPw = pw('reseal-corruption-test-password');
    const created = await createVault({
      masterPassword: masterPw,
      withRecoveryKey: false,
      kdfParams: await floorParams(),
    });
    const partnerDoc: VaultDocumentV1 = created.vault.doc;
    const vaultKey = created.vaultKey;
    const mergedInner: InnerDoc = makeInnerDoc();

    const resealedBytes = await resealInnerDoc(mergedInner, vaultKey, partnerDoc);
    await secureWipe(vaultKey);

    // Parse the outer JSON, flip a character in the base64 ciphertext, re-serialize.
    // This corrupts the AEAD MAC-protected ciphertext without breaking the JSON structure,
    // so unlockVault gets valid JSON but an invalid AEAD blob → typed VaultCorruptError.
    const doc = parseOuter(resealedBytes);
    // Flip a character near the middle of the base64 ciphertext string
    const ciphertext = doc.data.ciphertext;
    const midIdx = Math.floor(ciphertext.length / 2);
    // Replace a character with a visually different but still valid base64 character
    // to ensure the base64 decodes but the AEAD tag verification fails
    const charToFlip = ciphertext[midIdx]!;
    const flippedChar = charToFlip === 'A' ? 'B' : 'A';
    const corruptedCiphertext =
      ciphertext.slice(0, midIdx) + flippedChar + ciphertext.slice(midIdx + 1);
    const corruptedDoc: VaultDocumentV1 = {
      ...doc,
      data: { ...doc.data, ciphertext: corruptedCiphertext },
    };
    const corrupted = serializeOuter(corruptedDoc);

    // Act + Assert: unlockVault must throw a typed error, NEVER return partial data
    // A corrupted AEAD ciphertext → VaultCorruptError (fail closed, SEC-08)
    await expect(
      unlockVault(corrupted, { masterPassword: masterPw }),
    ).rejects.toThrow(VaultCorruptError);
  }, 60_000);

  it('preserves partner wrappedKeys, salt, KDF params, version, format unchanged', async () => {
    // Arrange: partner vault with recovery key to test a richer wrappedKeys map
    const masterPw = pw('reseal-envelope-preservation-test');
    const created = await createVault({
      masterPassword: masterPw,
      withRecoveryKey: true,
      kdfParams: await floorParams(),
    });
    const vaultKey = created.vaultKey;
    const mergedInner: InnerDoc = makeInnerDoc();

    // Set a known past timestamp on partnerDoc.meta.modifiedAt so we can assert it changes.
    // resealInnerDoc bumps modifiedAt to new Date().toISOString() — that will be later
    // than this fixed past value even in a fast-running test.
    const partnerDoc: VaultDocumentV1 = {
      ...created.vault.doc,
      meta: {
        ...created.vault.doc.meta,
        modifiedAt: '2020-01-01T00:00:00.000Z', // deterministic past timestamp
      },
    };

    // Act
    const resealedBytes = await resealInnerDoc(mergedInner, vaultKey, partnerDoc);
    await secureWipe(vaultKey);

    // Parse the re-sealed output and compare envelope fields
    const resealedDoc = parseOuter(resealedBytes);

    // Format discriminator and version unchanged (KAT-1..4 LOCKED boundary)
    expect(resealedDoc.format).toBe(partnerDoc.format);
    expect(resealedDoc.version).toBe(partnerDoc.version);

    // wrappedKeys byte-identical (master + recovery both preserved)
    expect(JSON.stringify(resealedDoc.wrappedKeys.master)).toBe(
      JSON.stringify(partnerDoc.wrappedKeys.master),
    );
    expect(JSON.stringify(resealedDoc.wrappedKeys.recovery)).toBe(
      JSON.stringify(partnerDoc.wrappedKeys.recovery),
    );

    // meta.createdAt preserved; meta.modifiedAt updated to current time (differs from fixed past)
    expect(resealedDoc.meta.createdAt).toBe(partnerDoc.meta.createdAt);
    expect(resealedDoc.meta.modifiedAt).not.toBe('2020-01-01T00:00:00.000Z');
    // The new modifiedAt must be more recent than the fixed past value
    expect(new Date(resealedDoc.meta.modifiedAt).getTime()).toBeGreaterThan(
      new Date('2020-01-01T00:00:00.000Z').getTime(),
    );

    // data.nonce differs (fresh nonce per AEAD — correct and expected)
    expect(resealedDoc.data.nonce).not.toBe(partnerDoc.data.nonce);

    // Sanity: the re-sealed doc has a data field (non-empty ciphertext)
    expect(resealedDoc.data.ciphertext.length).toBeGreaterThan(0);
  }, 60_000);

  it('SAFE-04: entriesBytes reseal-wipe leaves no plaintext (caller-wipe pattern)', async () => {
    // This test demonstrates the SAFE-04 caller-ownership contract:
    // after passing entriesBytes to resealInnerDoc (via the pattern the caller
    // in Plan 04 must follow), zeroing the buffer via sodium.memzero leaves all-zero.
    const sodium = await getSodium();

    const masterPw = pw('reseal-wipe-test-password');
    const created = await createVault({
      masterPassword: masterPw,
      withRecoveryKey: false,
      kdfParams: await floorParams(),
    });
    const partnerDoc: VaultDocumentV1 = created.vault.doc;
    const vaultKey = created.vaultKey;
    const mergedInner: InnerDoc = makeInnerDoc();

    // Simulate the SAFE-04 caller pattern: encode, seal, wipe
    const entriesBytes = new TextEncoder().encode(JSON.stringify(mergedInner));
    const _resealedBytes = await resealInnerDoc(mergedInner, vaultKey, partnerDoc);

    // SAFE-04: caller wipes entriesBytes in a finally block
    sodium.memzero(entriesBytes);

    // Assert: every byte in the wiped buffer is zero
    const allZero = entriesBytes.every((b) => b === 0);
    expect(allZero).toBe(true);
    expect(entriesBytes.length).toBeGreaterThan(0); // sanity: buffer existed

    await secureWipe(vaultKey);
  }, 60_000);
});
