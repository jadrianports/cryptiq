import { describe, it, expect } from 'vitest';
import { getSodium } from '../../crypto/sodium';
import { wrapKey } from '../../crypto/wrap';
import { parseOuter, serializeOuter, encryptInner, decryptInner } from '../serialize';
import { CURRENT_FORMAT_VERSION, FORMAT_IDENTIFIER } from '../format';
import type { VaultDocumentV1 } from '../format';
import { VaultCorruptError, UnknownVaultVersionError } from '../../errors';
import type { KdfParams } from '../../crypto/kdf';

// Wave 3 — outer JSON parse/serialize (VAULT-01, VAULT-02, VAULT-07) + inner
// encrypt/decrypt (SEC-06, VAULT-03). DC-3 per-wrap kdf, DC-4 open wrappedKeys map.
//
// Fixed Argon2id params for the master wrap (floor: 256 MiB / 3 ops). wrapKey itself
// takes an already-derived 32-byte derivation key; these params are recorded into the
// per-wrap kdf field (DC-3) — not used to actually run Argon2id here.
async function fixedKdfParams(): Promise<KdfParams> {
  const sodium = await getSodium();
  return {
    algorithm: 2,
    opsLimit: 3,
    memLimit: 268_435_456,
    salt: sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES),
  };
}

/** Build a complete, valid VaultDocumentV1 with a master wrap and an encrypted blob. */
async function buildDoc(entriesJson: string): Promise<VaultDocumentV1> {
  const sodium = await getSodium();
  const vaultKey = sodium.randombytes_buf(32);
  const derivationKey = sodium.randombytes_buf(32);
  const master = await wrapKey(vaultKey, derivationKey, await fixedKdfParams());
  const data = await encryptInner(new TextEncoder().encode(entriesJson), vaultKey);
  return {
    format: FORMAT_IDENTIFIER as 'cryptiq-vault',
    version: CURRENT_FORMAT_VERSION as 1,
    wrappedKeys: { master },
    data,
    meta: {
      createdAt: '2026-05-29T00:00:00.000Z',
      modifiedAt: '2026-05-29T00:00:00.000Z',
    },
  };
}

describe('vault/serialize — outer parse/serialize + inner encrypt/decrypt', () => {
  it('parseOuter round-trips serializeOuter (VAULT-01, VAULT-02)', async () => {
    const doc = await buildDoc('{"entries":[{"title":"GitHub"}]}');
    const bytes = serializeOuter(doc);
    const parsed = parseOuter(bytes);

    expect(parsed.format).toBe('cryptiq-vault');
    expect(parsed.version).toBe(1);
    // DC-3: per-wrap kdf nested inside wrappedKeys.master — never a top-level kdf.
    expect(parsed.wrappedKeys.master.kdf.algorithm).toBe(2);
    expect((parsed as unknown as Record<string, unknown>).kdf).toBeUndefined();
    expect(typeof parsed.data.nonce).toBe('string');
    expect(typeof parsed.data.ciphertext).toBe('string');
    expect(parsed).toEqual(doc);
  });

  it('serializeOuter output has NO top-level kdf field (DC-3 / Pitfall B)', async () => {
    const doc = await buildDoc('{"entries":[]}');
    const text = new TextDecoder().decode(serializeOuter(doc));
    const obj = JSON.parse(text) as Record<string, unknown>;
    expect(obj.kdf).toBeUndefined();
    // The kdf lives inside the wrap.
    const wrappedKeys = obj.wrappedKeys as { master: Record<string, unknown> };
    expect(wrappedKeys.master.kdf).toBeDefined();
  });

  it('parseOuter throws UnknownVaultVersionError on version != 1 (VAULT-07, T-02-10)', async () => {
    const doc = await buildDoc('{"entries":[]}');
    const forged = { ...doc, version: 2 as unknown as 1 };
    const bytes = serializeOuter(forged as VaultDocumentV1);
    expect(() => parseOuter(bytes)).toThrow(UnknownVaultVersionError);
  });

  it('parseOuter TOLERATES an unknown wrappedKeys label (DC-4 open map — no throw)', async () => {
    const doc = await buildDoc('{"entries":[]}');
    // Inject a future-style label (e.g. a v2.5 mobile wrap). Reuse the master wrap shape.
    const withUnknownLabel = {
      ...doc,
      wrappedKeys: {
        ...doc.wrappedKeys,
        mobile: doc.wrappedKeys.master,
        biometric_device42: doc.wrappedKeys.master,
      },
    };
    const bytes = serializeOuter(withUnknownLabel as VaultDocumentV1);
    const parsed = parseOuter(bytes);
    // No throw; the unknown labels survive the round-trip untouched.
    expect(parsed.wrappedKeys.mobile).toBeDefined();
    expect(parsed.wrappedKeys.biometric_device42).toBeDefined();
    expect(parsed.wrappedKeys.master).toBeDefined();
  });

  it('parseOuter throws VaultCorruptError on bad JSON, non-object root, or foreign format', () => {
    // Bad JSON.
    expect(() => parseOuter(new TextEncoder().encode('{not json'))).toThrow(VaultCorruptError);
    // Non-object root.
    expect(() => parseOuter(new TextEncoder().encode('"a string"'))).toThrow(VaultCorruptError);
    // Foreign format discriminator (T-02-11 format confusion).
    expect(() =>
      parseOuter(new TextEncoder().encode('{"format":"not-cryptiq","version":1}')),
    ).toThrow(VaultCorruptError);
  });

  // WR-05 regression: parseOuter must validate the meta SHAPE (createdAt/modifiedAt present +
  // string-typed; deviceLabel undefined or string). A file with meta:{} or a numeric
  // createdAt parsed "successfully" before, then the VaultDocumentV1 type LIED about the
  // string guarantee. Fail closed with VaultCorruptError on malformed meta.
  it('WR-05: parseOuter rejects malformed meta (missing/mistyped timestamps) → VaultCorruptError', async () => {
    const doc = await buildDoc('{"entries":[]}');

    // meta with no timestamps.
    const noTimestamps = serializeOuter({ ...doc, meta: {} as VaultDocumentV1['meta'] });
    expect(() => parseOuter(noTimestamps)).toThrow(VaultCorruptError);

    // createdAt wrong type (number).
    const numericCreated = serializeOuter({
      ...doc,
      meta: {
        createdAt: 42,
        modifiedAt: '2026-05-29T00:00:00.000Z',
      } as unknown as VaultDocumentV1['meta'],
    });
    expect(() => parseOuter(numericCreated)).toThrow(VaultCorruptError);

    // modifiedAt missing.
    const missingModified = serializeOuter({
      ...doc,
      meta: { createdAt: '2026-05-29T00:00:00.000Z' } as unknown as VaultDocumentV1['meta'],
    });
    expect(() => parseOuter(missingModified)).toThrow(VaultCorruptError);

    // deviceLabel wrong type (number) → rejected.
    const badLabel = serializeOuter({
      ...doc,
      meta: {
        createdAt: '2026-05-29T00:00:00.000Z',
        modifiedAt: '2026-05-29T00:00:00.000Z',
        deviceLabel: 99,
      } as unknown as VaultDocumentV1['meta'],
    });
    expect(() => parseOuter(badLabel)).toThrow(VaultCorruptError);
  });

  it('WR-05: parseOuter ACCEPTS valid meta (string timestamps, optional string deviceLabel)', async () => {
    const doc = await buildDoc('{"entries":[]}');
    // Both forms round-trip: with and without deviceLabel.
    const withoutLabel = serializeOuter(doc);
    expect(parseOuter(withoutLabel).meta.createdAt).toBe('2026-05-29T00:00:00.000Z');

    const withLabel = serializeOuter({
      ...doc,
      meta: { ...doc.meta, deviceLabel: 'James-Desktop' },
    });
    expect(parseOuter(withLabel).meta.deviceLabel).toBe('James-Desktop');
  });

  it('encryptInner -> decryptInner round-trips the exact entries bytes under VAULT_AD (SEC-06, VAULT-03)', async () => {
    const sodium = await getSodium();
    const vaultKey = sodium.randombytes_buf(32);
    const entries = '{"entries":[{"title":"Bank","secret":"hunter2"},{"title":"Email"}]}';
    const entryBytes = new TextEncoder().encode(entries);

    const data = await encryptInner(entryBytes, vaultKey);
    expect(typeof data.nonce).toBe('string');
    expect(typeof data.ciphertext).toBe('string');

    const restored = await decryptInner(data, vaultKey);
    expect(new TextDecoder().decode(restored)).toBe(entries);
    expect(Array.from(restored)).toEqual(Array.from(entryBytes));
  });

  it('decryptInner fails closed (VaultCorruptError) under the WRONG vault key', async () => {
    const sodium = await getSodium();
    const vaultKey = sodium.randombytes_buf(32);
    const wrongKey = sodium.randombytes_buf(32);
    const data = await encryptInner(new TextEncoder().encode('{"entries":[]}'), vaultKey);
    await expect(decryptInner(data, wrongKey)).rejects.toThrow(VaultCorruptError);
  });

  it('different entry counts in the SAME tier produce the SAME padded ciphertext length (entry-count hiding, VAULT-03)', async () => {
    const sodium = await getSodium();
    const vaultKey = sodium.randombytes_buf(32);
    // Two small but different entry blobs — both land in the first 16 KiB tier.
    const few = await encryptInner(new TextEncoder().encode('{"entries":[{"t":"A"}]}'), vaultKey);
    const more = await encryptInner(
      new TextEncoder().encode('{"entries":[{"t":"A"},{"t":"B"},{"t":"C"},{"t":"D"}]}'),
      vaultKey,
    );
    const lenFew = sodium.from_base64(few.ciphertext, sodium.base64_variants.ORIGINAL).length;
    const lenMore = sodium.from_base64(more.ciphertext, sodium.base64_variants.ORIGINAL).length;
    expect(lenFew).toBe(lenMore);
    // 16 KiB padded + 16-byte AEAD tag.
    expect(lenFew).toBe(16 * 1024 + 16);
  });
});
