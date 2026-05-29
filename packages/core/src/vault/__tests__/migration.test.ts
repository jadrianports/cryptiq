import { describe, it, expect, vi } from 'vitest';
import { loadAndMigrate, REGISTERED_MIGRATIONS } from '../migrations/index';
import type { Migration } from '../migrations/types';
import { createVault, saveVault, secureWipe } from '../vault';
import { parseOuter } from '../serialize';
import { getSodium } from '../../crypto/sodium';
import { deriveKey } from '../../crypto/kdf';
import type { KdfParams } from '../../crypto/kdf';
import { wrapKey } from '../../crypto/wrap';
import { sealData, VAULT_AD } from '../../crypto/aead';
import { padToTieredBucket } from '../../crypto/padding';
import { FORMAT_IDENTIFIER, CURRENT_FORMAT_VERSION } from '../format';
import type { VaultDocumentV1 } from '../format';
import type { VaultStorageAdapter, VaultBytes } from '../../storage/VaultStorageAdapter';
import { MigrationFailedError, UnknownVaultVersionError } from '../../errors';

// Migration framework scaffold (VAULT-04, TEST-03, SEC-08). The PRODUCTION registry is
// empty (Cryptiq starts at v1); the synthetic v0→v1 migration below lives ONLY here.
//
// FIXED kdf-override (256 MiB / 3 ops floor) keeps the suite under the 30s budget — real
// Argon2id, just not adaptively calibrated. createVault accepts it via the `kdfParams`
// test seam; production omits it and calibrates.

const FLOOR_OPS = 3;
const FLOOR_MEM = 268_435_456; // 256 MiB
const MASTER_PW = 'correct horse battery staple migration';

function pw(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

async function floorParams(): Promise<KdfParams> {
  const sodium = await getSodium();
  return {
    algorithm: 2,
    opsLimit: FLOOR_OPS,
    memLimit: FLOOR_MEM,
    salt: sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES),
  };
}

/** In-memory mock adapter — only savePreMigrationBackup is exercised by the migration path. */
function makeMockAdapter(): VaultStorageAdapter & {
  backups: Array<{ name: string; bytes: VaultBytes }>;
} {
  const backups: Array<{ name: string; bytes: VaultBytes }> = [];
  return {
    vaultLabel: 'mock://migration-test',
    backups,
    exists: () => Promise.resolve(true),
    load: () => Promise.reject(new Error('not used in these tests')),
    save: () => Promise.resolve(),
    listBackups: () => Promise.resolve([]),
    loadBackup: () => Promise.reject(new Error('not used in these tests')),
    savePreMigrationBackup: (name: string, bytes: VaultBytes) => {
      backups.push({ name, bytes: bytes.slice() });
      return Promise.resolve();
    },
  };
}

const KNOWN_ENTRIES = { entries: [{ title: 'Email', username: 'me', secret: 'hunter2' }] };

/**
 * Build a synthetic `version: 0` document the orchestrator can migrate. It is shaped
 * like v1 (master wrap + sealed `data` blob) but carries `version: 0`, so parseOuter
 * (which only accepts the current version) would refuse it — exactly the scaffold case.
 * The vault key is wrapped under the master password; the inner entries are sealed under
 * VAULT_AD so the v0→v1 migration can re-use the same vault key + AEAD on the v1 side.
 */
async function makeSyntheticV0(
  masterPw: Uint8Array,
): Promise<{ bytes: Uint8Array; vaultKey: Uint8Array }> {
  const sodium = await getSodium();
  const params = await floorParams();
  const vaultKey = sodium.randombytes_buf(32);
  const masterDK = await deriveKey(masterPw, params);
  const master = await wrapKey(vaultKey, masterDK, params);
  await secureWipe(masterDK);

  const padded = padToTieredBucket(new TextEncoder().encode(JSON.stringify(KNOWN_ENTRIES)));
  const { ciphertext, nonce } = await sealData(padded, vaultKey, VAULT_AD);

  const v0doc = {
    format: FORMAT_IDENTIFIER,
    version: 0,
    wrappedKeys: { master },
    data: {
      nonce: sodium.to_base64(nonce, sodium.base64_variants.ORIGINAL),
      ciphertext: sodium.to_base64(ciphertext, sodium.base64_variants.ORIGINAL),
    },
    meta: { createdAt: '2020-01-01T00:00:00.000Z', modifiedAt: '2020-01-01T00:00:00.000Z' },
  };
  // Return the vault key so the mock migration can pre-seal the v1 `data` blob with the
  // SAME key the orchestrator will recover from the master wrap (sync apply() constraint).
  return {
    bytes: new TextEncoder().encode(JSON.stringify(v0doc, null, 2) + '\n'),
    vaultKey,
  };
}

/**
 * Seal an inner entries object into a v1 `data` blob (fresh nonce, VAULT_AD, decision-27
 * base64). Shared by the honest + buggy mock migrations so they own the crypto — the
 * orchestrator only serializes + cold-decrypt-verifies.
 */
async function sealInner(
  inner: object,
  vaultKey: Uint8Array,
): Promise<{ nonce: string; ciphertext: string }> {
  const sodium = await getSodium();
  const padded = padToTieredBucket(new TextEncoder().encode(JSON.stringify(inner)));
  const { ciphertext, nonce } = await sealData(padded, vaultKey, VAULT_AD);
  return {
    nonce: sodium.to_base64(nonce, sodium.base64_variants.ORIGINAL),
    ciphertext: sodium.to_base64(ciphertext, sodium.base64_variants.ORIGINAL),
  };
}

/**
 * Honest synthetic v0→v1 migration. Re-stamps the document to `version: 1`, carrying over
 * the master wrap, and re-seals the (already-decrypted) entries into the v1 `data` blob.
 * `apply` is synchronous (per the interface), so the sealing is pre-computed here.
 */
async function makeV0to1Migration(vaultKey: Uint8Array): Promise<Migration<0, 1>> {
  const sealed = await sealInner(KNOWN_ENTRIES, vaultKey);
  return {
    fromVersion: 0,
    toVersion: 1,
    description: 'synthetic v0→v1 (test-only)',
    apply(doc, decryptedInner, _vaultKey) {
      const d = doc as unknown as VaultDocumentV1;
      const newDoc: VaultDocumentV1 = {
        format: FORMAT_IDENTIFIER,
        version: 1,
        wrappedKeys: d.wrappedKeys,
        data: sealed, // the migration owns the re-sealed ciphertext
        meta: { createdAt: d.meta.createdAt, modifiedAt: new Date().toISOString() },
      };
      return { ok: true, doc: newDoc, newInner: decryptedInner };
    },
  };
}

/**
 * A BUGGY migration: emits a structurally valid v1 doc but with a CORRUPTED ciphertext
 * (a flipped base64 char) while still claiming `newInner = KNOWN_ENTRIES`. The cold-decrypt
 * verify must catch this — the AEAD open of the tampered ciphertext fails fail-closed
 * (Pitfall 13 / T-02-20), so loadAndMigrate throws MigrationFailedError, never a silent pass.
 */
async function makeBuggyV0to1Migration(vaultKey: Uint8Array): Promise<Migration<0, 1>> {
  const sealed = await sealInner(KNOWN_ENTRIES, vaultKey);
  // Flip one character of the base64 ciphertext → AEAD tag fails on cold decrypt.
  const ct = sealed.ciphertext;
  const at = 10;
  const flippedChar = ct[at] === 'A' ? 'B' : 'A';
  const corrupted = {
    nonce: sealed.nonce,
    ciphertext: ct.slice(0, at) + flippedChar + ct.slice(at + 1),
  };
  return {
    fromVersion: 0,
    toVersion: 1,
    description: 'buggy v0→v1 (corrupts data.ciphertext)',
    apply(doc, _decryptedInner, _vaultKey) {
      const d = doc as unknown as VaultDocumentV1;
      const newDoc: VaultDocumentV1 = {
        format: FORMAT_IDENTIFIER,
        version: 1,
        wrappedKeys: d.wrappedKeys,
        data: corrupted, // structurally valid base64, cryptographically WRONG
        meta: { createdAt: d.meta.createdAt, modifiedAt: new Date().toISOString() },
      };
      return { ok: true, doc: newDoc, newInner: KNOWN_ENTRIES };
    },
  };
}

describe('vault/migrations — scaffold + loadAndMigrate pipeline', () => {
  it('production REGISTERED_MIGRATIONS is empty (Cryptiq starts at v1)', () => {
    expect(Array.isArray(REGISTERED_MIGRATIONS)).toBe(true);
    expect(REGISTERED_MIGRATIONS.length).toBe(0);
  });

  it('Test 1: current-version vault passes through unchanged (migrated: false)', async () => {
    const created = await createVault({
      masterPassword: pw(MASTER_PW),
      withRecoveryKey: false,
      kdfParams: await floorParams(),
    });
    created.vault.entries = KNOWN_ENTRIES;
    const bytes = await saveVault(created.vault, created.vaultKey);
    const adapter = makeMockAdapter();

    const result = await loadAndMigrate(bytes, { masterPassword: pw(MASTER_PW) }, adapter);

    expect(result.migrated).toBe(false);
    expect(result.bytes).toEqual(bytes); // bytes effectively unchanged
    expect(result.vault.doc.version).toBe(CURRENT_FORMAT_VERSION);
    expect(result.vault.entries).toEqual(KNOWN_ENTRIES);
    // No transform happened → no pre-migration backup written.
    expect(adapter.backups.length).toBe(0);
  });

  it('Test 2: synthetic v0→v1 applies, backs up ONCE before transform, produces a v1 that cold-decrypts', async () => {
    const masterPw = pw(MASTER_PW);
    const { bytes: v0, vaultKey } = await makeSyntheticV0(masterPw);
    const adapter = makeMockAdapter();
    const backupSpy = vi.spyOn(adapter, 'savePreMigrationBackup');

    const result = await loadAndMigrate(v0, { masterPassword: pw(MASTER_PW) }, adapter, [
      await makeV0to1Migration(vaultKey),
    ]);

    expect(result.migrated).toBe(true);
    expect(result.vault.doc.version).toBe(CURRENT_FORMAT_VERSION);
    expect(result.vault.entries).toEqual(KNOWN_ENTRIES); // cold-decrypt-verified entries
    // Backup written exactly once, BEFORE transform — with the ORIGINAL v0 bytes.
    expect(backupSpy).toHaveBeenCalledTimes(1);
    expect(adapter.backups.length).toBe(1);
    expect(adapter.backups[0]!.bytes).toEqual(v0);
    // The migrated bytes are a fresh v1 document (different from the v0 input).
    expect(result.bytes).not.toEqual(v0);
    expect(parseOuter(result.bytes).version).toBe(1);
  });

  it('Test 3: cold-decrypt verify catches a buggy migration → MigrationFailedError (NOT a silent pass)', async () => {
    const masterPw = pw(MASTER_PW);
    const { bytes: v0, vaultKey } = await makeSyntheticV0(masterPw);
    const adapter = makeMockAdapter();

    await expect(
      loadAndMigrate(v0, { masterPassword: pw(MASTER_PW) }, adapter, [
        await makeBuggyV0to1Migration(vaultKey),
      ]),
    ).rejects.toBeInstanceOf(MigrationFailedError);

    // The original is preserved: the backup of the untouched v0 was still written first.
    expect(adapter.backups.length).toBe(1);
    expect(adapter.backups[0]!.bytes).toEqual(v0);
  });

  it('Test 4: unknown version with no registered path → UnknownVaultVersionError', async () => {
    const v99 = new TextEncoder().encode(
      JSON.stringify({
        format: FORMAT_IDENTIFIER,
        version: 99,
        wrappedKeys: { master: {} },
        data: { nonce: '', ciphertext: '' },
        meta: { createdAt: 'x', modifiedAt: 'x' },
      }),
    );
    const adapter = makeMockAdapter();

    await expect(
      loadAndMigrate(v99, { masterPassword: pw(MASTER_PW) }, adapter),
    ).rejects.toBeInstanceOf(UnknownVaultVersionError);
    // No transform attempted → no backup.
    expect(adapter.backups.length).toBe(0);
  });

  // WR-03 regression: the final migrated v1 document must be built from an explicit field
  // whitelist (format, version, wrappedKeys, data, meta) — NOT a spread of the final step's
  // output. A buggy/partial migration step that returns a doc still carrying stale/foreign
  // top-level keys would otherwise leak them straight into the serialized v1 bytes (past the
  // cold-decrypt gate, which only checks the entries blob, not the outer shape).
  it('Test 6 (WR-03): foreign top-level fields from a step output are dropped from the migrated v1', async () => {
    const masterPw = pw(MASTER_PW);
    const { bytes: v0, vaultKey } = await makeSyntheticV0(masterPw);
    const adapter = makeMockAdapter();

    // A migration step that produces a VALID v1 (so cold-decrypt passes) but ALSO carries
    // foreign top-level keys in its output doc — simulating a partial/buggy step.
    const honest = await makeV0to1Migration(vaultKey);
    const leaky: Migration<0, 1> = {
      fromVersion: 0,
      toVersion: 1,
      description: 'leaky v0→v1 (emits foreign top-level keys)',
      apply(doc, decryptedInner, vk) {
        const r = honest.apply(doc, decryptedInner, vk);
        if (!r.ok) return r;
        // Pollute the step output with foreign top-level fields.
        const polluted = {
          ...(r.doc as unknown as Record<string, unknown>),
          legacyJunk: { resurrected: true },
          attackerControlled: 'should-not-survive',
        };
        return { ok: true, doc: polluted as unknown as VaultDocumentV1, newInner: r.newInner };
      },
    };

    const result = await loadAndMigrate(v0, { masterPassword: pw(MASTER_PW) }, adapter, [leaky]);

    expect(result.migrated).toBe(true);
    const migrated = JSON.parse(new TextDecoder().decode(result.bytes)) as Record<string, unknown>;
    // The migrated v1 file carries ONLY the whitelisted V1 fields.
    expect(Object.keys(migrated).sort()).toEqual(
      ['data', 'format', 'meta', 'version', 'wrappedKeys'].sort(),
    );
    expect(migrated.legacyJunk).toBeUndefined();
    expect(migrated.attackerControlled).toBeUndefined();
  });

  // WR-04 regression: an older document with a malformed `data` (absent / non-object /
  // non-string nonce|ciphertext) must fail closed with a typed MigrationFailedError via a
  // DELIBERATE shape validation BEFORE any base64 decode — its message must NOT contain
  // library-internal base64-decoder text (e.g. "incomplete input" / "invalid input").
  it('Test 7 (WR-04): a malformed old-doc data blob → controlled MigrationFailedError (validated, not lib-internal)', async () => {
    const masterPw = pw(MASTER_PW);
    const { bytes: v0, vaultKey } = await makeSyntheticV0(masterPw);
    const v0obj = JSON.parse(new TextDecoder().decode(v0)) as Record<string, unknown>;
    // Corrupt the data blob: nonce present but ciphertext is a number (wrong type).
    v0obj.data = { nonce: 'AAAA', ciphertext: 12345 };
    const malformed = new TextEncoder().encode(JSON.stringify(v0obj, null, 2) + '\n');
    const adapter = makeMockAdapter();

    const err = await loadAndMigrate(malformed, { masterPassword: pw(MASTER_PW) }, adapter, [
      await makeV0to1Migration(vaultKey),
    ]).then(
      () => null,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(MigrationFailedError);
    // The message is the deliberate shape-validation message, NOT a leaked library-internal
    // string (the old accidental path surfaced a libsodium TypeError like "buffer must be a
    // Uint8Array" / "invalid input" via decryptInner). The validated message names the field.
    const msg = (err as Error).message;
    expect(msg).toMatch(/data.*(nonce|ciphertext|malformed|base64)/i);
    expect(msg).not.toMatch(
      /incomplete input|invalid input|buffer must be a Uint8Array|The encoded data was not valid/i,
    );
  });

  it('Test 5: verify re-parses + re-decrypts the NEW migrated bytes (cold decrypt, not the original)', async () => {
    const masterPw = pw(MASTER_PW);
    const { bytes: v0, vaultKey } = await makeSyntheticV0(masterPw);
    const adapter = makeMockAdapter();

    const result = await loadAndMigrate(v0, { masterPassword: pw(MASTER_PW) }, adapter, [
      await makeV0to1Migration(vaultKey),
    ]);

    // The verified vault is the one parsed from the NEW bytes: parseOuter(result.bytes)
    // succeeds (v1) and its data blob matches the returned doc (proves the orchestrator
    // re-derived from the migrated file, not the v0 original which parseOuter rejects).
    const reparsed = parseOuter(result.bytes);
    expect(reparsed.version).toBe(1);
    expect(reparsed.data.ciphertext).toBe(result.vault.doc.data.ciphertext);
    expect(() => parseOuter(v0)).toThrow(UnknownVaultVersionError); // the original is NOT v1
  });
});
