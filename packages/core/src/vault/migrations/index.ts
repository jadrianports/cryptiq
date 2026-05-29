// packages/core/src/vault/migrations/index.ts
//
// THE MIGRATION FRAMEWORK SCAFFOLD (VAULT-04, TEST-03, SEC-08). Cryptiq starts at
// format version 1, so the PRODUCTION registry is EMPTY — there are no real migrations
// yet. The framework exists "from day one" (VAULT-04) so a future v2 lands as data, not
// as a refactor: register a `Migration<1, 2>` and loadAndMigrate carries old vaults
// forward through the back-up → migrate-copy → verify-by-cold-decrypt → swap pipeline.
//
// !!! REGISTERED_MIGRATIONS IS INTENTIONALLY EMPTY FOR v1 !!!
// The synthetic v0→v1 migration that exercises this orchestrator lives ONLY in the test
// suite (src/vault/__tests__/migration.test.ts) and the demo (scripts/demo/02-5-migration.mjs),
// passed in via the optional `migrations` parameter. Production callers omit that
// parameter and pick up REGISTERED_MIGRATIONS (empty), so a current-version vault always
// short-circuits to `migrated: false`.
//
// THE PIPELINE (ARCHITECTURE §7.3, Pitfall 13):
//   1. Peek the on-disk `version` WITHOUT parseOuter (parseOuter only accepts the current
//      version and would reject an older one). A foreign/corrupt file → VaultCorruptError;
//      the current version → unlockVault + return `migrated: false` (no transform, no backup).
//   2. version < current: assemble a migration chain from the registry; no path →
//      UnknownVaultVersionError (VAULT-07 — never guess at an unknown shape).
//   3. adapter.savePreMigrationBackup(name, ORIGINAL bytes) BEFORE any transform
//      (never-rotated named backup — T-02-21, the only-copy-destroyed DoS defense).
//   4. Recover the vault key from the old master wrap, decrypt the old inner once, then
//      apply each migration step. Each step is a PURE function returning the fully-formed
//      next-version document (INCLUDING its own re-sealed `data` blob) plus the inner it
//      sealed — so the orchestrator can cold-decrypt-verify against a known reference.
//   5. Serialize the final document → newBytes (the orchestrator owns serialization; the
//      migration owns the crypto so a buggy step's wrong ciphertext is INJECTABLE).
//   6. VERIFY-BY-COLD-DECRYPT (Pitfall 13, T-02-20): drop the in-memory key, parseOuter +
//      unlockVault the NEW bytes fresh (re-deriving the key from the NEW file's stored kdf
//      params) and assert the known reference inner round-trips byte-for-byte. Any AEAD
//      failure or mismatch → MigrationFailedError, original file untouched.
//   7. Swap: return the migrated bytes + the freshly-unlocked vault (`migrated: true`). The
//      actual on-disk file swap is the adapter's job in Phase 3 — here loadAndMigrate
//      returns the bytes the caller persists.
//
// Source: CONTEXT DC-8 (loadAndMigrate is part of the verb-first API), RESEARCH Pattern 9
//   + Pitfall 13, PATTERNS config.ts orchestrator analog (sequential validation, early-throw),
//   ARCHITECTURE §7.2-§7.5.

import { getSodium } from '../../crypto/sodium';
import { deriveKey } from '../../crypto/kdf';
import type { KdfParams } from '../../crypto/kdf';
import { tryUnwrap } from '../../crypto/wrap';
import { decodeRecoveryKey, toRecoveryWrapKey } from '../../crypto/recovery';
import { parseOuter, decryptInner } from '../serialize';
import { unlockVault, secureWipe } from '../vault';
import type { UnlockedVault, UnlockSecret } from '../vault';
import type { WrappedKeyV1, VaultDocumentV1 } from '../format';
import { CURRENT_FORMAT_VERSION, FORMAT_IDENTIFIER } from '../format';
import type { Migration } from './types';
import { MigrationFailedError, UnknownVaultVersionError, VaultCorruptError } from '../../errors';

/**
 * Production migration registry — EMPTY for v1 (Cryptiq starts at version 1; see banner).
 * A future v2 release appends a `Migration<1, 2>` here and nothing else in the pipeline
 * changes. Typed as `Migration<number, number>[]` so heterogeneous version steps can be
 * chained; the per-step version literals are checked at each migration's definition site.
 */
export const REGISTERED_MIGRATIONS: ReadonlyArray<Migration<number, number>> = [];

/** Result of running the migration pipeline over a set of vault bytes. */
export interface LoadAndMigrateResult {
  /** The unlocked vault (cold-decrypt-verified when a migration ran). */
  vault: UnlockedVault;
  /** The recovered 32-byte vault key — the caller mounts + memzeros it (SEC-09). */
  vaultKey: Uint8Array;
  /**
   * The vault bytes the caller should persist. Identical to the input when no migration
   * ran (`migrated: false`); the freshly-serialized v1 bytes when one did.
   */
  bytes: Uint8Array;
  /** true when at least one migration step was applied. */
  migrated: boolean;
}

/** Peek the outer `version` (and confirm the Cryptiq format) without the v1-only parseOuter. */
function peekVersion(bytes: Uint8Array): number {
  let raw: unknown;
  try {
    raw = JSON.parse(new TextDecoder('utf-8').decode(bytes));
  } catch (e) {
    throw new VaultCorruptError(`Vault file is not valid JSON: ${(e as Error).message}`);
  }
  if (raw === null || typeof raw !== 'object') {
    throw new VaultCorruptError('Vault file must be a JSON object.');
  }
  const obj = raw as Record<string, unknown>;
  if (obj.format !== FORMAT_IDENTIFIER) {
    throw new VaultCorruptError(
      `Vault file is not a Cryptiq vault (format=${JSON.stringify(obj.format)}).`,
    );
  }
  if (typeof obj.version !== 'number') {
    throw new VaultCorruptError(
      `Vault file: version must be a number (got ${typeof obj.version}).`,
    );
  }
  return obj.version;
}

/**
 * WR-04: validate an OLD document's `data` blob shape BEFORE handing it to decryptInner.
 * peekVersion only confirms `format` + numeric `version`, so `data` may be absent, a
 * non-object, or carry non-string nonce/ciphertext. Without this gate a bad shape would
 * throw a raw library-internal error inside `sodium.from_base64(...)` (e.g. "unsupported
 * input type"), which then leaked into the MigrationFailedError message. Fail closed here
 * with a DELIBERATE, controlled message that names the field (no library internals).
 */
function validateOldDataShape(data: unknown): { nonce: string; ciphertext: string } {
  if (data === null || typeof data !== 'object') {
    throw new MigrationFailedError(
      'Old vault document: data must be an object with base64 nonce + ciphertext.',
    );
  }
  const d = data as Record<string, unknown>;
  if (typeof d.nonce !== 'string' || typeof d.ciphertext !== 'string') {
    throw new MigrationFailedError(
      'Old vault document: data.nonce and data.ciphertext must both be base64 strings.',
    );
  }
  return { nonce: d.nonce, ciphertext: d.ciphertext };
}

/** Reconstruct runtime KdfParams from a stored wrap's per-wrap kdf (DC-3, decision 27 base64). */
async function wrappedKdfParams(wrapped: WrappedKeyV1): Promise<KdfParams> {
  const sodium = await getSodium();
  return {
    algorithm: 2,
    opsLimit: wrapped.kdf.opsLimit,
    memLimit: wrapped.kdf.memLimit,
    salt: sodium.from_base64(wrapped.kdf.salt, sodium.base64_variants.ORIGINAL),
  };
}

/**
 * Recover the vault key from an OLDER document's master/recovery wrap using the same
 * generic unwrap as unlockVault (DC-5). Version-agnostic: the wrap shape (WrappedKeyV1)
 * is stable across format versions in this scaffold — only the OUTER schema changes.
 */
async function recoverVaultKeyFromOld(
  oldDoc: Record<string, unknown>,
  secret: UnlockSecret,
): Promise<Uint8Array> {
  const wrappedKeys = oldDoc.wrappedKeys as Record<string, WrappedKeyV1 | undefined> | undefined;
  if (wrappedKeys === undefined || wrappedKeys === null) {
    throw new MigrationFailedError(
      'Old vault document has no wrappedKeys to recover the key from.',
    );
  }
  if ('masterPassword' in secret) {
    const master = wrappedKeys.master;
    if (master === undefined) {
      throw new MigrationFailedError('Old vault document has no master wrap.');
    }
    const params = await wrappedKdfParams(master);
    // WR-02: wipe the transient derived key on every exit (try/finally).
    const dk = await deriveKey(secret.masterPassword, params);
    let vaultKey: Uint8Array | null;
    try {
      vaultKey = await tryUnwrap(master, dk);
    } finally {
      await secureWipe(dk);
    }
    if (vaultKey === null) {
      throw new MigrationFailedError('Master password did not unlock the old vault for migration.');
    }
    return vaultKey;
  }
  const recovery = wrappedKeys.recovery;
  if (recovery === undefined) {
    throw new MigrationFailedError('Old vault document has no recovery wrap.');
  }
  const rawBytes = await decodeRecoveryKey(secret.recoveryKey);
  // WR-02: wipe the derived recovery wrap-key + raw recovery bytes on every exit.
  const wrapKeyBytes = await toRecoveryWrapKey(rawBytes);
  let vaultKey: Uint8Array | null;
  try {
    vaultKey = await tryUnwrap(recovery, wrapKeyBytes);
  } finally {
    await secureWipe(wrapKeyBytes);
    await secureWipe(rawBytes);
  }
  if (vaultKey === null) {
    throw new MigrationFailedError('Recovery key did not unlock the old vault for migration.');
  }
  return vaultKey;
}

/**
 * Build an ordered migration chain from `fromVersion` up to CURRENT_FORMAT_VERSION using
 * the supplied list. Each step must consume the previous step's `toVersion`. Returns null
 * when no contiguous path exists (→ UnknownVaultVersionError at the call site).
 */
function buildChain(
  fromVersion: number,
  migrations: ReadonlyArray<Migration<number, number>>,
): Migration<number, number>[] | null {
  const chain: Migration<number, number>[] = [];
  let cursor = fromVersion;
  // Bounded by the migration count — every step strictly advances the version forward.
  for (let guard = 0; guard <= migrations.length && cursor < CURRENT_FORMAT_VERSION; guard++) {
    const step = migrations.find((m) => m.fromVersion === cursor);
    if (step === undefined) return null;
    if (step.toVersion <= cursor) return null; // never accept a non-advancing step
    chain.push(step);
    cursor = step.toVersion;
  }
  return cursor === CURRENT_FORMAT_VERSION ? chain : null;
}

/**
 * Load a vault from bytes, migrating it forward to the current format version if needed,
 * with a pre-migration backup and a verify-by-cold-decrypt gate (Pitfall 13).
 *
 * @param bytes      the on-disk vault bytes (any known format version).
 * @param secret     DC-10 open-union unlock secret ({ masterPassword } | { recoveryKey }).
 * @param adapter    storage adapter — only `savePreMigrationBackup` is used here (Phase 3
 *                   owns the real load/save/swap; this returns the bytes to persist).
 * @param migrations the migration set to consider. Defaults to REGISTERED_MIGRATIONS
 *                   (EMPTY in v1). Tests/demo pass the synthetic v0→v1 here.
 *
 * @throws VaultCorruptError       foreign/corrupt bytes (bad JSON, wrong format).
 * @throws UnknownVaultVersionError no migration path from the file's version to current.
 * @throws MigrationFailedError    a step failed, OR the cold-decrypt verify failed
 *                                 (buggy migration emitted valid-looking but wrong bytes).
 */
export async function loadAndMigrate(
  bytes: Uint8Array,
  secret: UnlockSecret,
  adapter: { savePreMigrationBackup(name: string, bytes: Uint8Array): Promise<void> },
  migrations: ReadonlyArray<Migration<number, number>> = REGISTERED_MIGRATIONS,
): Promise<LoadAndMigrateResult> {
  // 1. Peek the version (does NOT use parseOuter, which only accepts the current version).
  const version = peekVersion(bytes);

  // Current version → no migration. Unlock straight through and return unchanged bytes.
  if (version === CURRENT_FORMAT_VERSION) {
    const { vault, vaultKey } = await unlockVault(bytes, secret);
    return { vault, vaultKey, bytes, migrated: false };
  }

  // Future / unknown-forward version → refuse (VAULT-07). Only OLDER versions migrate.
  if (version > CURRENT_FORMAT_VERSION) {
    throw new UnknownVaultVersionError(
      `Vault version ${version} is newer than this build supports (${CURRENT_FORMAT_VERSION}); cannot migrate forward.`,
    );
  }

  // 2. Build the migration chain. No path → refuse, never guess (T-02-22).
  const chain = buildChain(version, migrations);
  if (chain === null) {
    throw new UnknownVaultVersionError(
      `No migration path from vault version ${version} to ${CURRENT_FORMAT_VERSION}.`,
    );
  }

  // 3. Back up the ORIGINAL bytes BEFORE any transform (T-02-21 — never-rotated named backup).
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  await adapter.savePreMigrationBackup(`pre-v${CURRENT_FORMAT_VERSION}-backup-${stamp}`, bytes);

  // 4. Recover the vault key from the old wrap + decrypt the old inner once (migrate-copy input).
  const oldDoc = JSON.parse(new TextDecoder('utf-8').decode(bytes)) as Record<string, unknown>;
  const vaultKey = await recoverVaultKeyFromOld(oldDoc, secret);

  // WR-04: validate the old `data` shape with a DELIBERATE, controlled error BEFORE decrypt.
  // Done OUTSIDE the catch-all below so the controlled message is not re-wrapped/obscured by
  // a generic "could not decrypt" wrapper. On a bad shape, fail closed (wipe key + throw).
  let oldData: { nonce: string; ciphertext: string };
  try {
    oldData = validateOldDataShape(oldDoc.data);
  } catch (e) {
    await secureWipe(vaultKey);
    throw e;
  }

  let currentInner: object | null = null;
  try {
    const innerBytes = await decryptInner(oldData, vaultKey);
    // IN-05 mirror: an authentic-but-malformed inner blob must surface a typed error, not a
    // raw SyntaxError (the catch below re-wraps it as MigrationFailedError — fail closed).
    currentInner = JSON.parse(new TextDecoder().decode(innerBytes)) as object;
  } catch (e) {
    await secureWipe(vaultKey);
    throw new MigrationFailedError(
      `Could not decrypt the old vault's inner data for migration: ${(e as Error).message}`,
      e,
    );
  }

  // Apply each migration step in sequence. Each step returns the fully-formed
  // next-version document (with its own re-sealed `data`) plus the inner it sealed.
  let currentDoc: Record<string, unknown> = oldDoc;
  let referenceInner: object | null = currentInner;
  for (const step of chain) {
    const result = step.apply(
      currentDoc as unknown as Parameters<typeof step.apply>[0],
      currentInner,
      vaultKey,
    );
    if (!result.ok) {
      await secureWipe(vaultKey);
      throw new MigrationFailedError(
        `Migration ${step.fromVersion}→${step.toVersion} failed: ${result.reason}`,
      );
    }
    currentDoc = result.doc as unknown as Record<string, unknown>;
    currentInner = result.newInner;
    // The inner the FINAL step intended to seal is the cold-decrypt reference (the
    // bytes that must survive into the migrated file — Pitfall 13).
    referenceInner = result.newInner;
  }

  // 5. Serialize the final document → newBytes. WR-03: build the migrated v1 doc from an
  //    EXPLICIT field whitelist (format, version, wrappedKeys, data, meta) rather than
  //    spreading the final step's output. A buggy/partial step could otherwise carry stale or
  //    foreign top-level keys forward into the serialized v1 bytes — past the cold-decrypt
  //    gate, which only verifies the entries blob, NOT the outer shape. The orchestrator owns
  //    serialization; the migration owns the `data` ciphertext (so a wrong ciphertext is still
  //    carried into newBytes and caught by the cold-decrypt verify below — NOT a tautology).
  const finalSrc = currentDoc as unknown as VaultDocumentV1;
  const finalDoc: VaultDocumentV1 = {
    format: FORMAT_IDENTIFIER,
    version: CURRENT_FORMAT_VERSION,
    wrappedKeys: finalSrc.wrappedKeys,
    data: finalSrc.data,
    meta: finalSrc.meta,
  };
  const newBytes = new TextEncoder().encode(JSON.stringify(finalDoc, null, 2) + '\n');

  // 6. VERIFY-BY-COLD-DECRYPT (Pitfall 13, T-02-20, T-02-23). Drop the in-memory key + docs:
  //    re-parse and re-unlock the NEW bytes FRESH, re-deriving the key from the NEW file's
  //    stored kdf params. Assert a known entry round-trips. On ANY mismatch → reject.
  await secureWipe(vaultKey);

  let verified: { vault: UnlockedVault; vaultKey: Uint8Array };
  try {
    parseOuter(newBytes); // structural re-parse of the migrated file
    verified = await unlockVault(newBytes, secret); // cold re-derive + decrypt
  } catch (e) {
    throw new MigrationFailedError(
      `Cold-decrypt verification of the migrated vault failed: ${(e as Error).message}`,
      e,
    );
  }

  // Round-trip check: the cold-decrypted entries must equal the inner the final migration
  // step intended to seal (referenceInner). A step that emitted valid-looking but wrong
  // ciphertext either fails the AEAD open above OR mismatches here → reject (T-02-20).
  if (JSON.stringify(verified.vault.entries) !== JSON.stringify(referenceInner ?? {})) {
    await secureWipe(verified.vaultKey);
    throw new MigrationFailedError(
      'Cold-decrypt verification mismatch: migrated entries did not round-trip byte-for-byte.',
    );
  }

  // 7. Swap: hand back the migrated bytes + the freshly-unlocked vault (caller persists).
  return { vault: verified.vault, vaultKey: verified.vaultKey, bytes: newBytes, migrated: true };
}
