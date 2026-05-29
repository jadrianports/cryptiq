// packages/core/src/vault/migrations/types.ts
//
// Migration framework interfaces (VAULT-04, RESEARCH Pattern 9). Types-only — no
// runtime code, no imports beyond the local placeholder below. The concrete
// `loadAndMigrate` orchestrator + REGISTERED_MIGRATIONS land in Plan 05; the
// concrete versioned `VaultDocumentV1` shape lands in Plan 02/03's vault/format.ts.
//
// For this scaffold we use a local generic `VaultDocumentVN<N>` placeholder so the
// interface compiles standalone. When vault/format.ts lands its versioned document
// types, this placeholder is replaced by the real per-version document union and the
// migrations index wires concrete migrations against it.

/**
 * Placeholder for a versioned vault document. Phase 2 Plan 02/03 replaces this with
 * the concrete `VaultDocumentV1` (and future `VaultDocumentV2`, ...) discriminated on
 * the literal `version` field. Carries the version as a phantom type parameter so the
 * `Migration<NFrom, NTo>` signature is statically version-checked.
 */
export interface VaultDocumentVN<N extends number> {
  readonly version: N;
  // Concrete fields (format, wrappedKeys, data, meta) land in vault/format.ts.
  readonly [key: string]: unknown;
}

/**
 * A single forward migration step from schema version `NFrom` to `NTo`.
 *
 * Migrations are PURE functions: they receive the parsed outer document plus
 * (optionally) the already-decrypted inner entries blob and the vault key, and
 * return either a transformed document + new inner blob, or a failure reason. They
 * perform NO I/O — backup writes and the cold-decrypt verify happen in the
 * orchestrator (Plan 05), not here (Pitfall 13 defense lives in the orchestrator).
 */
export interface Migration<NFrom extends number, NTo extends number> {
  readonly fromVersion: NFrom;
  readonly toVersion: NTo;
  readonly description: string;
  apply(
    doc: VaultDocumentVN<NFrom>,
    decryptedInner: object | null,
    vaultKey: Uint8Array | null,
  ): MigrationResult<NTo>;
}

/**
 * Discriminated-union result of a migration step. On success the orchestrator must
 * still cold-decrypt-verify the re-serialized + re-encrypted bytes before swapping
 * the live vault (Pitfall 13). On failure the orchestrator surfaces
 * `MigrationFailedError` and leaves the original file untouched.
 */
export type MigrationResult<NTo extends number> =
  | { ok: true; doc: VaultDocumentVN<NTo>; newInner: object | null }
  | { ok: false; reason: string };
