// packages/core/src/vault/migrations/types.ts
//
// Migration framework interfaces (VAULT-04, RESEARCH Pattern 9). Types-only — no
// runtime code. Finalized in Plan 05 now that vault/format.ts ships the concrete
// `VaultDocumentV1`. The concrete `loadAndMigrate` orchestrator + REGISTERED_MIGRATIONS
// live in ./index.ts.
//
// A migration step transforms a document at schema version `NFrom` into one at `NTo`.
// We keep the version as a phantom type parameter (`VaultDocumentVN<N>`) so the
// `Migration<NFrom, NTo>` signature is statically version-checked at the call site
// (e.g. a `Migration<0, 1>` only accepts a `version: 0` document and only yields a
// `version: 1` one). The CURRENT on-disk shape is the concrete `VaultDocumentV1` in
// format.ts; older versions (v0) have no concrete TS type — they exist only as inputs
// to a migration — so the generic placeholder is the right model for the FROM side.

import type { VaultDocumentV1 } from '../format';

/** The open shape of an older (pre-current) vault document, read opaquely by a migration. */
export interface VaultDocumentVOld<N extends number> {
  readonly version: N;
  readonly [key: string]: unknown;
}

/**
 * A versioned vault document carrying its schema version as a phantom literal `N`.
 *
 * For `N = 1` (the CURRENT version) this resolves to the concrete `VaultDocumentV1` so a
 * `Migration<_, 1>` can return the real on-disk shape directly. For older `N` (e.g. the
 * synthetic v0 used only in tests) there is no concrete TS type — the document is whatever
 * the prior on-disk format was, with a `version: N` discriminator, modeled by the open
 * `VaultDocumentVOld<N>`. When a future v2 lands, this conditional grows a `2` arm.
 */
export type VaultDocumentVN<N extends number> = N extends 1
  ? VaultDocumentV1
  : VaultDocumentVOld<N>;

/**
 * The current-version document, expressed through the generic so a `Migration<_, 1>`
 * can return the concrete `VaultDocumentV1` and still satisfy `VaultDocumentVN<1>`.
 */
export type CurrentVaultDocument = VaultDocumentV1;

/**
 * A single forward migration step from schema version `NFrom` to `NTo`.
 *
 * Migrations are PURE functions: they receive the parsed outer document, the
 * already-decrypted inner entries blob (the orchestrator unlocked it once), and the
 * recovered vault key, and return either a transformed document + new inner blob, or a
 * failure reason. They perform NO I/O — the pre-migration backup write and the
 * cold-decrypt verify both happen in the orchestrator (Pitfall 13 defense lives in
 * loadAndMigrate, never inside a migration step).
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
 * Discriminated-union result of a migration step. On `ok: true` the orchestrator must
 * STILL cold-decrypt-verify the re-serialized + re-encrypted bytes before swapping the
 * live vault (Pitfall 13) — a step returning `ok: true` is necessary but not sufficient.
 * On `ok: false` the orchestrator surfaces `MigrationFailedError` and leaves the original
 * file untouched (the pre-migration backup is already on disk).
 */
export type MigrationResult<NTo extends number> =
  | { ok: true; doc: VaultDocumentVN<NTo>; newInner: object | null }
  | { ok: false; reason: string };
