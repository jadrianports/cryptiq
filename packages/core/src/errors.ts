// packages/core/src/errors.ts
//
// DC-9 typed error subclasses — the SINGLE SOURCE OF TRUTH for Phase 2 crypto/vault
// failures. Lives in its own file (not inside any crypto/ or vault/ module) so it can
// be imported from both `crypto/` and `vault/` without circular dependencies.
//
// Shapes copied from the canonical Phase 1 pattern in storage/VaultStorageAdapter.ts:
//   Shape A — no constructor args (stable readonly `code` only)
//   Shape B — message-only constructor
//   Shape C — message + optional `cause`
//
// Every class carries a stable readonly `code` string so callers branch on `.code`
// (or `instanceof`) instead of matching message text. Fail-closed discipline: any
// decryption/auth/derivation failure surfaces one of these, never a bare Error.

/** Master password did not unwrap the vault key (AEAD MAC failure on the master wrap). */
export class WrongPasswordError extends Error {
  readonly code = 'WRONG_PASSWORD';
}

/** Recovery key was malformed or did not unwrap the vault key. */
export class WrongRecoveryKeyError extends Error {
  readonly code = 'WRONG_RECOVERY_KEY';
  constructor(message: string) {
    super(message);
  }
}

/**
 * Argon2id (or any KDF allocation) failed — typically an OS-refused memory
 * allocation (OOM) during calibration or unlock, OR the libsodium.js zero-buffer
 * restricted-environment OOM path (issue #235). Fail closed: a zero buffer is never
 * accepted as a key.
 */
export class KdfResourceError extends Error {
  readonly code = 'KDF_RESOURCE';
  constructor(message: string) {
    super(message);
  }
}

/**
 * Vault `version` is not recognized by this build. VAULT-07: refuse to open,
 * never guess. Newer-than-known versions land here.
 */
export class UnknownVaultVersionError extends Error {
  readonly code = 'UNKNOWN_VAULT_VERSION';
  constructor(message: string) {
    super(message);
  }
}

/** A migration step failed (or its cold-decrypt verification failed). */
export class MigrationFailedError extends Error {
  readonly code = 'MIGRATION_FAILED';
  constructor(
    message: string,
    public override readonly cause?: unknown,
  ) {
    super(message);
  }
}

/**
 * Vault bytes are not valid (bad JSON, missing required fields, or an AEAD
 * authentication failure indicating tampering / truncation).
 *
 * Canonical declaration. storage/VaultStorageAdapter.ts re-exports this symbol to
 * avoid a duplicate class with the same `code`.
 */
export class VaultCorruptError extends Error {
  readonly code = 'VAULT_CORRUPT';
  constructor(message: string) {
    super(message);
  }
}

/**
 * The key unwrapped from a wrap did NOT match the live in-memory vault key (a session
 * desync or caller bug). Fail closed: changeMasterPassword refuses to re-wrap a key that
 * does not match what the current wrap actually protects, which would otherwise brick the
 * (untouched) data blob. The message NEVER contains key bytes (SEC-09 / no-secrets rule).
 */
export class VaultKeyMismatchError extends Error {
  readonly code = 'VAULT_KEY_MISMATCH';
  constructor(message: string) {
    super(message);
  }
}

/**
 * A wrapped-key management operation was refused because it would touch a PROTECTED label
 * (the always-present `master` wrap). Adding over `master` could clobber the primary unlock
 * path; removing `master` would brick the vault. DC-4 guard rails surface this typed error
 * so callers branch on `instanceof`/`.code` rather than message text.
 */
export class ProtectedWrapError extends Error {
  readonly code = 'PROTECTED_WRAP';
  constructor(message: string) {
    super(message);
  }
}

// ---------------------------------------------------------------------------
// Phase 3 typed errors (DC-9 pattern — Shape B: message-only constructor)
// ---------------------------------------------------------------------------

/**
 * An entry CRUD verb was called with an ID that does not exist in the vault,
 * or the target entry is soft-deleted when the verb requires an active entry.
 * Callers branch on `instanceof EntryNotFoundError` or `.code === 'ENTRY_NOT_FOUND'`.
 */
export class EntryNotFoundError extends Error {
  readonly code = 'ENTRY_NOT_FOUND';
  constructor(message: string) {
    super(message);
  }
}

/**
 * The generator options are invalid (e.g. no character class enabled, length too
 * short for the enabled classes, or an empty/null preset when one is required).
 * Callers branch on `instanceof GeneratorError` or `.code === 'GENERATOR_INVALID_OPTIONS'`.
 */
export class GeneratorError extends Error {
  readonly code = 'GENERATOR_INVALID_OPTIONS';
  constructor(message: string) {
    super(message);
  }
}

// ---------------------------------------------------------------------------
// Phase 8 typed errors (DC-9 pattern — Shape B: message-only constructor)
// ---------------------------------------------------------------------------

/**
 * The two `InnerDoc`s have different `schemaVersion` values — merge refused before
 * any records are processed (D-09). Never normalize/guess across schemas.
 * User-facing effect: "update both apps, then sync."
 */
export class MergeSchemaMismatchError extends Error {
  readonly code = 'MERGE_SCHEMA_MISMATCH';
  constructor(message: string) {
    super(message);
  }
}

/**
 * Wall-clock difference between local and remote exceeds 30 seconds — merge aborted
 * before any records are processed (D-12, MERGE-06). Strict `> 30_000ms`.
 * The engine never reads the clock directly; the caller injects both timestamps.
 */
export class MergeClockSkewError extends Error {
  readonly code = 'MERGE_CLOCK_SKEW';
  constructor(message: string) {
    super(message);
  }
}

/**
 * An entry in either `InnerDoc` has an invalid shape (missing `id`, unparseable
 * `modifiedAt`, or another required field missing) — the whole merge is refused;
 * never partial (D-17). An empty vault (zero entries) is valid and does NOT throw.
 */
export class MergeInvalidInputError extends Error {
  readonly code = 'MERGE_INVALID_INPUT';
  constructor(message: string) {
    super(message);
  }
}
