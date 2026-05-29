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
