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

// ---------------------------------------------------------------------------
// Phase 9 typed errors (DC-9 pattern — Shape B: message-only constructor)
// ---------------------------------------------------------------------------

/**
 * The pairing code (Base32 + check character) failed local validation before any
 * network attempt. Avoids an opaque handshake failure on a simple typo (D-11).
 * Callers branch on `instanceof PairingCodeInvalidError` or `.code === 'PAIRING_CODE_INVALID'`.
 */
export class PairingCodeInvalidError extends Error {
  readonly code = 'PAIRING_CODE_INVALID';
  constructor(message: string) {
    super(message);
  }
}

/**
 * The SAS codes on both devices did not match, or the SAS window expired. Treat
 * as a MITM signal — wipe ephemeral state and show interception warning (D-04).
 * Callers branch on `instanceof PairingSasMismatchError` or `.code === 'PAIRING_SAS_MISMATCH'`.
 */
export class PairingSasMismatchError extends Error {
  readonly code = 'PAIRING_SAS_MISMATCH';
  constructor(message: string) {
    super(message);
  }
}

/**
 * A re-pair was attempted for a device already in peers.json without an explicit
 * "Remove and re-pair" flow (D-16). Prevents silent key rotation / replay.
 * Callers branch on `instanceof PairingAlreadyExistsError` or `.code === 'PAIRING_ALREADY_EXISTS'`.
 */
export class PairingAlreadyExistsError extends Error {
  readonly code = 'PAIRING_ALREADY_EXISTS';
  constructor(message: string) {
    super(message);
  }
}

/**
 * The Noise handshake failed — wrong PSK, message authentication failure, or
 * connection drop. Fail closed; never expose internal snow error details.
 * Callers branch on `instanceof PairingHandshakeError` or `.code === 'PAIRING_HANDSHAKE_FAILED'`.
 */
export class PairingHandshakeError extends Error {
  readonly code = 'PAIRING_HANDSHAKE_FAILED';
  constructor(message: string) {
    super(message);
  }
}

/**
 * Windows Credential Manager operation failed. Wraps the Win32 GetLastError code
 * as a numeric `win32ErrorCode` field so callers branch on the stable `.code` string
 * or inspect the numeric error. Error message strings NEVER contain key bytes (SEC-09).
 * Callers branch on `instanceof CredentialManagerError` or `.code === 'CREDENTIAL_MANAGER_ERROR'`.
 */
export class CredentialManagerError extends Error {
  readonly code = 'CREDENTIAL_MANAGER_ERROR';
  constructor(
    message: string,
    public readonly win32ErrorCode?: number,
  ) {
    super(message);
  }
}

/**
 * `peers.json` failed schema or JSON validation — fail closed on bad JSON, missing
 * required fields, or unknown `schemaVersion` (never guess across schemas, mirrors
 * the `UnknownVaultVersionError` precedent).
 * Callers branch on `instanceof PeersDocCorruptError` or `.code === 'PEERS_DOC_CORRUPT'`.
 */
export class PeersDocCorruptError extends Error {
  readonly code = 'PEERS_DOC_CORRUPT';
  constructor(message: string) {
    super(message);
  }
}

/**
 * Initiating or accepting a pairing was attempted while the vault is LOCKED (D-18).
 * The frontend unlock guard in syncBridge.ts / PairingStore throws this before any
 * `pairing_initiate` / `pairing_connect` / `pairing_confirm` Tauri invoke, ensuring
 * the vault key is available before any pairing network activity begins.
 * Callers branch on `instanceof PairingRequiresUnlockError` or `.code === 'PAIRING_REQUIRES_UNLOCK'`.
 */
export class PairingRequiresUnlockError extends Error {
  readonly code = 'PAIRING_REQUIRES_UNLOCK';
  constructor(message: string) {
    super(message);
  }
}

// ---------------------------------------------------------------------------
// Phase 10 typed errors (fail-closed sync error set — DC-9 pattern, Shape B)
//
// HARDEN-02 (Phase 13) audits and locks this set. Do NOT change the stable
// `code` strings after Phase 10 — callers branch on them.
// Do NOT add SyncMergeError here (deferred to Phase 11/13 scope).
// ---------------------------------------------------------------------------

/**
 * The sync peer could not be reached within the connect/handshake deadline.
 * Also used when the IK handshake fails (wrong static key or MAC failure) —
 * deliberately indistinguishable from "unreachable" to avoid probing (SYNC-06).
 * Callers branch on `instanceof SyncPeerUnreachableError` or `.code === 'SYNC_PEER_UNREACHABLE'`.
 * User-facing: "Could not reach [device name] — check that it is on the same network
 * and the vault is unlocked."
 */
export class SyncPeerUnreachableError extends Error {
  readonly code = 'SYNC_PEER_UNREACHABLE';
  constructor(message: string) {
    super(message);
  }
}

/**
 * The remote blob failed to decrypt, indicating the peer's vault uses a different
 * master password. The vaultPairId binding was verified (correct vault) but the keys
 * diverged (e.g., password changed on one device without syncing). SYNC-05.
 * Callers branch on `instanceof SyncAuthFailedError` or `.code === 'SYNC_AUTH_FAILED'`.
 * User-facing: "Master passwords do not match. Ensure both vaults use the same
 * master password."
 */
export class SyncAuthFailedError extends Error {
  readonly code = 'SYNC_AUTH_FAILED';
  constructor(message: string) {
    super(message);
  }
}

/**
 * The sync transport encountered a framing, MAC, or IO error after the IK handshake
 * completed. The vault was not modified. Retry after checking network stability.
 * Callers branch on `instanceof SyncTransportError` or `.code === 'SYNC_TRANSPORT_ERROR'`.
 */
export class SyncTransportError extends Error {
  readonly code = 'SYNC_TRANSPORT_ERROR';
  constructor(message: string) {
    super(message);
  }
}

/**
 * The vaultPairId in the binding-check frame did not match the expected value in
 * peers.json. The remote device is paired to a DIFFERENT vault instance. Abort
 * immediately — no vault bytes should have been exchanged (SYNC-03).
 * Callers branch on `instanceof SyncBindingMismatchError` or `.code === 'SYNC_BINDING_MISMATCH'`.
 */
export class SyncBindingMismatchError extends Error {
  readonly code = 'SYNC_BINDING_MISMATCH';
  constructor(message: string) {
    super(message);
  }
}

// ---------------------------------------------------------------------------
// Phase 11 typed errors (partial-commit states + busy guard — DC-9 pattern, Shape B)
//
// D-02a: ack received but A's save failed — partner updated; this device did not save.
// D-02b: no ack received — neither side known committed; sync did not complete.
// D-08: second sync attempted while one is in flight — partner busy.
// D-06: partner's vault locked mid-sync — abort, no save, no ack.
//
// HARDEN-02 (Phase 13) audits and locks this set. Do NOT change the stable `code` strings.
// Do NOT add SyncMergeError here — deferred to Phase 13 HARDEN-02 scope.
// ---------------------------------------------------------------------------

/**
 * D-02a: The ack was received (partner's save succeeded) but this device's own save
 * failed. B definitely committed; A definitely did not. The user should sync again to
 * bring A up to date with B's committed state.
 * User-facing: "partner updated; this device did not save — sync again"
 * Callers branch on `instanceof SyncPartnerNotSavedError` or `.code === 'SYNC_PARTNER_NOT_SAVED'`.
 */
export class SyncPartnerNotSavedError extends Error {
  readonly code = 'SYNC_PARTNER_NOT_SAVED';
  constructor(message: string) {
    super(message);
  }
}

/**
 * D-02b: No ack was received — the sync did not complete and neither side is known to
 * have committed. The user should sync again; both vaults remain in their pre-sync state.
 * User-facing: "sync did not complete — no changes confirmed on this device; sync again"
 * Callers branch on `instanceof SyncNoAckError` or `.code === 'SYNC_NO_ACK'`.
 */
export class SyncNoAckError extends Error {
  readonly code = 'SYNC_NO_ACK';
  constructor(message: string) {
    super(message);
  }
}

/**
 * D-08: A second sync was attempted while one is already in flight. The busy guard
 * (SyncBusyGuard managed state) rejects concurrent syncs to prevent interleaved
 * partial-commit states. Retry after the in-flight sync completes.
 * User-facing: "sync already in progress — try again in a moment"
 * Callers branch on `instanceof SyncPartnerBusyError` or `.code === 'SYNC_PARTNER_BUSY'`.
 */
export class SyncPartnerBusyError extends Error {
  readonly code = 'SYNC_PARTNER_BUSY';
  constructor(message: string) {
    super(message);
  }
}

/**
 * D-06: The partner's vault locked mid-sync. Lock wins — the in-flight sync is aborted
 * with no save and no ack on either device. The user must unlock the partner vault and
 * sync again.
 * User-facing: "partner locked mid-sync — unlock and sync again"
 * Callers branch on `instanceof SyncLockedMidSyncError` or `.code === 'SYNC_LOCKED_MID_SYNC'`.
 */
export class SyncLockedMidSyncError extends Error {
  readonly code = 'SYNC_LOCKED_MID_SYNC';
  constructor(message: string) {
    super(message);
  }
}
