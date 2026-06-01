// apps/desktop/src/lib/util/errors.ts
//
// P4-09 shared unlock-error mapping (AUTH-07).
//
// SECURITY: Auth failures (wrong password / wrong recovery key) MUST map to ONE
// identical generic string. The calling code must NEVER reveal which authentication
// path failed — doing so would give an attacker an oracle to distinguish a password
// attempt from a recovery-key attempt (AUTH-07 / T-04-01 information-disclosure threat).
//
// Operational failures (corrupt vault, migration-needed, OOM) DO get distinct,
// actionable copy — they are not security-sensitive and the user needs guidance.
//
// Canonical error classes from @cryptiq/core (packages/core/src/errors.ts):
//   WrongPasswordError      — AEAD MAC failure on the master wrap
//   WrongRecoveryKeyError   — malformed or non-matching recovery key
//   VaultCorruptError       — bad JSON / missing fields / AEAD auth failure (tampering)
//   UnknownVaultVersionError — version not recognized by this build
//   MigrationFailedError    — migration step or cold-decrypt verification failed
//   KdfResourceError        — OS refused the Argon2id memory allocation (OOM)

import {
  WrongPasswordError,
  WrongRecoveryKeyError,
  VaultCorruptError,
  UnknownVaultVersionError,
  MigrationFailedError,
  KdfResourceError,
  VaultLockedByOtherProcessError,
} from '@cryptiq/core';

/**
 * Map any thrown unlock error to a user-facing string.
 *
 * Rules (P4-09 / AUTH-07 / T-04-01):
 *   - WrongPasswordError + WrongRecoveryKeyError → ONE identical generic message.
 *     The two auth paths are deliberately collapsed. An attacker watching error
 *     messages MUST NOT learn which credential they got wrong.
 *   - VaultCorruptError → distinct, actionable (not security-sensitive).
 *   - UnknownVaultVersionError | MigrationFailedError → distinct, actionable.
 *   - KdfResourceError → distinct, actionable (memory pressure).
 *   - All other errors → safe generic fallback.
 *
 * @param e The caught error (unknown type — always use instanceof branching).
 * @returns A human-readable error string safe to display in the UI.
 */
export function mapUnlockError(e: unknown): string {
  // AUTH-07: generic for ALL auth failures — never reveal which path failed.
  if (e instanceof WrongPasswordError || e instanceof WrongRecoveryKeyError) {
    return "Couldn't unlock — check your password.";
  }

  // Distinct + actionable for operational failures (not security-sensitive).
  if (e instanceof VaultCorruptError) {
    return 'Vault file appears damaged. Restore from a backup.';
  }

  if (e instanceof UnknownVaultVersionError || e instanceof MigrationFailedError) {
    return 'Vault format is from a newer version of Cryptiq. Update the app.';
  }

  if (e instanceof KdfResourceError) {
    return 'Not enough memory to unlock. Close other apps and try again.';
  }

  // Advisory lock held by another live process (now effectively only a cross-host /
  // network-share scenario — same-host locks are always taken over). Clear + actionable
  // so this never falls through to the scary generic message (UAT T5).
  if (e instanceof VaultLockedByOtherProcessError) {
    return 'This vault is open in another Cryptiq window. Close it and try again.';
  }

  // Safe generic fallback — never expose raw error messages to the user.
  return 'Something went wrong. Please try again.';
}
