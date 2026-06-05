// packages/core/src/sync/pairingCode.ts
//
// Phase 9 — D-11: pairing-code local validator (pure core, no Tauri/Svelte/node imports).
//
// DESIGN DECISIONS:
//   D-11: A mistyped pairing code is caught LOCALLY by verifying the Crockford check
//         character BEFORE any connect attempt. A typo surfaces as a clear
//         PairingCodeInvalidError, not an opaque handshake failure.
//   D-18: Initiating or accepting a pairing while the vault is LOCKED is refused via
//         assertVaultUnlockedForPairing(isUnlocked). The guard is a pure boolean-injected
//         predicate (mirroring lockLogic.ts) — the frontend owns and injects the lock
//         state; no IO/syscalls in core.
//   B3:   The validator lives in core so its regression test runs under the fast core
//         Vitest runner, NOT the flaky desktop browser-mode suite.
//
// REUSED from recovery.ts (no modification to that file):
//   encodeCrockfordBase32 — encode raw bytes to Crockford Base32 string
//   decodeCrockfordBase32 — decode Base32 string back to bytes; throws WrongRecoveryKeyError
//   crockfordCheckChar    — compute the Crockford check character (bytes mod 37)
//
// PAIRING CODE FORMAT (D-07/D-11):
//   The full pairing bundle is "IP:PORT:BASE32BODY+CHECKCHAR" where:
//     - BASE32BODY = crockford_encode(32-byte secret) = 52 chars (32 bytes × 8 / 5 = 51.2 → 52)
//     - CHECKCHAR  = crockfordCheckChar(32-byte secret) = 1 char
//   validatePairingCode validates ONLY the check-character portion of the secret field.
//   Full IP:PORT:SECRET parsing is done in Rust (pairing.rs decode_pairing_code).
//   This split is intentional (Pattern 5): JS validates typo before any network,
//   Rust decodes the full bundle for the actual handshake.
//
// CORE PURITY: no @tauri-apps/*, no svelte, no node:fs, no node:path.

import {
  encodeCrockfordBase32,
  decodeCrockfordBase32,
  crockfordCheckChar,
} from '../crypto/recovery';
import { PairingCodeInvalidError, PairingRequiresUnlockError } from '../errors';

// Re-export for consumers that import from @cryptiq/core barrel
export { encodeCrockfordBase32, decodeCrockfordBase32, crockfordCheckChar };

/**
 * The secret portion of a decoded pairing code (the Base32 body + raw bytes).
 * Returned by validatePairingCode on success.
 */
export interface PairingCodePayload {
  /** The raw decoded bytes of the pairing secret (32 bytes for a pairing code). */
  rawBytes: Uint8Array;
  /** The normalized uppercase body string (Base32 only, without the check char). */
  base32Body: string;
  /** The check character that was verified. */
  checkChar: string;
}

/**
 * Validate a pairing code string by verifying its Crockford check character (D-11).
 *
 * The pairing code format is "IP:PORT:BASE32BODY+CHECKCHAR". This function accepts
 * either the FULL bundle (IP:PORT:…) or just the SECRET portion (BASE32BODY+CHECKCHAR).
 * It strips all formatting, normalizes to uppercase, splits off the last character as
 * the check character, decodes the body, and verifies the check.
 *
 * A single mistyped character throws PairingCodeInvalidError — the user sees a clear
 * "typo detected" message instead of an opaque handshake failure (D-11).
 *
 * Look-alike mapping (I/L→1, O→0, U→V) is applied to the BASE32 BODY only (not the
 * check char), mirroring the recovery.ts normalization discipline (CR-01 parity).
 *
 * @param input Raw typed pairing code (any grouping/formatting is stripped).
 * @returns     PairingCodePayload containing rawBytes, base32Body, checkChar.
 * @throws      PairingCodeInvalidError if the code fails check-character verification
 *              or contains characters outside the Crockford alphabet.
 */
export function validatePairingCode(input: string): PairingCodePayload {
  if (!input || input.trim() === '') {
    throw new PairingCodeInvalidError(
      'Pairing code is empty — please enter the code shown on the other device.',
    );
  }

  // Extract the secret field: if the code has ":" separators (full bundle IP:PORT:SECRET),
  // take only the last segment. Otherwise treat the whole input as the secret field.
  const trimmed = input.trim();
  const colonCount = (trimmed.match(/:/g) ?? []).length;
  const secretField =
    colonCount >= 2
      ? trimmed.slice(trimmed.lastIndexOf(':') + 1) // third segment of IP:PORT:SECRET
      : trimmed; // raw secret-only input

  // Uppercase + strip non-Crockford characters (formatting dashes, spaces, etc.).
  // Note: CHECK_ALPHABET includes '*', '~', '$', '=', 'U' — keep them.
  const normalized = secretField.toUpperCase().replace(/[^0-9A-Z*~$=]/g, '');

  if (normalized.length < 2) {
    throw new PairingCodeInvalidError(
      `Pairing code secret field is too short after normalization (got ${normalized.length} character(s)).`,
    );
  }

  // Split: everything except the last char is the Base32 body; the last char is the check.
  const base32Body = normalized.slice(0, -1);
  const checkChar = normalized.slice(-1)!;

  // Apply look-alike mapping to the BASE32 BODY only (not the check char — 'U' is a
  // valid check symbol at index 36, CR-01 parity with recovery.ts).
  const mappedBody = base32Body
    .replace(/[IL]/g, '1')
    .replace(/O/g, '0')
    .replace(/U/g, 'V');

  // Decode the Base32 body → raw bytes. decodeCrockfordBase32 throws WrongRecoveryKeyError
  // on any out-of-alphabet character; we catch and re-throw as PairingCodeInvalidError.
  let rawBytes: Uint8Array;
  try {
    rawBytes = decodeCrockfordBase32(mappedBody);
  } catch (_err) {
    throw new PairingCodeInvalidError(
      `Pairing code contains an invalid character — looks like a typo. Please check the code and try again.`,
    );
  }

  // Verify the check character (D-11 — typo guard).
  const expectedCheck = crockfordCheckChar(rawBytes);
  if (checkChar !== expectedCheck) {
    throw new PairingCodeInvalidError(
      `Pairing code check character does not match (got '${checkChar}', expected '${expectedCheck}') — looks like one character is wrong.`,
    );
  }

  return { rawBytes, base32Body: mappedBody, checkChar };
}

/**
 * D-18 unlock guard: assert that the vault is unlocked before initiating or accepting
 * a pairing. Throws PairingRequiresUnlockError if the vault is locked.
 *
 * This is a PURE boolean-injected predicate (mirroring lockLogic.ts). The frontend
 * owns the actual lock state and injects `vaultSession.isUnlocked` here. No IO,
 * no syscalls, no Tauri imports — so this can be tested under the core Vitest runner.
 *
 * syncBridge.ts calls this with `vaultSession.isUnlocked` BEFORE every
 * pairing-initiating invoke (pairing_initiate, pairing_connect, pairing_confirm).
 *
 * @param isUnlocked Whether the vault is currently unlocked (from VaultSession).
 * @throws           PairingRequiresUnlockError if isUnlocked is false (D-18).
 */
export function assertVaultUnlockedForPairing(isUnlocked: boolean): void {
  if (!isUnlocked) {
    throw new PairingRequiresUnlockError(
      'Pairing requires the vault to be unlocked. Please unlock the vault first.',
    );
  }
}
