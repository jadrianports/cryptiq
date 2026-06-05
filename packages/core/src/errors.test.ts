// packages/core/src/errors.test.ts
//
// Regression-lock assertions for every Phase 9 pairing typed-error class.
// Purpose: pin the stable `code` strings so a downstream rename of a code constant
// breaks this test immediately — callers in syncBridge.ts / PairingStore.svelte.ts
// and the Rust→JS error mapping all branch on `.code`, not message text.
//
// Coverage:
//   PAIRING_CODE_INVALID     — D-11: typo caught before any network attempt
//   PAIRING_SAS_MISMATCH     — D-04: MITM signal; wipe ephemeral state
//   PAIRING_ALREADY_EXISTS   — D-16: re-pair requires explicit remove-and-re-pair
//   PAIRING_HANDSHAKE_FAILED — Noise handshake / auth failure; fail closed
//   CREDENTIAL_MANAGER_ERROR — Win32 GetLastError wrapper; win32ErrorCode roundtrip
//   PEERS_DOC_CORRUPT        — peers.json parse failure; fail closed on bad schema
//   PAIRING_REQUIRES_UNLOCK  — D-18: unlock-precondition guard (frontend throws this)
//
// Conventions (CLAUDE.md):
//   - No Math.random; no getSodium() — pure typed-error construction, no crypto needed.
//   - No console.* calls.
//   - Import only from './errors' and 'vitest' — no Tauri / Svelte / snow imports.

import { describe, it, expect } from 'vitest';
import {
  PairingCodeInvalidError,
  PairingSasMismatchError,
  PairingAlreadyExistsError,
  PairingHandshakeError,
  CredentialManagerError,
  PeersDocCorruptError,
  PairingRequiresUnlockError,
} from './errors';

describe('Phase 9 pairing typed errors — stable code regression guard', () => {
  describe('PairingCodeInvalidError', () => {
    it('carries code PAIRING_CODE_INVALID', () => {
      const err = new PairingCodeInvalidError('bad pairing code');
      expect(err.code).toBe('PAIRING_CODE_INVALID');
    });

    it('preserves the error message', () => {
      const err = new PairingCodeInvalidError('bad pairing code');
      expect(err.message).toBe('bad pairing code');
    });

    it('is instanceof Error', () => {
      const err = new PairingCodeInvalidError('bad pairing code');
      expect(err).toBeInstanceOf(Error);
    });
  });

  describe('PairingSasMismatchError', () => {
    it('carries code PAIRING_SAS_MISMATCH', () => {
      const err = new PairingSasMismatchError('SAS mismatch — possible MITM');
      expect(err.code).toBe('PAIRING_SAS_MISMATCH');
    });

    it('preserves the error message', () => {
      const err = new PairingSasMismatchError('SAS mismatch — possible MITM');
      expect(err.message).toBe('SAS mismatch — possible MITM');
    });

    it('is instanceof Error', () => {
      const err = new PairingSasMismatchError('SAS mismatch — possible MITM');
      expect(err).toBeInstanceOf(Error);
    });
  });

  describe('PairingAlreadyExistsError', () => {
    it('carries code PAIRING_ALREADY_EXISTS', () => {
      const err = new PairingAlreadyExistsError('device already paired');
      expect(err.code).toBe('PAIRING_ALREADY_EXISTS');
    });

    it('preserves the error message', () => {
      const err = new PairingAlreadyExistsError('device already paired');
      expect(err.message).toBe('device already paired');
    });

    it('is instanceof Error', () => {
      const err = new PairingAlreadyExistsError('device already paired');
      expect(err).toBeInstanceOf(Error);
    });
  });

  describe('PairingHandshakeError', () => {
    it('carries code PAIRING_HANDSHAKE_FAILED', () => {
      const err = new PairingHandshakeError('Noise handshake failed');
      expect(err.code).toBe('PAIRING_HANDSHAKE_FAILED');
    });

    it('preserves the error message', () => {
      const err = new PairingHandshakeError('Noise handshake failed');
      expect(err.message).toBe('Noise handshake failed');
    });

    it('is instanceof Error', () => {
      const err = new PairingHandshakeError('Noise handshake failed');
      expect(err).toBeInstanceOf(Error);
    });
  });

  describe('CredentialManagerError', () => {
    it('carries code CREDENTIAL_MANAGER_ERROR', () => {
      const err = new CredentialManagerError('CredWriteW failed', 1168);
      expect(err.code).toBe('CREDENTIAL_MANAGER_ERROR');
    });

    it('preserves the error message', () => {
      const err = new CredentialManagerError('CredWriteW failed', 1168);
      expect(err.message).toBe('CredWriteW failed');
    });

    it('is instanceof Error', () => {
      const err = new CredentialManagerError('CredWriteW failed', 1168);
      expect(err).toBeInstanceOf(Error);
    });

    it('round-trips win32ErrorCode when provided', () => {
      const err = new CredentialManagerError('CredWriteW failed', 1168);
      expect(err.win32ErrorCode).toBe(1168);
    });

    it('win32ErrorCode is undefined when omitted', () => {
      const err = new CredentialManagerError('CredReadW failed');
      expect(err.win32ErrorCode).toBeUndefined();
    });
  });

  describe('PeersDocCorruptError', () => {
    it('carries code PEERS_DOC_CORRUPT', () => {
      const err = new PeersDocCorruptError('peers.json has unknown schemaVersion');
      expect(err.code).toBe('PEERS_DOC_CORRUPT');
    });

    it('preserves the error message', () => {
      const err = new PeersDocCorruptError('peers.json has unknown schemaVersion');
      expect(err.message).toBe('peers.json has unknown schemaVersion');
    });

    it('is instanceof Error', () => {
      const err = new PeersDocCorruptError('peers.json has unknown schemaVersion');
      expect(err).toBeInstanceOf(Error);
    });
  });

  describe('PairingRequiresUnlockError (D-18 regression guard)', () => {
    it('carries code PAIRING_REQUIRES_UNLOCK', () => {
      const err = new PairingRequiresUnlockError('vault must be unlocked before pairing');
      expect(err.code).toBe('PAIRING_REQUIRES_UNLOCK');
    });

    it('preserves the error message', () => {
      const err = new PairingRequiresUnlockError('vault must be unlocked before pairing');
      expect(err.message).toBe('vault must be unlocked before pairing');
    });

    it('is instanceof Error', () => {
      const err = new PairingRequiresUnlockError('vault must be unlocked before pairing');
      expect(err).toBeInstanceOf(Error);
    });
  });
});
