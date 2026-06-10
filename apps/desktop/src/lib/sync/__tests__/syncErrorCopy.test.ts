// apps/desktop/src/lib/sync/__tests__/syncErrorCopy.test.ts
//
// Wave-0 node test: D-15 error copy fence.
// Asserts that all error body strings are static (no URLs, length < 300),
// and that connect/handshake failures both produce the same heading (T-10-20).
//
// Environment: node (vitest.config.ts — no browser provider invoked).

import { describe, it, expect } from 'vitest';
import {
  SyncPeerUnreachableError,
  SyncAuthFailedError,
  SyncBindingMismatchError,
  SyncTransportError,
  SyncPartnerNotSavedError,
  SyncNoAckError,
  SyncPartnerBusyError,
  SyncLockedMidSyncError,
} from '@cryptiq/core';
import { syncErrorToCopy } from '../syncErrorCopy';

// All error classes to test
const allErrorInstances = [
  new SyncPeerUnreachableError('raw connect timed out'),
  new SyncAuthFailedError('raw auth failed'),
  new SyncBindingMismatchError('raw binding mismatch'),
  new SyncTransportError('raw transport error'),
  new SyncPartnerNotSavedError('raw partner not saved'),
  new SyncNoAckError('raw no ack'),
  new SyncPartnerBusyError('raw busy'),
  new SyncLockedMidSyncError('raw locked mid sync'),
];

describe('syncErrorToCopy — D-15 error copy fence', () => {
  describe('all body strings are static (no URL, length < 300)', () => {
    for (const err of allErrorInstances) {
      it(`${err.constructor.name}: body has no URL and is < 300 chars`, () => {
        const { body } = syncErrorToCopy(err);
        expect(body).not.toMatch(/https?:\/\//);
        expect(body.length).toBeLessThan(300);
      });
    }
  });

  describe('no crypto-state distinction: connect and handshake both produce same heading (T-10-20)', () => {
    it('SyncPeerUnreachableError and a handshake-failure string produce the same heading shape', () => {
      const fromTyped = syncErrorToCopy(new SyncPeerUnreachableError('IK handshake failed'));
      // A string that looks like a handshake failure should also map to "Couldn't reach..."
      const fromString = syncErrorToCopy(
        "Sync failed: could not reach the peer. Check that the other device is online and unlocked.",
        'Alice-Laptop',
      );
      // Both should contain "Couldn't reach" in the heading (no crypto-state distinction)
      expect(fromTyped.heading).toContain("Couldn't reach");
      expect(fromString.heading).toContain("Couldn't reach");
    });

    it('connect timeout and IK handshake failure both map to SyncPeerUnreachable heading', () => {
      const connectErr = new SyncPeerUnreachableError('connect timed out');
      const handshakeErr = new SyncPeerUnreachableError('IK handshake failed');
      const connectCopy = syncErrorToCopy(connectErr);
      const handshakeCopy = syncErrorToCopy(handshakeErr);
      expect(connectCopy.heading).toBe(handshakeCopy.heading);
      expect(connectCopy.body).toBe(handshakeCopy.body);
    });
  });

  describe('individual error mappings match UI-SPEC table', () => {
    it('SyncPeerUnreachableError → "Couldn\'t reach…"', () => {
      const { heading, body } = syncErrorToCopy(
        new SyncPeerUnreachableError('connect failed'),
        'Bob-PC',
      );
      expect(heading).toBe("Couldn't reach Bob-PC");
      expect(body).toContain('same network');
    });

    it('SyncAuthFailedError → "Authentication failed"', () => {
      const { heading, body } = syncErrorToCopy(new SyncAuthFailedError('auth failed'));
      expect(heading).toBe('Authentication failed');
      expect(body).toContain('master password');
    });

    it('SyncBindingMismatchError → "Vault mismatch"', () => {
      const { heading, body } = syncErrorToCopy(new SyncBindingMismatchError('binding mismatch'));
      expect(heading).toBe('Vault mismatch');
      expect(body).toContain('Unpair');
    });

    it('SyncTransportError → "Connection lost"', () => {
      const { heading, body } = syncErrorToCopy(new SyncTransportError('framing error'));
      expect(heading).toBe('Connection lost');
      expect(body).toContain('unchanged');
    });

    it('SyncPartnerNotSavedError → "Sync incomplete"', () => {
      const { heading, body } = syncErrorToCopy(new SyncPartnerNotSavedError("partner didn't save"));
      expect(heading).toBe('Sync incomplete');
      expect(body).toContain("didn't confirm");
    });

    it('SyncNoAckError → "Sync incomplete" (same as SyncPartnerNotSavedError)', () => {
      const { heading } = syncErrorToCopy(new SyncNoAckError('no ack'));
      expect(heading).toBe('Sync incomplete');
    });

    it('SyncPartnerBusyError → "Other device is busy"', () => {
      const { heading, body } = syncErrorToCopy(new SyncPartnerBusyError('busy'));
      expect(heading).toBe('Other device is busy');
      expect(body).toContain('in progress');
    });

    it('SyncLockedMidSyncError → "Vault locked during sync"', () => {
      const { heading, body } = syncErrorToCopy(new SyncLockedMidSyncError('locked mid sync'));
      expect(heading).toBe('Vault locked during sync');
      expect(body).toContain('locked');
    });

    it('unknown error → generic "Sync failed"', () => {
      const { heading, body } = syncErrorToCopy(new Error('something unexpected'));
      expect(heading).toBe('Sync failed');
      expect(body).toContain('unexpected');
    });

    it('null → generic "Sync failed"', () => {
      const { heading } = syncErrorToCopy(null);
      expect(heading).toBe('Sync failed');
    });
  });

  describe('string fallback routing (syncStore.lastError display string)', () => {
    it('routes "could not reach the peer" string to peer-unreachable copy', () => {
      const { heading } = syncErrorToCopy(
        'Sync failed: could not reach the peer. Check that the other device is online and unlocked.',
        'Alice',
      );
      expect(heading).toContain("Couldn't reach");
    });

    it('routes "binding" string to vault mismatch', () => {
      const { heading } = syncErrorToCopy('sync_now: binding check failed: vaultPairId mismatch');
      expect(heading).toBe('Vault mismatch');
    });
  });
});
