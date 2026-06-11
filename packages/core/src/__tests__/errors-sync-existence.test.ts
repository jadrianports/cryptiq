// packages/core/src/__tests__/errors-sync-existence.test.ts
//
// HARDEN-02 regression-lock assertions for the four Phase-13-named typed error classes.
// Purpose: pin the stable `code` strings + `cause` preservation so a downstream
// rename of a class or code constant breaks this test immediately.
//
// Conventions (CLAUDE.md):
//   - No Math.random; no getSodium() — pure typed-error construction.
//   - No console.* calls.
//   - Import only from '../errors' and 'vitest'.

import { describe, it, expect } from 'vitest';
import {
  SyncPeerUnreachableError,
  SyncAuthFailedError,
  SyncTransportError,
  SyncMergeError,
  MergeSchemaMismatchError,
} from '../errors';

describe('HARDEN-02 error-existence regression lock', () => {
  describe('SyncPeerUnreachableError (HARDEN-02)', () => {
    it('carries code SYNC_PEER_UNREACHABLE', () => {
      const err = new SyncPeerUnreachableError('could not reach peer');
      expect(err.code).toBe('SYNC_PEER_UNREACHABLE');
    });

    it('preserves the error message', () => {
      const err = new SyncPeerUnreachableError('could not reach peer');
      expect(err.message).toBe('could not reach peer');
    });

    it('is instanceof Error', () => {
      const err = new SyncPeerUnreachableError('could not reach peer');
      expect(err).toBeInstanceOf(Error);
    });
  });

  describe('SyncAuthFailedError (HARDEN-02)', () => {
    it('carries code SYNC_AUTH_FAILED', () => {
      const err = new SyncAuthFailedError('master passwords do not match');
      expect(err.code).toBe('SYNC_AUTH_FAILED');
    });

    it('preserves the error message', () => {
      const err = new SyncAuthFailedError('master passwords do not match');
      expect(err.message).toBe('master passwords do not match');
    });

    it('is instanceof Error', () => {
      const err = new SyncAuthFailedError('master passwords do not match');
      expect(err).toBeInstanceOf(Error);
    });
  });

  describe('SyncTransportError (HARDEN-02)', () => {
    it('carries code SYNC_TRANSPORT_ERROR', () => {
      const err = new SyncTransportError('framing error after handshake');
      expect(err.code).toBe('SYNC_TRANSPORT_ERROR');
    });

    it('preserves the error message', () => {
      const err = new SyncTransportError('framing error after handshake');
      expect(err.message).toBe('framing error after handshake');
    });

    it('is instanceof Error', () => {
      const err = new SyncTransportError('framing error after handshake');
      expect(err).toBeInstanceOf(Error);
    });
  });

  describe('SyncMergeError (HARDEN-02 D-07)', () => {
    it('carries code SYNC_MERGE_ERROR', () => {
      const e = new SyncMergeError('merge failed on sync path');
      expect(e.code).toBe('SYNC_MERGE_ERROR');
    });

    it('preserves the error message', () => {
      const e = new SyncMergeError('merge failed on sync path');
      expect(e.message).toBe('merge failed on sync path');
    });

    it('is instanceof Error', () => {
      const e = new SyncMergeError('merge failed on sync path');
      expect(e).toBeInstanceOf(Error);
    });

    it('preserves typed cause when provided', () => {
      const cause = new MergeSchemaMismatchError('schema mismatch');
      const e = new SyncMergeError('schema mismatch on sync path', cause);
      expect(e.cause).toBe(cause);
      expect(e.cause).toBeInstanceOf(MergeSchemaMismatchError);
    });

    it('cause is undefined when omitted', () => {
      const e = new SyncMergeError('merge failed on sync path');
      expect(e.cause).toBeUndefined();
    });
  });
});
