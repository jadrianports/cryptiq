// apps/desktop/src/lib/bridge/__tests__/extensionUnpairConfirm.test.ts
//
// Wave-0 node test: BRIDGE-09 revoke-confirm toggle reducer.
// Verbatim-renamed test mirror of sync/__tests__/unpairConfirm.test.ts — pins the
// single-row invariant, pure-function (no mutation) contract, and the
// open/close/isConfirming predicate behaviors for the Browser Extensions domain.
//
// Environment: node (vitest.config.ts — no browser provider invoked).

import { describe, it, expect } from 'vitest';
import {
  openExtensionRevokeConfirm,
  closeExtensionRevokeConfirm,
  isExtensionRevokeConfirming,
} from '../extensionUnpairConfirm';
import type { ExtensionRevokeConfirmState } from '../extensionUnpairConfirm';

describe('extensionUnpairConfirm — BRIDGE-09 inline revoke confirm toggle reducer', () => {
  describe('openExtensionRevokeConfirm', () => {
    it('after openExtensionRevokeConfirm(s, "client-a"), isExtensionRevokeConfirming(result, "client-a") is true', () => {
      const s: ExtensionRevokeConfirmState = null;
      const result = openExtensionRevokeConfirm(s, 'client-a');
      expect(isExtensionRevokeConfirming(result, 'client-a')).toBe(true);
    });

    it('after openExtensionRevokeConfirm(s, "client-a"), isExtensionRevokeConfirming(result, "client-b") is false (single-row invariant)', () => {
      const s: ExtensionRevokeConfirmState = null;
      const result = openExtensionRevokeConfirm(s, 'client-a');
      expect(isExtensionRevokeConfirming(result, 'client-b')).toBe(false);
    });
  });

  describe('single-row invariant: opening a different row replaces the prior pending row', () => {
    it('opening "client-b" on a state where "client-a" is open flips "client-a" to false and "client-b" to true', () => {
      const s: ExtensionRevokeConfirmState = null;
      const withClientA = openExtensionRevokeConfirm(s, 'client-a');
      expect(isExtensionRevokeConfirming(withClientA, 'client-a')).toBe(true);

      const withClientB = openExtensionRevokeConfirm(withClientA, 'client-b');
      expect(isExtensionRevokeConfirming(withClientB, 'client-a')).toBe(false);
      expect(isExtensionRevokeConfirming(withClientB, 'client-b')).toBe(true);
    });
  });

  describe('closeExtensionRevokeConfirm', () => {
    it('closeExtensionRevokeConfirm(result) yields false for all ids', () => {
      const withClientA = openExtensionRevokeConfirm(null, 'client-a');
      const closed = closeExtensionRevokeConfirm(withClientA);
      expect(isExtensionRevokeConfirming(closed, 'client-a')).toBe(false);
      expect(isExtensionRevokeConfirming(closed, 'client-b')).toBe(false);
      expect(isExtensionRevokeConfirming(closed, 'client-c')).toBe(false);
    });

    it('closeExtensionRevokeConfirm(null) is a no-op (safe to call when nothing is open)', () => {
      const closed = closeExtensionRevokeConfirm(null);
      expect(closed).toBeNull();
      expect(isExtensionRevokeConfirming(closed, 'client-a')).toBe(false);
    });
  });

  describe('pure function contract: input state is not mutated', () => {
    it('openExtensionRevokeConfirm does not mutate the input state (returns a new value)', () => {
      const original: ExtensionRevokeConfirmState = null;
      const result = openExtensionRevokeConfirm(original, 'client-a');
      expect(original).toBeNull();
      expect(result).toBe('client-a');
      expect(result).not.toBe(original);
    });

    it('closeExtensionRevokeConfirm does not mutate the input state', () => {
      const original: ExtensionRevokeConfirmState = 'client-a';
      const result = closeExtensionRevokeConfirm(original);
      expect(original).toBe('client-a');
      expect(result).toBeNull();
    });
  });

  describe('isExtensionRevokeConfirming predicate', () => {
    it('returns false when state is null for any clientId', () => {
      expect(isExtensionRevokeConfirming(null, 'client-a')).toBe(false);
      expect(isExtensionRevokeConfirming(null, '')).toBe(false);
    });

    it('returns true only for the exact matching clientId', () => {
      const state: ExtensionRevokeConfirmState = 'client-a';
      expect(isExtensionRevokeConfirming(state, 'client-a')).toBe(true);
      expect(isExtensionRevokeConfirming(state, 'client-A')).toBe(false); // case-sensitive
      expect(isExtensionRevokeConfirming(state, 'client-b')).toBe(false);
    });
  });
});
