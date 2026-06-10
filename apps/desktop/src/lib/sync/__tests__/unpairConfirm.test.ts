// apps/desktop/src/lib/sync/__tests__/unpairConfirm.test.ts
//
// Wave-0 node test: UI-16 unpair-confirm toggle reducer.
// Pins the single-row invariant, pure-function (no mutation) contract,
// and the open/close/isConfirming predicate behaviors.
//
// Environment: node (vitest.config.ts — no browser provider invoked).

import { describe, it, expect } from 'vitest';
import {
  openUnpairConfirm,
  closeUnpairConfirm,
  isUnpairConfirming,
} from '../unpairConfirm';
import type { UnpairConfirmState } from '../unpairConfirm';

describe('unpairConfirm — UI-16 inline unpair confirm toggle reducer', () => {
  describe('openUnpairConfirm', () => {
    it('after openUnpairConfirm(s, "dev-a"), isUnpairConfirming(result, "dev-a") is true', () => {
      const s: UnpairConfirmState = null;
      const result = openUnpairConfirm(s, 'dev-a');
      expect(isUnpairConfirming(result, 'dev-a')).toBe(true);
    });

    it('after openUnpairConfirm(s, "dev-a"), isUnpairConfirming(result, "dev-b") is false (single-row invariant)', () => {
      const s: UnpairConfirmState = null;
      const result = openUnpairConfirm(s, 'dev-a');
      expect(isUnpairConfirming(result, 'dev-b')).toBe(false);
    });
  });

  describe('single-row invariant: opening a different row replaces the prior pending row', () => {
    it('opening "dev-b" on a state where "dev-a" is open flips "dev-a" to false and "dev-b" to true', () => {
      const s: UnpairConfirmState = null;
      const withDevA = openUnpairConfirm(s, 'dev-a');
      expect(isUnpairConfirming(withDevA, 'dev-a')).toBe(true);

      const withDevB = openUnpairConfirm(withDevA, 'dev-b');
      expect(isUnpairConfirming(withDevB, 'dev-a')).toBe(false);
      expect(isUnpairConfirming(withDevB, 'dev-b')).toBe(true);
    });
  });

  describe('closeUnpairConfirm', () => {
    it('closeUnpairConfirm(result) yields false for all ids', () => {
      const withDevA = openUnpairConfirm(null, 'dev-a');
      const closed = closeUnpairConfirm(withDevA);
      expect(isUnpairConfirming(closed, 'dev-a')).toBe(false);
      expect(isUnpairConfirming(closed, 'dev-b')).toBe(false);
      expect(isUnpairConfirming(closed, 'dev-c')).toBe(false);
    });

    it('closeUnpairConfirm(null) is a no-op (safe to call when nothing is open)', () => {
      const closed = closeUnpairConfirm(null);
      expect(closed).toBeNull();
      expect(isUnpairConfirming(closed, 'dev-a')).toBe(false);
    });
  });

  describe('pure function contract: input state is not mutated', () => {
    it('openUnpairConfirm does not mutate the input state (returns a new value)', () => {
      const original: UnpairConfirmState = null;
      const result = openUnpairConfirm(original, 'dev-a');
      // original must still be null
      expect(original).toBeNull();
      expect(result).toBe('dev-a');
      // They are different values
      expect(result).not.toBe(original);
    });

    it('closeUnpairConfirm does not mutate the input state', () => {
      const original: UnpairConfirmState = 'dev-a';
      const result = closeUnpairConfirm(original);
      expect(original).toBe('dev-a');
      expect(result).toBeNull();
    });
  });

  describe('isUnpairConfirming predicate', () => {
    it('returns false when state is null for any deviceId', () => {
      expect(isUnpairConfirming(null, 'dev-a')).toBe(false);
      expect(isUnpairConfirming(null, '')).toBe(false);
    });

    it('returns true only for the exact matching deviceId', () => {
      const state: UnpairConfirmState = 'dev-a';
      expect(isUnpairConfirming(state, 'dev-a')).toBe(true);
      expect(isUnpairConfirming(state, 'dev-A')).toBe(false); // case-sensitive
      expect(isUnpairConfirming(state, 'dev-b')).toBe(false);
    });
  });
});
