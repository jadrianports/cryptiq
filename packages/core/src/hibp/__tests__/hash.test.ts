// packages/core/src/hibp/__tests__/hash.test.ts
//
// SC-4: proves the SHA-1 source (@noble/hashes/legacy.js) is correct via a known
// vector (RFC 3174 "abc") and the real known-breached-password vector ("password"),
// and that output is always uppercase (D-08 precondition).

import { describe, expect, it } from 'vitest';
import { HibpLookupError } from '../../errors';
import { sha1Hex } from '../hash';

describe('HibpLookupError', () => {
  it('carries the stable code and the Rust short-code reason', () => {
    const err = new HibpLookupError('lookup failed', 'hibp_timeout');
    expect(err.code).toBe('HIBP_LOOKUP_FAILED');
    expect(err.reason).toBe('hibp_timeout');
  });
});

describe('sha1Hex', () => {
  it('returns the real SHA-1 of "password" (known-breached KAT, SC-3/SC-4)', () => {
    expect(sha1Hex('password')).toBe('5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8');
  });

  it('returns the RFC 3174 known vector for "abc" (SHA-1 correctness, SC-4)', () => {
    expect(sha1Hex('abc')).toBe('A9993E364706816ABA3E25717850C26C9CD0D89D');
  });

  it('always returns uppercase hex (D-08)', () => {
    const hex = sha1Hex('password');
    expect(hex).toHaveLength(40);
    expect(hex).toBe(hex.toUpperCase());
    expect(/[a-f]/.test(hex)).toBe(false);
  });
});
