// packages/core/src/hibp/__tests__/kanon.test.ts
//
// SC-3 GATE: proves the split + case-insensitive suffix match against a REAL
// known-breached password's SHA-1, including the case-mismatch guard (a naive
// case-sensitive implementation must FAIL the lowercase-local-suffix test).
// Also proves the D-04 fail-closed orchestrator contract via a fake injected
// `invoke` (no network).

import { describe, expect, it, vi } from 'vitest';
import { HibpLookupError } from '../../errors';
import { lookupHibpRange } from '../index';
import { matchesSuffix, splitPrefixSuffix } from '../kanon';

const PASSWORD_SHA1 = '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8';
const PASSWORD_SUFFIX = '1E4C9B93F3F0682250B6CF8331B7EE68FD8';

describe('splitPrefixSuffix', () => {
  it('splits a 40-char SHA-1 hex digest into 5-char prefix + 35-char suffix', () => {
    expect(splitPrefixSuffix(PASSWORD_SHA1)).toEqual({
      prefix: '5BAA6',
      suffix: PASSWORD_SUFFIX,
    });
  });
});

describe('matchesSuffix (SC-3 GATE)', () => {
  it('matches the real known-breached "password" suffix against an uppercase response line', () => {
    const lines = [`${PASSWORD_SUFFIX}:12345`];
    expect(matchesSuffix(lines, PASSWORD_SUFFIX)).toBe(true);
  });

  it('still matches when the LOCAL suffix is passed lowercase (case-mismatch guard)', () => {
    const lines = [`${PASSWORD_SUFFIX}:12345`];
    expect(matchesSuffix(lines, PASSWORD_SUFFIX.toLowerCase())).toBe(true);
  });

  it('returns false when the suffix is absent from the lines', () => {
    const lines = ['0000000000000000000000000000000000:1', 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:2'];
    expect(matchesSuffix(lines, PASSWORD_SUFFIX)).toBe(false);
  });

  it('discards a count-0 HIBP Add-Padding fabricated record (T-30-PAD)', () => {
    const lines = [`${PASSWORD_SUFFIX}:0`];
    expect(matchesSuffix(lines, PASSWORD_SUFFIX)).toBe(false);
  });

  it('still matches the real breached "password" KAT with a genuine positive count', () => {
    const lines = [`${PASSWORD_SUFFIX}:52372427`];
    expect(matchesSuffix(lines, PASSWORD_SUFFIX)).toBe(true);
  });

  it('fails closed when the line has no COUNT field at all (no colon)', () => {
    const lines = [PASSWORD_SUFFIX];
    expect(matchesSuffix(lines, PASSWORD_SUFFIX)).toBe(false);
  });

  it('fails closed when COUNT is non-numeric', () => {
    const lines = [`${PASSWORD_SUFFIX}:notanumber`];
    expect(matchesSuffix(lines, PASSWORD_SUFFIX)).toBe(false);
  });
});

describe('lookupHibpRange (fail-closed orchestrator, D-04/D-07)', () => {
  it('throws HibpLookupError when the injected invoke rejects (never resolves false)', async () => {
    const fakeInvoke = vi.fn().mockRejectedValue(new Error('hibp_timeout'));
    await expect(lookupHibpRange('password', fakeInvoke)).rejects.toBeInstanceOf(HibpLookupError);
  });

  it('resolves true when the response body contains the matching suffix', async () => {
    const fakeInvoke = vi.fn().mockResolvedValue(`AAAA:1\r\n${PASSWORD_SUFFIX}:12345\r\nBBBB:2`);
    await expect(lookupHibpRange('password', fakeInvoke)).resolves.toBe(true);
    expect(fakeInvoke).toHaveBeenCalledWith('hibp_range_lookup', { prefix: '5BAA6' });
  });

  it('resolves false when the response body does not contain the suffix', async () => {
    const fakeInvoke = vi.fn().mockResolvedValue('AAAA:1\r\nBBBB:2');
    await expect(lookupHibpRange('password', fakeInvoke)).resolves.toBe(false);
  });
});
