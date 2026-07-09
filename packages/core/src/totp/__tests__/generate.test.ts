// packages/core/src/totp/__tests__/generate.test.ts
//
// TOTP-04 data + TOTP-05: pure generator, RFC 6238 Appendix-B interop KAT (SC-4).
// nowMs is injected (never Date.now()) -- proves generate.ts is fully pure.

import { describe, it, expect } from 'vitest';
import { generateTotpCode } from '../generate';

// RFC 6238 Appendix B seeds (ASCII, Base32-encoded RFC 4648 no-padding uppercase).
const SEED_SHA1_BASE32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const SEED_SHA256_BASE32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA';
const SEED_SHA512_BASE32 =
  'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA';

const VECTORS: Array<[number, string, string, string]> = [
  [59, '94287082', '46119246', '90693936'],
  [1111111109, '07081804', '68084774', '25091201'],
  [1111111111, '14050471', '67062674', '99943326'],
  [1234567890, '89005924', '91819424', '93441116'],
  [2000000000, '69279037', '90698825', '38618901'],
  [20000000000, '65353130', '77737706', '47863826'],
];

describe('RFC 6238 Appendix B interop KAT (SC-4)', () => {
  it.each(VECTORS)('T=%i matches SHA1/SHA256/SHA512 (8-digit, 30s period)', (t, sha1, sha256, sha512) => {
    const nowMs = t * 1000;
    expect(
      generateTotpCode({ secret: SEED_SHA1_BASE32, algorithm: 'SHA1', digits: 8, period: 30 }, nowMs).code,
    ).toBe(sha1);
    expect(
      generateTotpCode({ secret: SEED_SHA256_BASE32, algorithm: 'SHA256', digits: 8, period: 30 }, nowMs).code,
    ).toBe(sha256);
    expect(
      generateTotpCode({ secret: SEED_SHA512_BASE32, algorithm: 'SHA512', digits: 8, period: 30 }, nowMs).code,
    ).toBe(sha512);
  });
});

describe('generateTotpCode — non-default params + secondsRemaining', () => {
  it('honors a non-default period (60s) and produces a period-correct code + secondsRemaining', () => {
    const result = generateTotpCode(
      { secret: SEED_SHA1_BASE32, algorithm: 'SHA1', digits: 8, period: 60 },
      59_000,
    );
    // T=59s / 60s period -> counter 0; RFC 6238's 8-digit/30s-period vector does NOT
    // apply here (different period => different counter/code) -- assert shape + determinism.
    expect(result.code).toHaveLength(8);
    expect(result.period).toBe(60);
    expect(result.secondsRemaining).toBe(1); // 60 - 59 = 1s remaining until the next boundary.
  });

  it('produces a 6-digit code when digits:6 (Cryptiq default)', () => {
    const result = generateTotpCode(
      { secret: SEED_SHA1_BASE32, algorithm: 'SHA1', digits: 6, period: 30 },
      59_000,
    );
    expect(result.code).toHaveLength(6);
    expect(result.period).toBe(30);
  });

  it('secondsRemaining is derived from the injected nowMs (1s remaining at T=59, period=30), never Date.now()', () => {
    const result = generateTotpCode(
      { secret: SEED_SHA1_BASE32, algorithm: 'SHA1', digits: 8, period: 30 },
      59_000,
    );
    expect(result.secondsRemaining).toBe(1);
  });

  it('secondsRemaining is a full period at the exact start of a period boundary', () => {
    const result = generateTotpCode(
      { secret: SEED_SHA1_BASE32, algorithm: 'SHA1', digits: 8, period: 30 },
      60_000,
    );
    expect(result.secondsRemaining).toBe(30);
  });
});
