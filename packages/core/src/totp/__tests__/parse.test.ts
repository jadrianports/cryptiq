// packages/core/src/totp/__tests__/parse.test.ts
//
// TOTP-01/02: smart-paste discriminator + otpauth-URI/raw-Base32 parser.
// Fail-closed (D-10): malformed input throws TotpParseError, never partial data.
// Includes an RFC 4648 vs Crockford confusion-guard regression companion to
// packages/core/src/crypto/__tests__/recovery.test.ts's TOTP-07/SC-5 fixture.

import { describe, it, expect } from 'vitest';
import { detectPasteKind, parsePastedTotp } from '../parse';
import { TotpParseError } from '../../errors';

// Same seed used by generate.test.ts's RFC 6238 Appendix-B KAT table.
const SHA1_SEED_BASE32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

describe('detectPasteKind', () => {
  it('classifies an otpauth:// URI as "uri"', () => {
    expect(detectPasteKind(`otpauth://totp/Acme:alice?secret=${SHA1_SEED_BASE32}`)).toBe('uri');
  });

  it('classifies a raw Base32 secret as "base32"', () => {
    expect(detectPasteKind(SHA1_SEED_BASE32)).toBe('base32');
  });

  it('classifies a space/hyphen-grouped Base32 secret as "base32"', () => {
    expect(detectPasteKind('GEZD GNBV-GY3T QOJQ GEZD GNBV GY3T QOJQ')).toBe('base32');
  });

  it('classifies garbage as "invalid"', () => {
    expect(detectPasteKind('not a totp thing at all!!')).toBe('invalid');
  });

  it('classifies an empty string as "invalid"', () => {
    expect(detectPasteKind('   ')).toBe('invalid');
  });
});

describe('parsePastedTotp — otpauth:// URI branch', () => {
  it('parses a full otpauth://totp URI with non-default params (SHA256/8/60) + label/issuer', () => {
    const uri = `otpauth://totp/Acme:alice@example.com?secret=${SHA1_SEED_BASE32}&issuer=Acme&algorithm=SHA256&digits=8&period=60`;
    const result = parsePastedTotp(uri);
    expect(result.algorithm).toBe('SHA256');
    expect(result.digits).toBe(8);
    expect(result.period).toBe(60);
    expect(result.issuer).toBe('Acme');
    expect(result.label).toBe('alice@example.com');
  });

  it('parses a defaults-only otpauth://totp URI (no algorithm/digits/period/issuer query params; otpauth requires a non-empty label path segment)', () => {
    const uri = `otpauth://totp/Default?secret=${SHA1_SEED_BASE32}`;
    const result = parsePastedTotp(uri);
    expect(result.algorithm).toBe('SHA1');
    expect(result.digits).toBe(6);
    expect(result.period).toBe(30);
    expect(result.label).toBe('Default');
    expect(result).not.toHaveProperty('issuer');
  });

  it('throws TotpParseError on an otpauth://hotp URI (D-09: totp only)', () => {
    const uri = `otpauth://hotp/Acme:alice?secret=${SHA1_SEED_BASE32}&counter=0`;
    expect(() => parsePastedTotp(uri)).toThrow(TotpParseError);
  });

  it('throws TotpParseError on a malformed otpauth:// URI, no partial return (D-10)', () => {
    expect(() => parsePastedTotp('otpauth://totp/???not-a-valid-uri???')).toThrow(TotpParseError);
  });

  it('throws TotpParseError on an out-of-range digits value (otpauth silently accepts digits=999 — this module must not, D-10 GATE)', () => {
    const uri = `otpauth://totp/x?digits=999&secret=${SHA1_SEED_BASE32}`;
    expect(() => parsePastedTotp(uri)).toThrow(TotpParseError);
  });

  it('throws TotpParseError on an out-of-range period value (otpauth silently accepts period=999999999 — this module must not, RR-29-01)', () => {
    const uri = `otpauth://totp/x?period=999999999&secret=${SHA1_SEED_BASE32}`;
    expect(() => parsePastedTotp(uri)).toThrow(TotpParseError);
  });

  it('parses a valid non-default period=60 URI and yields period 60', () => {
    const uri = `otpauth://totp/x?period=60&secret=${SHA1_SEED_BASE32}`;
    const result = parsePastedTotp(uri);
    expect(result.period).toBe(60);
  });
});

describe('parsePastedTotp — raw Base32 branch', () => {
  it('parses a raw Base32 secret with resolved defaults SHA1/6/30 and stores the canonical secret.base32', () => {
    const result = parsePastedTotp(SHA1_SEED_BASE32);
    expect(result.algorithm).toBe('SHA1');
    expect(result.digits).toBe(6);
    expect(result.period).toBe(30);
    expect(result.secret).toBe(SHA1_SEED_BASE32);
    expect(result).not.toHaveProperty('label');
    expect(result).not.toHaveProperty('issuer');
  });

  it('parses a space/hyphen-grouped Base32 paste, stripping separators before decode', () => {
    const grouped = 'GEZD GNBV-GY3T QOJQ GEZD GNBV GY3T QOJQ';
    const result = parsePastedTotp(grouped);
    expect(result.secret).toBe(SHA1_SEED_BASE32);
  });

  it('parses an RFC 4648 secret containing I, L, O, and U successfully -- proving it does NOT route through the Crockford recovery codec (regression companion to crypto/__tests__/recovery.test.ts TOTP-07/SC-5)', () => {
    // Same fixture string used by the Crockford confusion-guard regression test:
    // valid RFC 4648 Base32 (contains I/L/O/U), which the Crockford alphabet
    // deliberately excludes and would reject.
    const rfc4648SecretWithILOU = 'JBSWY3DPEHPK3PXPILOU2FA';
    const result = parsePastedTotp(rfc4648SecretWithILOU);
    expect(result.secret).toMatch(/I/);
    expect(result.algorithm).toBe('SHA1');
  });

  it('throws TotpParseError on a garbage string (fails both uri and base32 detection)', () => {
    expect(() => parsePastedTotp('not a totp thing at all!!')).toThrow(TotpParseError);
  });

  it('throws TotpParseError on a string containing digits outside the RFC 4648 alphabet (0,1,8,9), no partial return (D-10)', () => {
    expect(() => parsePastedTotp('01890189')).toThrow(TotpParseError);
  });

});
