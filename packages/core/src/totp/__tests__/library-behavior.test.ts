// packages/core/src/totp/__tests__/library-behavior.test.ts
//
// Wave-0 characterization spike (29-01, TOTP-05). This test exercises the raw
// `otpauth` library DIRECTLY — no Cryptiq module (totp/parse.ts, totp/generate.ts
// etc.) exists yet. Its purpose is to record ACTUAL runtime facts so Plan 03's
// design is built on verified behavior, not assumptions (29-RESEARCH.md
// Assumptions Log A3/A5, Open Question #2).
//
// ============================================================================
// VERDICTS (read this before building Plan 03):
//
// (A3) `.generate({timestamp})` DOES honor an injected timestamp (not
//      Date.now()) — proven against the RFC 6238 Appendix-B T=59 vector.
//      `.remaining({timestamp})` ALSO honors the injected timestamp (proven
//      below: at T=59s with a 30s period, 1000ms remain until the T=60
//      boundary). The hand-computed arithmetic fallback
//      (`period - (Math.floor(nowMs/1000) % period)`) is NOT required —
//      `generateTotpCode` (Plan 03) can rely on `instance.remaining({timestamp})`
//      directly.
//
// (A5) `OTPAuth.Secret.fromBase32(...)` THROWS on a non-RFC-4648 alphabet
//      (digits '0'/'1'/'8'/'9' are outside the A-Z2-7 Base32 alphabet). The
//      thrown value is a plain `Error` (not a distinguishable custom subclass) —
//      `parsePastedTotp` (Plan 03) must catch broadly (`catch { ... }`, not
//      `catch (e) { if (e instanceof SomeOtpauthError) ... }`) and re-throw its
//      own typed `TotpParseError`.
//
// (Open-Q2 / D-10 fail-closed) MIXED RESULT — otpauth's fail-closed behavior
//      differs by field:
//        - `algorithm`: otpauth DOES throw (fail closed) on an unsupported
//          algorithm string, at BOTH the `TOTP` constructor
//          (`TypeError: Unknown hash algorithm: MD5`) AND `URI.parse`
//          (`TypeError: Invalid 'algorithm' parameter`). No allowlist needed
//          for algorithm — otpauth's internal @noble/hashes dispatch already
//          rejects any non-supported HMAC name.
//        - `digits`: otpauth SILENTLY ACCEPTS an out-of-range `digits` value
//          (999) at `URI.parse` time — no throw, the value is parsed and
//          stored verbatim.
//      VERDICT: Plan 03's `parsePastedTotp` does NOT need its own algorithm
//      allowlist (otpauth already fails closed there) but MUST add its own
//      explicit digits range check (e.g. 6-10) before accepting a parsed
//      result — otpauth does not fail closed on digits (D-10 GATE requirement,
//      narrower in scope than originally assumed).
// ============================================================================

import { describe, it, expect } from 'vitest';
import * as OTPAuth from 'otpauth';

// RFC 6238 Appendix B, SHA1 20-byte ASCII seed '12345678901234567890',
// Base32-encoded (RFC 4648, no padding, uppercase) — same seed used by
// Plan 03's generate.test.ts KAT table (29-RESEARCH Pattern 2).
const SHA1_SEED_BASE32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

describe('otpauth library-behavior characterization (Wave-0 spike)', () => {
  describe('A3: does TOTP honor an injected timestamp, or fall back to Date.now()?', () => {
    it('generate({timestamp: 59000}) returns the RFC 6238 Appendix-B T=59 SHA1 8-digit vector', () => {
      const totp = new OTPAuth.TOTP({
        secret: SHA1_SEED_BASE32,
        algorithm: 'SHA1',
        digits: 8,
        period: 30,
      });
      // T=59s -> counter 1 (59/30 floored). RFC 6238 Appendix B row 1.
      expect(totp.generate({ timestamp: 59000 })).toBe('94287082');
    });

    it('generate() output CHANGES when timestamp moves to the next period boundary (proves timestamp, not Date.now(), drives output)', () => {
      const totp = new OTPAuth.TOTP({
        secret: SHA1_SEED_BASE32,
        algorithm: 'SHA1',
        digits: 8,
        period: 30,
      });
      const codeAtT59 = totp.generate({ timestamp: 59000 });
      // Same period (T=59 and T=1 are both counter=1 for period=30... use a
      // clearly different counter instead: T=1111111109 is the next RFC vector).
      const codeAtNextVector = totp.generate({ timestamp: 1111111109 * 1000 });
      expect(codeAtNextVector).toBe('07081804');
      expect(codeAtNextVector).not.toBe(codeAtT59);
    });

    it('remaining({timestamp: 59000}) honors the injected timestamp: 1000ms remain until the T=60 period boundary (period=30)', () => {
      const totp = new OTPAuth.TOTP({
        secret: SHA1_SEED_BASE32,
        algorithm: 'SHA1',
        digits: 8,
        period: 30,
      });
      // T=59s is 1s before the next 30s-period boundary at T=60s (counter flips
      // from floor(59/30)=1 to floor(60/30)=2). remaining() is documented to
      // return milliseconds until that boundary.
      const remainingMs = totp.remaining({ timestamp: 59000 });
      expect(remainingMs).toBe(1000);
    });

    it('remaining() at the exact start of a period returns a full period (30000ms), confirming timestamp (not Date.now()) drives the boundary math', () => {
      const totp = new OTPAuth.TOTP({
        secret: SHA1_SEED_BASE32,
        algorithm: 'SHA1',
        digits: 8,
        period: 30,
      });
      // T=60s is exactly the start of counter=2's window (60/30=2, no remainder).
      const remainingMs = totp.remaining({ timestamp: 60_000 });
      expect(remainingMs).toBe(30_000);
    });
  });

  describe('A5: does Secret.fromBase32 throw on a non-RFC-4648 alphabet?', () => {
    it('throws on a string containing digits outside the RFC 4648 A-Z2-7 alphabet (0, 1, 8, 9)', () => {
      // '0189' -- '0','1','8','9' are all outside RFC 4648 Base32's A-Z2-7 alphabet.
      // (Note: '8' and '9' are ALSO outside RFC 4648, unlike Crockford Base32 which
      // includes a different digit subset — see the dedicated RFC4648-vs-Crockford
      // confusion-guard test (TOTP-07, SC-5) for the full alphabet contrast.)
      expect(() => OTPAuth.Secret.fromBase32('0189')).toThrow();
    });

    it('the thrown value is a plain Error (no distinguishable custom error subclass) -- callers must catch broadly', () => {
      let caught: unknown;
      try {
        OTPAuth.Secret.fromBase32('0189');
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(Error);
      // Not asserting a specific named subclass -- otpauth does not export one
      // for this failure. parsePastedTotp (Plan 03) must catch broadly (bare
      // `catch { ... }`), not attempt an `instanceof SomeOtpauthSpecificError` check.
    });

    it('does NOT throw on a valid RFC 4648 alphabet string (sanity check the negative case)', () => {
      expect(() => OTPAuth.Secret.fromBase32(SHA1_SEED_BASE32)).not.toThrow();
    });
  });

  describe('Open-Q2 / D-10: does otpauth fail closed on an out-of-spec algorithm or digits?', () => {
    it('the TOTP constructor DOES throw on an unsupported algorithm string (e.g. "MD5") -- fails closed, no allowlist needed', () => {
      expect(
        () =>
          new OTPAuth.TOTP({
            secret: SHA1_SEED_BASE32,
            algorithm: 'MD5',
            digits: 6,
            period: 30,
          }),
      ).toThrow(/unknown hash algorithm/i);
    });

    it('URI.parse DOES throw on an unsupported algorithm query param (e.g. "NOTREAL") -- fails closed, no allowlist needed', () => {
      const uri = `otpauth://totp/x?algorithm=NOTREAL&secret=${SHA1_SEED_BASE32}`;
      expect(() => OTPAuth.URI.parse(uri)).toThrow(/algorithm/i);
    });

    it('URI.parse does NOT throw on an out-of-range digits value (999) -- silently accepted and stored verbatim (digits needs its own guard)', () => {
      const uri = `otpauth://totp/x?digits=999&secret=${SHA1_SEED_BASE32}`;
      let parsed: unknown;
      expect(() => {
        parsed = OTPAuth.URI.parse(uri);
      }).not.toThrow();
      expect(parsed).toBeInstanceOf(OTPAuth.TOTP);
      expect((parsed as OTPAuth.TOTP).digits).toBe(999);
    });

    // VERDICT (recorded above the describe blocks): algorithm already fails
    // closed inside otpauth itself -- no allowlist needed for that field.
    // digits does NOT fail closed -- parsePastedTotp (Plan 03) MUST add its
    // own explicit digits range check (e.g. 6-10) before accepting a parsed
    // result. This is a narrower requirement than originally assumed by
    // 29-RESEARCH.md's Open Question #2 / Pitfall 4.
  });
});
