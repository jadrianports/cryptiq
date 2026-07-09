// packages/core/src/totp/parse.ts
//
// Smart-paste discriminator + otpauth-URI/raw-Base32 parser (D-13, TOTP-01/02).
//
// `detectPasteKind` is a pure classifier over raw pasted input, mirroring
// `import/detect.ts`'s "pure discriminator" idiom. `parsePastedTotp` routes to
// the otpauth-URI branch or the raw-Base32 branch and fails closed (D-10): any
// malformed input throws a typed `TotpParseError`, never a partial `EntryTotp`.
//
// otpauth already fails closed on an unsupported `algorithm` string (both the
// `TOTP` constructor and `URI.parse` throw — verified in 29-01's characterization
// spike, packages/core/src/totp/__tests__/library-behavior.test.ts). It does NOT
// fail closed on an out-of-range `digits` value (`URI.parse` silently accepts
// `digits=999`) — this module enforces its own digits range check (D-10 GATE).
//
// This module NEVER imports `crypto/recovery.ts`. That module's Crockford Base32
// codec deliberately EXCLUDES I/L/O/U and uses a different check-char scheme —
// a DIFFERENT alphabet for a DIFFERENT problem (human-transcribed recovery keys
// vs. machine/QR-scanned TOTP secrets, RFC 4648, which INCLUDES I/L/O/U).
//
// Core purity: no @tauri-apps/*, svelte, node:fs, node:path imports. No
// console.*, no Math.random, no Date.now().

import * as OTPAuth from 'otpauth';
import type { EntryTotp } from '../entries/types';
import { TotpParseError } from '../errors';

/** RFC 4648 Base32 alphabet (A-Z, 2-7), optional trailing `=` padding. */
const RFC4648_BASE32_RE = /^[A-Z2-7]+=*$/i;

/** otpauth's own accepted digits range (D-10 GATE — otpauth does not enforce this itself). */
const MIN_DIGITS = 6;
const MAX_DIGITS = 10;

/**
 * otpauth's own accepted period range (RR-29-01 — otpauth already fails closed
 * on period=0/negatives via a thrown TypeError, but silently accepts an
 * unbounded large period such as 999999999, yielding a code that effectively
 * never rotates). This module enforces its own bound.
 */
const MIN_PERIOD = 15;
const MAX_PERIOD = 300;

const GENERIC_PARSE_ERROR_MESSAGE = "That doesn't look like an otpauth:// link or a Base32 setup key.";

export type PasteKind = 'uri' | 'base32' | 'invalid';

/**
 * Classify a pasted string as an otpauth:// URI, a raw (possibly
 * space/hyphen-grouped) RFC 4648 Base32 secret, or invalid. Pure — no parsing
 * side effects, no throw.
 */
export function detectPasteKind(raw: string): PasteKind {
  const trimmed = raw.trim();
  if (/^otpauth:\/\//i.test(trimmed)) return 'uri';
  // Common copy-paste artifact: setup keys are often displayed space/hyphen-grouped
  // (e.g. "ABCD EFGH IJKL"). Strip whitespace/hyphens before alphabet validation.
  const stripped = trimmed.replace(/[\s-]/g, '');
  if (stripped.length > 0 && RFC4648_BASE32_RE.test(stripped)) return 'base32';
  return 'invalid';
}

function assertDigitsInRange(digits: number): void {
  if (!Number.isInteger(digits) || digits < MIN_DIGITS || digits > MAX_DIGITS) {
    throw new TotpParseError(GENERIC_PARSE_ERROR_MESSAGE);
  }
}

function assertPeriodInRange(period: number): void {
  if (!Number.isInteger(period) || period < MIN_PERIOD || period > MAX_PERIOD) {
    throw new TotpParseError(GENERIC_PARSE_ERROR_MESSAGE);
  }
}

/**
 * Parse a pasted string (otpauth:// URI or raw Base32 secret) into an
 * `EntryTotp`. Fails closed (D-10): throws `TotpParseError` on any malformed
 * input, unsupported otpauth kind (D-09: totp only), or out-of-range `digits` —
 * never returns partial data.
 */
export function parsePastedTotp(raw: string): EntryTotp {
  const kind = detectPasteKind(raw);

  if (kind === 'uri') {
    let parsed: OTPAuth.TOTP;
    try {
      const result = OTPAuth.URI.parse(raw.trim());
      if (!(result instanceof OTPAuth.TOTP)) {
        // D-09 boundary: an otpauth://hotp URI (or any non-TOTP kind) is unsupported.
        throw new TotpParseError('Only otpauth://totp URIs are supported, not otpauth://hotp.');
      }
      parsed = result;
    } catch (e) {
      if (e instanceof TotpParseError) throw e;
      // otpauth throws a plain URIError/TypeError on malformed input (A5, 29-01
      // characterization spike) — catch broadly, never assume a named subclass.
      throw new TotpParseError(GENERIC_PARSE_ERROR_MESSAGE);
    }
    assertDigitsInRange(parsed.digits);
    assertPeriodInRange(parsed.period);
    return {
      secret: parsed.secret.base32,
      algorithm: parsed.algorithm,
      digits: parsed.digits,
      period: parsed.period,
      ...(parsed.label !== undefined && parsed.label !== '' ? { label: parsed.label } : {}),
      ...(parsed.issuer !== undefined && parsed.issuer !== '' ? { issuer: parsed.issuer } : {}),
    };
  }

  if (kind === 'base32') {
    const stripped = raw.trim().replace(/[\s-]/g, '').toUpperCase();
    let secret: OTPAuth.Secret;
    try {
      // otpauth throws a plain Error on a non-RFC-4648 alphabet (A5, 29-01
      // characterization spike) — catch broadly, never assume a named subclass.
      secret = OTPAuth.Secret.fromBase32(stripped);
    } catch {
      throw new TotpParseError(GENERIC_PARSE_ERROR_MESSAGE);
    }
    // Raw-Base32 paste carries NO algorithm/digits/period/label/issuer — apply
    // Cryptiq's resolved defaults (SHA1/6/30). Store the library's canonical
    // re-encoding (`secret.base32`), never the raw unnormalized paste.
    return { secret: secret.base32, algorithm: 'SHA1', digits: 6, period: 30 };
  }

  throw new TotpParseError(GENERIC_PARSE_ERROR_MESSAGE);
}
