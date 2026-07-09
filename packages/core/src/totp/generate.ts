// packages/core/src/totp/generate.ts
//
// Pure TOTP code generator (D-13/D-14, TOTP-04 data + TOTP-05).
//
// This module contains ONLY a pure function — no IO, no imports of @tauri-apps,
// svelte, node:fs, node:path, or Date.now(). The current timestamp (`nowMs`) is
// injected by the caller (apps/desktop's ticking-clock component, D-14), keeping
// the untestable wall clock out of this module — mirrors storage/lockLogic.ts's
// PID-liveness injection precedent exactly.
//
// `nowMs` is a REQUIRED positional param (never optional-with-Date.now-default);
// defaulting it would smuggle a hidden clock read into core.
//
// otpauth's `.generate({timestamp})` and `.remaining({timestamp})` both genuinely
// honor an injected timestamp (verified in 29-01's characterization spike against
// the RFC 6238 Appendix-B vectors, packages/core/src/totp/__tests__/library-behavior.test.ts,
// verdict A3) — no hand-computed fallback arithmetic is needed.

import * as OTPAuth from 'otpauth';
import type { EntryTotp } from '../entries/types';

export interface TotpCode {
  code: string;
  secondsRemaining: number;
  period: number;
}

/**
 * Generate the live TOTP code for `totp` at `nowMs`. Pure — no `Date.now()`, no
 * IO. Wraps `otpauth` (the one sanctioned crypto-rule bend for Phase 29) —
 * never a hand-assembled HMAC/truncation.
 */
export function generateTotpCode(totp: EntryTotp, nowMs: number): TotpCode {
  const instance = new OTPAuth.TOTP({
    algorithm: totp.algorithm,
    digits: totp.digits,
    period: totp.period,
    secret: totp.secret, // otpauth accepts the raw Base32 string directly — no pre-decode.
    ...(totp.issuer !== undefined ? { issuer: totp.issuer } : {}),
    ...(totp.label !== undefined ? { label: totp.label } : {}),
  });
  const code = instance.generate({ timestamp: nowMs });
  const remainingMs = instance.remaining({ timestamp: nowMs });
  const secondsRemaining = Math.ceil(remainingMs / 1000);
  return { code, secondsRemaining, period: totp.period };
}
