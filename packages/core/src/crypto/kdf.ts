// packages/core/src/crypto/kdf.ts
//
// DC-1 adaptive Argon2id calibration + key derivation (SEC-03, SEC-08, SEC-09).
//
// CALIBRATION PHILOSOPHY (DC-1, deliberate deviation noted below):
//   Hard FLOOR of 256 MiB / 3 ops (OWASP discipline — non-negotiable). NO CEILING:
//   high-end machines genuinely shoot for the skies. Geometric memory-first ramp at
//   ops=3 (256→384→512→768→1024→1536→2048→3072→4096 MiB); if still under target after
//   maxing memory, bump opslimit 4→…→20 at max memory. Settle at the first trial
//   ≥ SETTLE_MS. On OOM, STOP and keep the last successful params — never write params
//   that OOM'd on the calibrating machine.
//
//   DELIBERATE DEVIATION (DC-1, historical): an earlier ROADMAP draft cited a 512 MiB /
//   10 ops ceiling; DC-1 removed that ceiling entirely — there is NO upper cap. DC-2's
//   portabilityWarning (memLimit > 512 MiB) is the mitigation — the Phase-4 creation
//   report surfaces the disclosure + an "older machines" opt-down. Intentional, locked.
//
// DUAL-PATH OOM (Pitfall A / libsodium.js issue #235):
//   crypto_pwhash on OOM EITHER throws an Error OR, in some restricted environments,
//   returns an all-ZEROS buffer instead of throwing. We detect BOTH: every measurement
//   is wrapped in try/catch AND, after a successful return, asserted non-zero via
//   .some(b => b !== 0). A zero buffer is treated as OOM (break in calibration; throw
//   KdfResourceError in deriveKey) and is NEVER accepted as a key.
//
// PER-WRAP PARAMS (DC-3): these KdfParams are stored INSIDE each wrapped-key object
//   (NOT at the vault top level). kdf.ts only produces/consumes the params; the per-wrap
//   storage shape lands in Plan 02/03.
//
// Source: RESEARCH Pattern 2 + PITFALLS Pitfall A + CONTEXT DC-1/DC-2/DC-3.

import { getSodium } from './sodium';
import { KdfResourceError } from '../errors';

export interface KdfParams {
  algorithm: 2; // crypto_pwhash_ALG_ARGON2ID13
  opsLimit: number; // Cryptiq floor: 3
  memLimit: number; // Cryptiq floor: 268435456 (256 MiB)
  salt: Uint8Array; // 16 bytes, generated fresh per vault creation
}

export const FLOOR_OPS = 3;
export const FLOOR_MEM = 268_435_456; // 256 MiB — matches crypto_pwhash_MEMLIMIT_MODERATE
export const TARGET_MS = 1_000;
export const SETTLE_MS = 800; // "≥800ms is good enough" per DC-1

// DC-1 geometric memory-first ramp (bytes). NO Math.min / cap — the array IS the ramp,
// and the opslimit bump below has an upper loop bound only to terminate, not to cap
// security (it breaks on OOM well before then on any realistic machine).
const MEM_STEPS = [256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096].map((m) => m * 1024 * 1024);

/**
 * True if `derived` is a non-empty buffer that is NOT entirely zero. A zero-filled
 * buffer is the libsodium.js #235 restricted-environment OOM signal — never a valid key.
 */
function isNonZeroKey(derived: Uint8Array): boolean {
  return derived.length > 0 && derived.some((b) => b !== 0);
}

export async function calibrateArgon2id(): Promise<{
  params: KdfParams;
  measuredMs: number;
  portabilityWarning: boolean;
}> {
  const sodium = await getSodium();
  const dummySalt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
  const dummyPw = new TextEncoder().encode('calibration-dummy-' + Date.now());

  let bestParams: KdfParams = {
    algorithm: sodium.crypto_pwhash_ALG_ARGON2ID13 as 2,
    opsLimit: FLOOR_OPS,
    memLimit: FLOOR_MEM,
    salt: dummySalt,
  };
  let bestMs = 0;

  // Returns elapsed ms on success; THROWS on either OOM path (libsodium throw OR
  // zero-buffer). Callers catch and break the ramp, keeping the last good params.
  const measure = (ops: number, mem: number): number => {
    const t0 = performance.now();
    const derived = sodium.crypto_pwhash(
      32,
      dummyPw,
      dummySalt,
      ops,
      mem,
      sodium.crypto_pwhash_ALG_ARGON2ID13,
    );
    const elapsed = performance.now() - t0;
    if (!isNonZeroKey(derived)) {
      // Zero-buffer OOM (issue #235) — treat exactly like a thrown OOM.
      throw new Error('crypto_pwhash returned a zero-filled buffer (restricted-env OOM, #235)');
    }
    sodium.memzero(derived);
    return elapsed;
  };

  // Phase 1: grow memlimit geometrically at ops=3.
  for (const mem of MEM_STEPS) {
    let ms: number;
    try {
      ms = measure(FLOOR_OPS, mem);
    } catch {
      // OOM (thrown or zero-buffer): stop, keep last successful params.
      break;
    }
    bestParams = { ...bestParams, opsLimit: FLOOR_OPS, memLimit: mem };
    bestMs = ms;
    if (ms >= SETTLE_MS) break;
  }

  // Phase 2: memory maxed but still too fast → bump opslimit at max memory.
  if (bestMs < SETTLE_MS) {
    const maxMem = MEM_STEPS[MEM_STEPS.length - 1]!;
    for (let ops = FLOOR_OPS + 1; ops <= 20; ops++) {
      let ms: number;
      try {
        ms = measure(ops, maxMem);
      } catch {
        break; // OOM at max memory + higher ops — keep last good.
      }
      bestParams = { ...bestParams, opsLimit: ops, memLimit: maxMem };
      bestMs = ms;
      if (ms >= SETTLE_MS) break;
    }
  }

  // SEC-09: wipe the dummy salt from memory once calibration is done. (JS GC-string
  // limitations on the dummy password are documented in 02-security-design.md.)
  sodium.memzero(dummySalt);

  return {
    params: bestParams,
    measuredMs: bestMs,
    portabilityWarning: bestParams.memLimit > 512 * 1024 * 1024, // DC-2
  };
}

/**
 * Derive a `keyLen`-byte key from `password` under `params` using Argon2id. Throws
 * `KdfResourceError` on BOTH OOM paths: a thrown error from crypto_pwhash OR an
 * all-zeros buffer (#235). Fail closed — a zero buffer is never returned as a key.
 */
export async function deriveKey(
  password: Uint8Array,
  params: KdfParams,
  keyLen = 32,
): Promise<Uint8Array> {
  const sodium = await getSodium();
  let derived: Uint8Array;
  try {
    derived = sodium.crypto_pwhash(
      keyLen,
      password,
      params.salt,
      params.opsLimit,
      params.memLimit,
      sodium.crypto_pwhash_ALG_ARGON2ID13,
    );
  } catch (err) {
    throw new KdfResourceError(
      `Argon2id failed (ops=${params.opsLimit}, mem=${params.memLimit}): ${String(err)}`,
    );
  }
  if (!isNonZeroKey(derived)) {
    // Zero-buffer OOM (#235) — never accept as a key.
    throw new KdfResourceError(
      `Argon2id returned a zero-filled key (restricted-env OOM #235; ops=${params.opsLimit}, mem=${params.memLimit}).`,
    );
  }
  return derived;
}
