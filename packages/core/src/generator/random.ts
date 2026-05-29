// packages/core/src/generator/random.ts
//
// Random-string generator.
//
// Implementation contract (locked):
//   P3-05 — ≥1 char per enabled class via slot-phase + Fisher–Yates shuffle.
//           All index selection via sodium.randombytes_uniform(n) (never buf%n — bias).
//   P3-06 — AMBIGUOUS_CHARS = { l, 1, I, O, 0 } removed when avoidAmbiguous is true.
//   P3-04 — Entropy = length * log2(poolSize) (theoretical bits; not zxcvbn).
//   GEN-03 — CSPRNG only (Math.random banned project-wide; ESLint enforced).
//
// Source: CONTEXT.md P3-04/P3-05/P3-06 + 03-RESEARCH Pattern 3

import type { RandomOptions, GeneratorOptions } from './types';
import { AMBIGUOUS_CHARS } from './types';
import { getSodium } from '../crypto/sodium';
import { GeneratorError } from '../errors';
import { estimateEntropyBits } from './entropy';
import { generatePassphrase } from './passphrase';

// ---------------------------------------------------------------------------
// Character pool definitions
// ---------------------------------------------------------------------------

/** Full 26-char lowercase pool */
const FULL_LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';

/** Full 26-char uppercase pool */
const FULL_UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';

/** Full 10-char digits pool */
const FULL_DIGITS = '0123456789';

/**
 * 30-char symbols pool — no ambiguous characters exist in this set (P3-06).
 *
 * Exactly 30 chars so that SYMBOLS_COUNT in entropy.ts matches:
 * ! " # $ % & ' ( ) * + , - . / : ; < = > ? @ [ \ ] ^ _ ` { | } ~
 *
 * Count verification: !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~  (ASCII 33-47, 58-64, 91-96, 123-126)
 * That is 32 printable-ASCII non-alphanumeric. We exclude space (32) and DEL (127).
 * We use a curated 30-char set that is keyboard-reachable on standard US layout.
 */
const SYMBOLS = '!@#$%^&*()-_=+[]{}|;:,.<>?/~`\'';

// Verify at module load that SYMBOLS has the expected length (30).
// This is a compile-time guard to catch accidental edits; it runs once at
// import time and throws clearly if the count drifts from entropy.ts.
//
// We use a function-scoped check that cannot be tree-shaken by ensuring it
// is part of the module execution path (not inside a dead branch).
if (SYMBOLS.length !== 30) {
  throw new Error(
    `[random.ts] SYMBOLS pool length is ${SYMBOLS.length}, expected 30. ` +
    `Keep in sync with entropy.ts SYMBOLS_COUNT.`,
  );
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Filter the given pool string: remove chars that appear in AMBIGUOUS_CHARS.
 *
 * P3-06 is the single source of truth — the actual filter uses the imported
 * AMBIGUOUS_CHARS constant so no second hardcoded copy of the 5-char set exists
 * here.
 */
function filterAmbiguous(chars: string): string {
  return chars
    .split('')
    .filter((c) => !AMBIGUOUS_CHARS.has(c))
    .join('');
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Generate a random-string password with guaranteed class coverage (P3-05).
 *
 * Algorithm:
 *   1. Build per-class pools (applying avoidAmbiguous filter if set).
 *   2. Slot phase: pick one CSPRNG char from each enabled class.
 *   3. Fill phase: pick remaining chars from the union of all enabled classes.
 *   4. Fisher–Yates shuffle: ALL swaps use randombytes_uniform(i+1).
 *
 * @returns `{ password, entropyBits }` — theoretical information-theoretic entropy.
 * @throws GeneratorError if no character class is enabled or length < enabled classes.
 */
export async function generateRandom(
  opts: RandomOptions,
): Promise<{ password: string; entropyBits: number }> {
  const sodium = await getSodium();
  const { length, classes, avoidAmbiguous } = opts;

  // Build per-class pools, applying the ambiguous filter when requested.
  const pools: string[] = [];
  if (classes.lowercase) {
    pools.push(avoidAmbiguous ? filterAmbiguous(FULL_LOWERCASE) : FULL_LOWERCASE);
  }
  if (classes.uppercase) {
    pools.push(avoidAmbiguous ? filterAmbiguous(FULL_UPPERCASE) : FULL_UPPERCASE);
  }
  if (classes.digits) {
    pools.push(avoidAmbiguous ? filterAmbiguous(FULL_DIGITS) : FULL_DIGITS);
  }
  if (classes.symbols) {
    // Symbols pool has no ambiguous chars (P3-06) — no filter needed.
    pools.push(SYMBOLS);
  }

  if (pools.length === 0) {
    throw new GeneratorError('At least one character class must be enabled.');
  }
  if (length < pools.length) {
    throw new GeneratorError(
      `length (${length}) must be >= number of enabled classes (${pools.length}).`,
    );
  }

  // Union of all enabled (and filtered) pools.
  const union = pools.join('');

  // Slot phase — one guaranteed char per enabled class (P3-05).
  const slots: string[] = pools.map(
    (pool) => pool[sodium.randombytes_uniform(pool.length)]!,
  );

  // Fill phase — remaining positions from the union.
  for (let i = pools.length; i < length; i++) {
    slots.push(union[sodium.randombytes_uniform(union.length)]!);
  }

  // Fisher–Yates shuffle — ALL indices via randombytes_uniform (no modulo bias).
  for (let i = slots.length - 1; i > 0; i--) {
    const j = sodium.randombytes_uniform(i + 1);
    // Swap slots[i] and slots[j]
    const tmp = slots[i]!;
    slots[i] = slots[j]!;
    slots[j] = tmp;
  }

  const password = slots.join('');

  // Entropy from entropy.ts — single source of truth (no drift).
  const entropyBits = estimateEntropyBits(opts);

  return { password, entropyBits };
}

// ---------------------------------------------------------------------------
// Cross-plan dispatcher (added per 03-cross_plan_note, for Phase 5 wiring)
// ---------------------------------------------------------------------------

/**
 * Dispatcher: routes a `GeneratorOptions` value to the correct generator and
 * returns the generated secret string (password or phrase).
 *
 * Usage: `const secret = await generateFromOptions(opts)` regardless of mode.
 * Intended for callers (e.g. Phase-5 UI) that hold a `GeneratorOptions` union
 * value and need to call one function without switching on `mode` themselves.
 *
 * Note: `regenerateFromPreset` in entries/crud.ts uses direct imports (not this
 * dispatcher) — both approaches are valid; this export is the convenience path
 * for Plan 03-05 / Phase-4 UI wiring.
 */
export async function generateFromOptions(opts: GeneratorOptions): Promise<string> {
  if (opts.mode === 'random') {
    const { password } = await generateRandom(opts);
    return password;
  } else {
    const { phrase } = await generatePassphrase(opts);
    return phrase;
  }
}
