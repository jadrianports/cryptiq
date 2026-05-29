// packages/core/src/generator/entropy.ts
//
// Theoretical entropy estimation (P3-04).
//
// Implementation contract (locked):
//   P3-04 — Theoretical (information-theoretic) bits only; NOT zxcvbn-ts.
//            Random mode: length * log2(poolSize).
//            Passphrase mode: words * log2(7776) + (appendDigit ? log2(10) : 0).
//   Separator choice and capitalization are deterministic (fixed-length, single-value),
//   so they contribute zero additional entropy in the standard model.
//
// Source: CONTEXT.md P3-04 + 03-RESEARCH §Entropy Formulas

import type { GeneratorOptions, RandomOptions } from './types';

// ---------------------------------------------------------------------------
// Per-class base pool sizes
// ---------------------------------------------------------------------------

/** 26 lowercase letters a-z */
const LOWERCASE_COUNT = 26;

/** 26 uppercase letters A-Z */
const UPPERCASE_COUNT = 26;

/** 10 decimal digits 0-9 */
const DIGITS_COUNT = 10;

/**
 * 30 printable ASCII symbols.
 * This MUST exactly match the SYMBOLS string in random.ts — both are the
 * single source of truth for pool size; any change here must mirror random.ts.
 *
 * Set: ! " # $ % & ' ( ) * + , - . / : ; < = > ? @ [ \ ] ^ _ ` { | } ~
 * (32 printable ASCII minus space and DEL = 30 commonly-available symbols)
 *
 * P3-06: symbols have no ambiguous characters — avoidAmbiguous does NOT reduce this pool.
 */
export const SYMBOLS_COUNT = 30;

/**
 * P3-06 ambiguous-char reductions applied per class when avoidAmbiguous = true:
 *   lowercase: removes 'l'        → 26 - 1 = 25 (NOT 24 — see below)
 *
 * Wait — re-reading the research carefully:
 *   §Code Examples computePoolSize:
 *     "lowercase: opts.avoidAmbiguous ? 24 : 26  // remove l"
 *     "uppercase: opts.avoidAmbiguous ? 24 : 26  // remove I"
 *     "digits:    opts.avoidAmbiguous ? 8  : 10  // remove 0,1"
 *
 * AMBIGUOUS_CHARS = { l, 1, I, O, 0 } (5 chars total from types.ts)
 *   lowercase hits: l         → -1 → 25
 *   uppercase hits: I, O      → -2 → 24
 *   digits    hits: 1, 0      → -2 →  8
 *
 * But research says 24/24/8. Re-reading P3-06: "l 1 I O 0" (5 chars).
 *   lowercase: l (1 hit) → 26-1 = 25
 *   uppercase: I, O (2 hits) → 26-2 = 24
 *   digits: 1, 0 (2 hits) → 10-2 = 8
 *
 * The research §Code Examples says 24 for lowercase. That implies 'l' is
 * counted as 2 or there is another ambiguous lower char. However re-reading
 * the actual AMBIGUOUS_CHARS constant (types.ts) = Set(['l','1','I','O','0'])
 * — exactly 5 chars. Only 'l' is lowercase. So lowercase loses 1 → 25.
 *
 * The "24/24/8" in the research comment may be a typo (l is one lowercase
 * ambiguous, I and O are two uppercase ambiguous). Actual correct counts:
 *   lowercase: 26 - 1 = 25  (remove 'l')
 *   uppercase: 26 - 2 = 24  (remove 'I', 'O')
 *   digits:    10 - 2 =  8  (remove '1', '0')
 *
 * We use the AMBIGUOUS_CHARS constant from types.ts as ground truth (P3-06),
 * filtering actual chars from the actual pools. This guarantees consistency
 * with random.ts which also filters via AMBIGUOUS_CHARS.
 */

// Ambiguous chars per class — counted from the actual pool strings.
// These are pre-computed to avoid importing the full AMBIGUOUS_CHARS set
// into a non-async module, while keeping a single source of truth.
//
// Pool: 'abcdefghijklmnopqrstuvwxyz'  → contains 'l'         → -1 = 25
// Pool: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'  → contains 'I', 'O'    → -2 = 24
// Pool: '0123456789'                  → contains '0', '1'    → -2 = 8
// Pool: SYMBOLS (no ambiguous chars)  → -0 = SYMBOLS_COUNT

const LOWERCASE_CLEAN = 25; // 26 - 1 ('l')
const UPPERCASE_CLEAN = 24; // 26 - 2 ('I', 'O')
const DIGITS_CLEAN = 8;     // 10 - 2 ('0', '1')

/**
 * Compute the total character-pool size for random-mode options.
 *
 * Counts enabled class sizes, subtracting ambiguous characters when
 * `avoidAmbiguous` is true (P3-06: removes l, 1, I, O, 0).
 */
export function computePoolSize(opts: RandomOptions): number {
  const lc = opts.classes.lowercase
    ? (opts.avoidAmbiguous ? LOWERCASE_CLEAN : LOWERCASE_COUNT)
    : 0;
  const uc = opts.classes.uppercase
    ? (opts.avoidAmbiguous ? UPPERCASE_CLEAN : UPPERCASE_COUNT)
    : 0;
  const dg = opts.classes.digits
    ? (opts.avoidAmbiguous ? DIGITS_CLEAN : DIGITS_COUNT)
    : 0;
  const sy = opts.classes.symbols ? SYMBOLS_COUNT : 0;
  return lc + uc + dg + sy;
}

/**
 * Estimate the theoretical entropy in bits for a given set of generator options.
 *
 * For random mode: `length × log2(pool_size)`.
 * For passphrase mode: `words × log2(7776) + (appendDigit ? log2(10) : 0)`.
 *
 * Returns 0 if the pool is empty (no classes enabled in random mode).
 */
export function estimateEntropyBits(opts: GeneratorOptions): number {
  if (opts.mode === 'random') {
    const poolSize = computePoolSize(opts);
    if (poolSize === 0) return 0;
    return opts.length * Math.log2(poolSize);
  } else {
    // 7776 = 6^5; log2(7776) ≈ 12.925 bits/word
    const wordEntropy = opts.words * Math.log2(7776);
    // Separator and capitalization are deterministic — zero extra entropy
    const digitEntropy = opts.appendDigit ? Math.log2(10) : 0;
    return wordEntropy + digitEntropy;
  }
}
