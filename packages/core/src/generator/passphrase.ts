// packages/core/src/generator/passphrase.ts
//
// EFF passphrase generator.
//
// Implementation contract (locked):
//   GEN-02 — Selects words from the bundled EFF long wordlist (7,776 words).
//   P3-04 — Entropy = words * log2(7776) + (appendDigit ? log2(10) : 0).
//   GEN-03 — CSPRNG only; word selection via sodium.randombytes_uniform(7776).
//
// Source: CONTEXT.md P3-04 + 03-RESEARCH Pattern 4

import type { PassphraseOptions } from './types';
import { getSodium } from '../crypto/sodium';
import { estimateEntropyBits } from './entropy';
import effWords from './eff-long.json';

// The EFF list has exactly 7776 entries (verified by the Wave-0 test suite).
const WORDLIST_SIZE = 7776;

/**
 * Generate an EFF-wordlist passphrase.
 *
 * Algorithm:
 *   1. Pick `words` word indices via `randombytes_uniform(7776)` from the bundled EFF list.
 *   2. Capitalize the first letter of each word when `capitalize` is true.
 *   3. Join words with `separator`.
 *   4. Append one `randombytes_uniform(10)` digit when `appendDigit` is true.
 *
 * Separator and capitalization are deterministic transforms — they add zero
 * entropy in the standard model (P3-04 — theoretical bits only).
 *
 * @returns `{ phrase, entropyBits }` — theoretical information-theoretic entropy.
 */
export async function generatePassphrase(
  opts: PassphraseOptions,
): Promise<{ phrase: string; entropyBits: number }> {
  const sodium = await getSodium();
  const { words, separator, capitalize, appendDigit } = opts;

  // Pick words via CSPRNG; never Math.random (ESLint-banned).
  const chosen: string[] = [];
  for (let i = 0; i < words; i++) {
    let word = (effWords as string[])[sodium.randombytes_uniform(WORDLIST_SIZE)]!;
    if (capitalize) {
      word = word.charAt(0).toUpperCase() + word.slice(1);
    }
    chosen.push(word);
  }

  let phrase = chosen.join(separator);

  // Append a single random digit when requested.
  if (appendDigit) {
    phrase += sodium.randombytes_uniform(10).toString();
  }

  // Entropy from entropy.ts — single source of truth, no drift vs generator output.
  const entropyBits = estimateEntropyBits(opts);

  return { phrase, entropyBits };
}
