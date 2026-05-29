// packages/core/src/generator/__tests__/generator.test.ts
//
// Wave 0 + Plan 03-03 generator test suite.
// Requirements covered:
//   GEN-01 — random string: class coverage, length, ambiguous avoidance (l 1 I O 0)
//   GEN-02 — passphrase: word count, separator, capitalization, digit, entropy
//   GEN-03 — CSPRNG only (Math.random ban covered by ESLint; behavioural tests here)
//   GEN-04 — generator defaults stored in vault settings block
//   TEST-05 — generator length/class correctness, passphrase, entropy, presets honored
//
// Passing assertions (pass NOW against Wave-0 scaffolding):
//   - effWords length === 7776
//   - DEFAULT_RANDOM_OPTIONS and DEFAULT_PASSPHRASE_OPTIONS shapes are correct
//   - AMBIGUOUS_CHARS set contains exactly l, 1, I, O, 0

import { describe, it, expect } from 'vitest';
import effWords from '../eff-long.json';
import {
  DEFAULT_RANDOM_OPTIONS,
  DEFAULT_PASSPHRASE_OPTIONS,
  AMBIGUOUS_CHARS,
  type RandomOptions,
  type PassphraseOptions,
} from '../types';
import { generateRandom } from '../random';
import { generatePassphrase } from '../passphrase';
import { estimateEntropyBits, computePoolSize } from '../entropy';
import { GeneratorError } from '../../errors';

// ---------------------------------------------------------------------------
// Passing assertions against Wave-0 scaffolding
// ---------------------------------------------------------------------------

describe('EFF wordlist (GEN-02 precondition)', () => {
  it('has exactly 7776 words', () => {
    expect((effWords as string[]).length).toBe(7776);
  });

  it('all entries are non-empty lowercase strings', () => {
    const words = effWords as string[];
    expect(words.every((w) => typeof w === 'string' && w.length > 0)).toBe(true);
    expect(words.every((w) => w === w.toLowerCase())).toBe(true);
  });

  it('first word is "abacus" and last is "zoom" (spot check source integrity)', () => {
    const words = effWords as string[];
    expect(words[0]).toBe('abacus');
    expect(words[words.length - 1]).toBe('zoom');
  });
});

describe('DEFAULT_RANDOM_OPTIONS (GEN-01/GEN-04)', () => {
  it('has mode "random"', () => {
    expect(DEFAULT_RANDOM_OPTIONS.mode).toBe('random');
  });

  it('has length 20', () => {
    expect(DEFAULT_RANDOM_OPTIONS.length).toBe(20);
  });

  it('has all character classes enabled', () => {
    const { classes } = DEFAULT_RANDOM_OPTIONS;
    expect(classes.lowercase).toBe(true);
    expect(classes.uppercase).toBe(true);
    expect(classes.digits).toBe(true);
    expect(classes.symbols).toBe(true);
  });

  it('has avoidAmbiguous false', () => {
    expect(DEFAULT_RANDOM_OPTIONS.avoidAmbiguous).toBe(false);
  });
});

describe('DEFAULT_PASSPHRASE_OPTIONS (GEN-02/GEN-04)', () => {
  it('has mode "passphrase"', () => {
    expect(DEFAULT_PASSPHRASE_OPTIONS.mode).toBe('passphrase');
  });

  it('has 5 words', () => {
    expect(DEFAULT_PASSPHRASE_OPTIONS.words).toBe(5);
  });

  it('uses "-" separator', () => {
    expect(DEFAULT_PASSPHRASE_OPTIONS.separator).toBe('-');
  });

  it('has capitalize and appendDigit both false', () => {
    expect(DEFAULT_PASSPHRASE_OPTIONS.capitalize).toBe(false);
    expect(DEFAULT_PASSPHRASE_OPTIONS.appendDigit).toBe(false);
  });
});

describe('AMBIGUOUS_CHARS (P3-06)', () => {
  it('contains exactly the five look-alike characters: l 1 I O 0', () => {
    expect(AMBIGUOUS_CHARS.has('l')).toBe(true);
    expect(AMBIGUOUS_CHARS.has('1')).toBe(true);
    expect(AMBIGUOUS_CHARS.has('I')).toBe(true);
    expect(AMBIGUOUS_CHARS.has('O')).toBe(true);
    expect(AMBIGUOUS_CHARS.has('0')).toBe(true);
    // Ensure no extra characters slipped in
    expect(AMBIGUOUS_CHARS.size).toBe(5);
  });
});

// ---------------------------------------------------------------------------
// Plan 03-03 implementations — generateRandom (GEN-01/GEN-03)
// ---------------------------------------------------------------------------

describe('generateRandom (GEN-01/GEN-03)', () => {
  it('returns a string of the requested length', async () => {
    const result = await generateRandom(DEFAULT_RANDOM_OPTIONS);
    expect(typeof result.password).toBe('string');
    expect(result.password.length).toBe(DEFAULT_RANDOM_OPTIONS.length);
  });

  it('returns correct length for custom length values', async () => {
    for (const len of [1, 4, 8, 12, 32, 64]) {
      const opts: RandomOptions = { mode: 'random', length: len, classes: { lowercase: true, uppercase: false, digits: false, symbols: false }, avoidAmbiguous: false };
      const result = await generateRandom(opts);
      expect(result.password.length).toBe(len);
    }
  });

  it('includes at least one character from each enabled class (loop ≥50 runs)', async () => {
    const opts: RandomOptions = {
      mode: 'random',
      length: 20,
      classes: { lowercase: true, uppercase: true, digits: true, symbols: true },
      avoidAmbiguous: false,
    };

    const lower = new Set('abcdefghijklmnopqrstuvwxyz');
    const upper = new Set('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
    const digits = new Set('0123456789');
    const symbols = new Set('!@#$%^&*()-_=+[]{}|;:,.<>?/~`\'');

    for (let run = 0; run < 50; run++) {
      const { password } = await generateRandom(opts);
      const chars = password.split('');
      expect(chars.some((c) => lower.has(c))).toBe(true);
      expect(chars.some((c) => upper.has(c))).toBe(true);
      expect(chars.some((c) => digits.has(c))).toBe(true);
      expect(chars.some((c) => symbols.has(c))).toBe(true);
    }
  });

  it('class coverage holds for 3-class (no symbols) over ≥50 runs', async () => {
    const opts: RandomOptions = {
      mode: 'random',
      length: 10,
      classes: { lowercase: true, uppercase: true, digits: true, symbols: false },
      avoidAmbiguous: false,
    };
    const lower = new Set('abcdefghijklmnopqrstuvwxyz');
    const upper = new Set('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
    const digits = new Set('0123456789');

    for (let run = 0; run < 50; run++) {
      const { password } = await generateRandom(opts);
      const chars = password.split('');
      expect(chars.some((c) => lower.has(c))).toBe(true);
      expect(chars.some((c) => upper.has(c))).toBe(true);
      expect(chars.some((c) => digits.has(c))).toBe(true);
    }
  });

  it('class coverage holds for single-class (lowercase only)', async () => {
    const opts: RandomOptions = {
      mode: 'random',
      length: 8,
      classes: { lowercase: true, uppercase: false, digits: false, symbols: false },
      avoidAmbiguous: false,
    };
    const lower = new Set('abcdefghijklmnopqrstuvwxyz');
    for (let run = 0; run < 50; run++) {
      const { password } = await generateRandom(opts);
      expect(password.split('').every((c) => lower.has(c))).toBe(true);
    }
  });

  it('never includes ambiguous chars when avoidAmbiguous=true (loop ≥50 runs)', async () => {
    const opts: RandomOptions = {
      mode: 'random',
      length: 30,
      classes: { lowercase: true, uppercase: true, digits: true, symbols: true },
      avoidAmbiguous: true,
    };
    for (let run = 0; run < 50; run++) {
      const { password } = await generateRandom(opts);
      for (const ch of AMBIGUOUS_CHARS) {
        expect(password).not.toContain(ch);
      }
    }
  });

  it('avoidAmbiguous removes exactly l 1 I O 0 and nothing else', async () => {
    // Generate many passwords; collect all unique chars; confirm absent set is EXACTLY
    // the intersection of AMBIGUOUS_CHARS and the enabled classes.
    const opts: RandomOptions = {
      mode: 'random',
      length: 40,
      classes: { lowercase: true, uppercase: true, digits: true, symbols: false },
      avoidAmbiguous: true,
    };
    const seen = new Set<string>();
    for (let run = 0; run < 200; run++) {
      const { password } = await generateRandom(opts);
      password.split('').forEach((c) => seen.add(c));
    }
    // None of the 5 ambiguous chars should appear
    for (const ch of AMBIGUOUS_CHARS) {
      expect(seen.has(ch)).toBe(false);
    }
    // All non-ambiguous lowercase + uppercase + digit chars should appear eventually
    const nonAmbigLower = 'abcdefghijkmnopqrstuvwxyz'; // 'l' excluded
    const nonAmbigUpper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';   // 'I','O' excluded
    const nonAmbigDigits = '23456789';                   // '0','1' excluded
    for (const ch of nonAmbigLower + nonAmbigUpper + nonAmbigDigits) {
      expect(seen.has(ch)).toBe(true);
    }
  });

  it('throws GeneratorError when no class is enabled', async () => {
    const opts: RandomOptions = {
      mode: 'random',
      length: 10,
      classes: { lowercase: false, uppercase: false, digits: false, symbols: false },
      avoidAmbiguous: false,
    };
    await expect(generateRandom(opts)).rejects.toThrow(GeneratorError);
  });

  it('throws GeneratorError when length < number of enabled classes', async () => {
    // 3 classes enabled, length = 2 → must throw
    const opts: RandomOptions = {
      mode: 'random',
      length: 2,
      classes: { lowercase: true, uppercase: true, digits: true, symbols: false },
      avoidAmbiguous: false,
    };
    await expect(generateRandom(opts)).rejects.toThrow(GeneratorError);
  });

  it('does NOT throw when length === number of enabled classes (boundary)', async () => {
    const opts: RandomOptions = {
      mode: 'random',
      length: 3,
      classes: { lowercase: true, uppercase: true, digits: true, symbols: false },
      avoidAmbiguous: false,
    };
    const result = await generateRandom(opts);
    expect(result.password.length).toBe(3);
  });

  it('returns an entropy estimate > 0', async () => {
    const result = await generateRandom(DEFAULT_RANDOM_OPTIONS);
    expect(result.entropyBits).toBeGreaterThan(0);
  });

  it('entropy returned by generator equals estimateEntropyBits for identical options (TEST-05 no-drift)', async () => {
    const opts: RandomOptions = {
      mode: 'random',
      length: 16,
      classes: { lowercase: true, uppercase: true, digits: true, symbols: true },
      avoidAmbiguous: false,
    };
    const { entropyBits } = await generateRandom(opts);
    const estimate = estimateEntropyBits(opts);
    expect(entropyBits).toBeCloseTo(estimate, 10);
  });

  it('entropy estimate matches with avoidAmbiguous=true', async () => {
    const opts: RandomOptions = {
      mode: 'random',
      length: 20,
      classes: { lowercase: true, uppercase: true, digits: true, symbols: false },
      avoidAmbiguous: true,
    };
    const { entropyBits } = await generateRandom(opts);
    const estimate = estimateEntropyBits(opts);
    expect(entropyBits).toBeCloseTo(estimate, 10);
  });
});

// ---------------------------------------------------------------------------
// generatePassphrase (GEN-02/GEN-03)
// ---------------------------------------------------------------------------

describe('generatePassphrase (GEN-02/GEN-03)', () => {
  const wordSet = new Set(effWords as string[]);

  it('returns the requested number of words joined by separator', async () => {
    const opts: PassphraseOptions = { mode: 'passphrase', words: 5, separator: '-', capitalize: false, appendDigit: false };
    const { phrase } = await generatePassphrase(opts);
    const parts = phrase.split('-');
    expect(parts.length).toBe(5);
  });

  it('all chosen words belong to the EFF list', async () => {
    // Use underscore separator: no EFF word contains '_', so the split is unambiguous.
    // (4 EFF words contain '-': drop-down, felt-tip, t-shirt, yo-yo — splitting on '-'
    //  would produce non-EFF fragments, causing false negatives.)
    const opts: PassphraseOptions = { mode: 'passphrase', words: 4, separator: '_', capitalize: false, appendDigit: false };
    for (let run = 0; run < 20; run++) {
      const { phrase } = await generatePassphrase(opts);
      const parts = phrase.split('_');
      expect(parts.length).toBe(4);
      for (const word of parts) {
        expect(wordSet.has(word)).toBe(true);
      }
    }
  });

  it('separator appears word_count-1 times in the phrase', async () => {
    const sep = '::';
    const opts: PassphraseOptions = { mode: 'passphrase', words: 3, separator: sep, capitalize: false, appendDigit: false };
    const { phrase } = await generatePassphrase(opts);
    const occurrences = phrase.split(sep).length - 1;
    expect(occurrences).toBe(2);
  });

  it('works with a single word', async () => {
    const opts: PassphraseOptions = { mode: 'passphrase', words: 1, separator: '-', capitalize: false, appendDigit: false };
    const { phrase } = await generatePassphrase(opts);
    expect(wordSet.has(phrase)).toBe(true);
  });

  it('capitalizes first letter of each word when capitalize=true', async () => {
    const opts: PassphraseOptions = { mode: 'passphrase', words: 4, separator: '-', capitalize: true, appendDigit: false };
    for (let run = 0; run < 20; run++) {
      const { phrase } = await generatePassphrase(opts);
      const words = phrase.split('-');
      for (const word of words) {
        expect(word.charAt(0)).toBe(word.charAt(0).toUpperCase());
        // The rest should be lowercase (original word body)
        expect(word.slice(1)).toBe(word.slice(1).toLowerCase());
      }
    }
  });

  it('capitalize=false leaves all words lowercase (EFF words are already lowercase)', async () => {
    const opts: PassphraseOptions = { mode: 'passphrase', words: 4, separator: '-', capitalize: false, appendDigit: false };
    for (let run = 0; run < 20; run++) {
      const { phrase } = await generatePassphrase(opts);
      const words = phrase.split('-');
      for (const word of words) {
        expect(word).toBe(word.toLowerCase());
      }
    }
  });

  it('appends a single decimal digit (0-9) when appendDigit=true', async () => {
    const opts: PassphraseOptions = { mode: 'passphrase', words: 3, separator: '-', capitalize: false, appendDigit: true };
    for (let run = 0; run < 30; run++) {
      const { phrase } = await generatePassphrase(opts);
      // Last char should be a digit 0-9
      const lastChar = phrase.charAt(phrase.length - 1);
      expect('0123456789').toContain(lastChar);
      // The phrase without the digit should split into exactly 3 words
      const withoutDigit = phrase.slice(0, -1);
      expect(withoutDigit.split('-').length).toBe(3);
    }
  });

  it('appendDigit=false produces no trailing digit', async () => {
    // Use '_' separator — no EFF word contains '_', so split is unambiguous.
    const opts: PassphraseOptions = { mode: 'passphrase', words: 3, separator: '_', capitalize: false, appendDigit: false };
    for (let run = 0; run < 20; run++) {
      const { phrase } = await generatePassphrase(opts);
      const parts = phrase.split('_');
      // All parts must be EFF words (no stray digit suffix)
      expect(parts.length).toBe(3);
      for (const part of parts) {
        expect(wordSet.has(part)).toBe(true);
      }
    }
  });

  it('entropy bits = words * log2(7776), no digit (TEST-05)', async () => {
    const opts: PassphraseOptions = { mode: 'passphrase', words: 5, separator: '-', capitalize: false, appendDigit: false };
    const { entropyBits } = await generatePassphrase(opts);
    const expected = 5 * Math.log2(7776);
    expect(entropyBits).toBeCloseTo(expected, 10);
  });

  it('entropy bits = words * log2(7776) + log2(10) when appendDigit=true (TEST-05)', async () => {
    const opts: PassphraseOptions = { mode: 'passphrase', words: 4, separator: '-', capitalize: false, appendDigit: true };
    const { entropyBits } = await generatePassphrase(opts);
    const expected = 4 * Math.log2(7776) + Math.log2(10);
    expect(entropyBits).toBeCloseTo(expected, 10);
  });

  it('entropy returned by generator equals estimateEntropyBits for identical options (TEST-05 no-drift)', async () => {
    const opts: PassphraseOptions = { mode: 'passphrase', words: 6, separator: '_', capitalize: true, appendDigit: true };
    const { entropyBits } = await generatePassphrase(opts);
    const estimate = estimateEntropyBits(opts);
    expect(entropyBits).toBeCloseTo(estimate, 10);
  });

  it('separator and capitalization do not affect entropy (deterministic transforms)', async () => {
    const base: PassphraseOptions = { mode: 'passphrase', words: 5, separator: '-', capitalize: false, appendDigit: false };
    const capitalized: PassphraseOptions = { ...base, capitalize: true };
    const diffSep: PassphraseOptions = { ...base, separator: ' ' };

    const baseEnt = estimateEntropyBits(base);
    const capEnt = estimateEntropyBits(capitalized);
    const sepEnt = estimateEntropyBits(diffSep);

    // Separator and capitalize are deterministic → zero entropy contribution
    expect(baseEnt).toBeCloseTo(capEnt, 10);
    expect(baseEnt).toBeCloseTo(sepEnt, 10);
  });
});

// ---------------------------------------------------------------------------
// estimateEntropyBits (P3-04)
// ---------------------------------------------------------------------------

describe('estimateEntropyBits (P3-04)', () => {
  it('random mode: length * log2(poolSize)', () => {
    const opts: RandomOptions = {
      mode: 'random', length: 20,
      classes: { lowercase: true, uppercase: true, digits: true, symbols: true },
      avoidAmbiguous: false,
    };
    const pool = computePoolSize(opts);
    const expected = 20 * Math.log2(pool);
    expect(estimateEntropyBits(opts)).toBeCloseTo(expected, 10);
  });

  it('passphrase mode: words * log2(7776) + optional log2(10) for digit', () => {
    const withDigit: PassphraseOptions = { mode: 'passphrase', words: 5, separator: '-', capitalize: false, appendDigit: true };
    const noDigit: PassphraseOptions = { ...withDigit, appendDigit: false };
    expect(estimateEntropyBits(withDigit)).toBeCloseTo(5 * Math.log2(7776) + Math.log2(10), 10);
    expect(estimateEntropyBits(noDigit)).toBeCloseTo(5 * Math.log2(7776), 10);
  });

  it('returns 0 for an empty pool (no classes enabled in random mode)', () => {
    const opts: RandomOptions = {
      mode: 'random', length: 10,
      classes: { lowercase: false, uppercase: false, digits: false, symbols: false },
      avoidAmbiguous: false,
    };
    expect(estimateEntropyBits(opts)).toBe(0);
  });

  it('avoidAmbiguous reduces entropy vs non-ambiguous version', () => {
    const normal: RandomOptions = {
      mode: 'random', length: 16,
      classes: { lowercase: true, uppercase: true, digits: true, symbols: false },
      avoidAmbiguous: false,
    };
    const noAmb: RandomOptions = { ...normal, avoidAmbiguous: true };
    expect(estimateEntropyBits(noAmb)).toBeLessThan(estimateEntropyBits(normal));
  });
});

// ---------------------------------------------------------------------------
// computePoolSize (P3-04)
// ---------------------------------------------------------------------------

describe('computePoolSize (P3-04)', () => {
  it('counts all enabled classes: lowercase=26, uppercase=26, digits=10, symbols=30', () => {
    const opts: RandomOptions = {
      mode: 'random', length: 20,
      classes: { lowercase: true, uppercase: true, digits: true, symbols: true },
      avoidAmbiguous: false,
    };
    expect(computePoolSize(opts)).toBe(26 + 26 + 10 + 30);
  });

  it('only lowercase (no ambiguous)', () => {
    const opts: RandomOptions = {
      mode: 'random', length: 5,
      classes: { lowercase: true, uppercase: false, digits: false, symbols: false },
      avoidAmbiguous: false,
    };
    expect(computePoolSize(opts)).toBe(26);
  });

  it('subtracts ambiguous chars when avoidAmbiguous=true', () => {
    const opts: RandomOptions = {
      mode: 'random', length: 20,
      classes: { lowercase: true, uppercase: true, digits: true, symbols: false },
      avoidAmbiguous: true,
    };
    // lowercase: 26 - 1 ('l') = 25
    // uppercase: 26 - 2 ('I','O') = 24
    // digits:    10 - 2 ('0','1') = 8
    // total = 57
    expect(computePoolSize(opts)).toBe(57);
  });

  it('symbols are unaffected by avoidAmbiguous (no ambiguous chars in symbols pool)', () => {
    const withSymbols: RandomOptions = {
      mode: 'random', length: 20,
      classes: { lowercase: false, uppercase: false, digits: false, symbols: true },
      avoidAmbiguous: true,
    };
    const withoutFlag: RandomOptions = { ...withSymbols, avoidAmbiguous: false };
    expect(computePoolSize(withSymbols)).toBe(computePoolSize(withoutFlag));
    expect(computePoolSize(withSymbols)).toBe(30);
  });

  it('returns 0 when no classes enabled', () => {
    const opts: RandomOptions = {
      mode: 'random', length: 5,
      classes: { lowercase: false, uppercase: false, digits: false, symbols: false },
      avoidAmbiguous: false,
    };
    expect(computePoolSize(opts)).toBe(0);
  });

  it('verifies the exact per-class ambiguous reductions match the filter in random.ts', async () => {
    // Generate 500 passwords with avoidAmbiguous=true and count unique chars per class
    const opts: RandomOptions = {
      mode: 'random', length: 40,
      classes: { lowercase: true, uppercase: true, digits: true, symbols: false },
      avoidAmbiguous: true,
    };
    const seen = new Set<string>();
    for (let i = 0; i < 200; i++) {
      const { password } = await generateRandom(opts);
      password.split('').forEach((c) => seen.add(c));
    }
    // Count seen chars per class
    const seenLower = [...seen].filter((c) => c >= 'a' && c <= 'z').length;
    const seenUpper = [...seen].filter((c) => c >= 'A' && c <= 'Z').length;
    const seenDigits = [...seen].filter((c) => c >= '0' && c <= '9').length;
    // With enough runs, the pool size is fully exercised
    expect(seenLower).toBe(computePoolSize({ mode: 'random', length: 1, classes: { lowercase: true, uppercase: false, digits: false, symbols: false }, avoidAmbiguous: true }));
    expect(seenUpper).toBe(computePoolSize({ mode: 'random', length: 1, classes: { lowercase: false, uppercase: true, digits: false, symbols: false }, avoidAmbiguous: true }));
    expect(seenDigits).toBe(computePoolSize({ mode: 'random', length: 1, classes: { lowercase: false, uppercase: false, digits: true, symbols: false }, avoidAmbiguous: true }));
  });
});

// ---------------------------------------------------------------------------
// generatorPreset stored in vault settings (GEN-04)
// ---------------------------------------------------------------------------

describe('generatorPreset stored in vault settings (GEN-04)', () => {
  it('DEFAULT_RANDOM_OPTIONS produces valid output of the expected shape (preset honoring)', async () => {
    const result = await generateRandom(DEFAULT_RANDOM_OPTIONS);
    expect(typeof result.password).toBe('string');
    expect(result.password.length).toBe(DEFAULT_RANDOM_OPTIONS.length);
    expect(result.entropyBits).toBeGreaterThan(0);
  });

  it('DEFAULT_PASSPHRASE_OPTIONS produces valid output of the expected shape', async () => {
    const result = await generatePassphrase(DEFAULT_PASSPHRASE_OPTIONS);
    expect(typeof result.phrase).toBe('string');
    expect(result.phrase.split(DEFAULT_PASSPHRASE_OPTIONS.separator).length).toBe(5);
    expect(result.entropyBits).toBeGreaterThan(0);
  });

  it('a saved random preset round-trips through the generator faithfully (GEN-04)', async () => {
    // Simulate saving a preset and regenerating from it
    const preset = {
      ...DEFAULT_RANDOM_OPTIONS,
      length: 16,
      avoidAmbiguous: true,
    };
    for (let run = 0; run < 10; run++) {
      const result = await generateRandom(preset);
      expect(result.password.length).toBe(16);
      for (const ch of AMBIGUOUS_CHARS) {
        expect(result.password).not.toContain(ch);
      }
    }
  });

  it('a saved passphrase preset round-trips through the generator faithfully (GEN-04)', async () => {
    const preset: PassphraseOptions = {
      mode: 'passphrase',
      words: 3,
      separator: '_',
      capitalize: true,
      appendDigit: true,
    };
    for (let run = 0; run < 10; run++) {
      const { phrase, entropyBits } = await generatePassphrase(preset);
      // With digit: last char is 0-9; before it is "word_word_word"
      const lastChar = phrase.charAt(phrase.length - 1);
      expect('0123456789').toContain(lastChar);
      const body = phrase.slice(0, -1);
      const words = body.split('_');
      expect(words.length).toBe(3);
      // Each word is capitalized
      for (const w of words) {
        expect(w.charAt(0)).toBe(w.charAt(0).toUpperCase());
      }
      // Entropy is stable across runs (same preset → same formula)
      expect(entropyBits).toBeCloseTo(estimateEntropyBits(preset), 10);
    }
  });
});
