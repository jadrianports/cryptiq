// packages/core/src/generator/types.ts
//
// Generator options discriminated union — the SINGLE TYPE used for both:
//   1. Live generator input (passed to generateRandom / generatePassphrase)
//   2. Per-entry preset storage (`generatorPreset` field on Entry — P3-07)
//
// This single-type approach means a saved preset faithfully reproduces the exact
// configuration the user had when they set it — no translation layer needed.
//
// Source: CONTEXT.md P3-06/P3-07 + 03-RESEARCH §Generator Options Type

/** Random-string generator options. */
export type RandomOptions = {
  mode: 'random';
  /** Character count. Default 20. */
  length: number;
  /** Enabled character classes. */
  classes: {
    lowercase: boolean;
    uppercase: boolean;
    digits: boolean;
    symbols: boolean;
  };
  /**
   * When true, removes the five look-alike characters `l 1 I O 0` (P3-06).
   * The exact set is the checked-in AMBIGUOUS_CHARS constant below.
   */
  avoidAmbiguous: boolean;
};

/** EFF-passphrase generator options. */
export type PassphraseOptions = {
  mode: 'passphrase';
  /** Word count. Default 5. */
  words: number;
  /** Separator between words. Default '-'. */
  separator: string;
  /** Capitalize the first letter of each word. Default false. */
  capitalize: boolean;
  /** Append a single random digit (0-9) after the phrase. Default false. */
  appendDigit: boolean;
};

/**
 * Discriminated union used everywhere generator options appear — live generation
 * AND per-entry `generatorPreset` storage (P3-07).
 */
export type GeneratorOptions = RandomOptions | PassphraseOptions;

/**
 * P3-06 — the exact five look-alike characters the avoidAmbiguous toggle removes.
 * A checked-in constant: no silent pool reduction beyond this spec.
 */
export const AMBIGUOUS_CHARS: ReadonlySet<string> = new Set(['l', '1', 'I', 'O', '0']);

/** Default random-string options (length 20, all classes on, ambiguous allowed). */
export const DEFAULT_RANDOM_OPTIONS: RandomOptions = {
  mode: 'random',
  length: 20,
  classes: { lowercase: true, uppercase: true, digits: true, symbols: true },
  avoidAmbiguous: false,
};

/** Default passphrase options (5 words, hyphen separator, no capitalize, no digit). */
export const DEFAULT_PASSPHRASE_OPTIONS: PassphraseOptions = {
  mode: 'passphrase',
  words: 5,
  separator: '-',
  capitalize: false,
  appendDigit: false,
};
