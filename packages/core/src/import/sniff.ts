// packages/core/src/import/sniff.ts
//
// Delimiter/format sniffing + tokenization for the .txt import front door
// (IMPORT-09/10/11).
//
// `sniffFormat` and `tokenize` are pure functions: string[] in -> structured
// result out. No IO, no side effects. Mirrors `detect.ts`'s pure-seam pattern
// (headers-in/mapper-out) one tier down: here the input is raw text LINES
// (no header row assumed) and the output is a scored candidate set plus a
// synthetic header/row projection.
//
// Core purity: no @tauri-apps/*, svelte, node:fs, node:path imports.
// No console.*, no Math.random.

/** The 5 named delimiter/format candidates this sniffer scores. */
export type SniffFormat = 'comma' | 'tab' | 'whitespace' | 'kv-colon' | 'kv-equals';

/**
 * A single scored candidate. All 5 are always returned by `sniffFormat` (D-03 —
 * the user must be able to see and pick any candidate, not just the winner).
 */
export interface SniffCandidate {
  format: SniffFormat;
  /** UI label per 32-UI-SPEC.md's Copywriting Contract. */
  label: string;
  /** Modal field count (positional candidates) or union key count (kv candidates). */
  fieldCount: number;
  /** Variance of per-line field/match counts across the sampled lines. */
  variance: number;
  /** false = this candidate's delimiter/shape doesn't meaningfully appear in the file. */
  eligible: boolean;
}

/** Result of scoring all 5 candidates against a sample of lines. */
export interface SniffResult {
  /** All 5 candidates, always returned in a fixed order. */
  candidates: SniffCandidate[];
  /** The pre-selected default — lowest-variance ELIGIBLE candidate. */
  bestFormat: SniffFormat;
}

/** A row whose field count (positional) or match count (kv) didn't fit the chosen format. */
export interface RaggedRow {
  rowIndex: number;
  reason: string;
}

/** Result of tokenizing ALL lines under a chosen format. */
export interface TokenizeResult {
  format: SniffFormat;
  /** Synthetic 'Column N' headers (positional) or smart keys (kv), union-ordered. */
  headers: string[];
  /** Only well-formed rows (field/match count consistent with `headers`). */
  dataRows: string[][];
  /** Rows excluded from `dataRows` — never silently padded/truncated/dropped (D-04/SC-4). */
  raggedRows: RaggedRow[];
}

const LABELS: Record<SniffFormat, string> = {
  comma: 'Comma',
  tab: 'Tab',
  whitespace: 'Whitespace',
  'kv-colon': 'key: value',
  'kv-equals': 'key=value',
};

const CANDIDATE_ORDER: SniffFormat[] = ['comma', 'tab', 'whitespace', 'kv-equals', 'kv-colon'];

/**
 * Score all 5 candidates against a sample of (non-empty) lines and pick the
 * lowest-variance eligible candidate as the default.
 *
 * STUB (Task 1): returns all-ineligible placeholder candidates. Real scoring
 * lands in Task 2.
 *
 * @param lines Raw text lines (non-empty; caller has already filtered blanks).
 */
export function sniffFormat(_lines: string[]): SniffResult {
  const candidates: SniffCandidate[] = CANDIDATE_ORDER.map((format) => ({
    format,
    label: LABELS[format],
    fieldCount: 0,
    variance: 0,
    eligible: false,
  }));
  return { candidates, bestFormat: 'whitespace' };
}

/**
 * Tokenize ALL lines (not just the sniff sample) under a chosen format.
 *
 * STUB (Task 1): returns an empty placeholder result. Real tokenization
 * (synthetic headers, name-based kv projection, ragged-row routing) lands
 * in Task 3.
 *
 * @param lines  Raw text lines (non-empty; caller has already filtered blanks).
 * @param format The format to tokenize under (from `SniffResult.bestFormat`
 *               or a user override).
 */
export function tokenize(_lines: string[], format: SniffFormat): TokenizeResult {
  return { format, headers: [], dataRows: [], raggedRows: [] };
}
