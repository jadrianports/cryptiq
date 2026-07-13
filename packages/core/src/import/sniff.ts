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
 * Tie-break priority when two or more eligible candidates share the same
 * (lowest) variance: self-labeling (kv) candidates rank above positional ones
 * — their eligibility gate is already a much stronger structural signal than
 * mere count-consistency — then comma -> tab -> whitespace (32-CONTEXT.md's
 * own suggested priority order).
 */
const TIE_BREAK_ORDER: SniffFormat[] = ['kv-colon', 'kv-equals', 'comma', 'tab', 'whitespace'];

/** Bound sniff SCORING to the first 200 non-empty lines (Pattern 3 sampling / T-32-02). */
const SNIFF_SAMPLE_SIZE = 200;

/**
 * Anchored, character-class-bounded kv-token patterns (Pitfall 6 / ASVS V5) —
 * never `.+` before a fixed anchor. Linear-time matching.
 */
const KV_EQUALS_TOKEN = /^([^\s=]+)=(\S+)$/;
const KV_COLON_TOKEN = /^([^,:]+):\s*(.+)$/;

/** Positional field splitters — used only for SCORING (naive is fine here; Pattern 1). */
function splitComma(line: string): string[] {
  return line.split(',');
}
function splitTab(line: string): string[] {
  return line.split('\t');
}
function splitWhitespace(line: string): string[] {
  const trimmed = line.trim();
  if (trimmed.length === 0) return [''];
  return trimmed.split(/\s+/);
}

/**
 * Outer-token split for the kv-colon candidate: comma (then tab as a
 * fallback when no comma is present) — never plain whitespace, since
 * `key: value` has a CONVENTIONAL space after the colon that would collide
 * with whitespace-run outer splitting and truncate multi-word values
 * (Pitfall 3).
 */
function splitKvColonOuter(line: string): string[] {
  if (line.includes(',')) return line.split(',');
  if (line.includes('\t')) return line.split('\t');
  return [line];
}

/** Outer-token split for the kv-equals candidate: whitespace-run (no conventional space around `=`). */
function splitKvEqualsOuter(line: string): string[] {
  const trimmed = line.trim();
  if (trimmed.length === 0) return [''];
  return trimmed.split(/\s+/);
}

interface FieldCountStats {
  mean: number;
  variance: number;
  modalCount: number;
}

/** Plain reduce()-based mean/variance/modal-count arithmetic (Pattern 3) — no stats library. */
function computeStats(counts: number[]): FieldCountStats {
  if (counts.length === 0) {
    return { mean: 0, variance: 0, modalCount: 0 };
  }
  const mean = counts.reduce((a, b) => a + b, 0) / counts.length;
  const variance = counts.reduce((a, c) => a + (c - mean) ** 2, 0) / counts.length;
  const freq = new Map<number, number>();
  for (const c of counts) freq.set(c, (freq.get(c) ?? 0) + 1);
  let modalCount = counts[0] ?? 0;
  let best = 0;
  for (const [count, n] of freq) {
    if (n > best) {
      best = n;
      modalCount = count;
    }
  }
  return { mean, variance, modalCount };
}

/** Score one of the 3 positional candidates over the sampled lines. */
function scorePositional(
  sample: string[],
  splitter: (line: string) => string[],
): { fieldCount: number; variance: number; eligible: boolean } {
  const counts = sample.map((l) => splitter(l).length);
  const { mean, variance, modalCount } = computeStats(counts);
  // Pitfall 1 guard: a delimiter that never appears produces a constant field
  // count of 1 ("perfectly consistent") — only eligible when mean >= 2.
  return { fieldCount: modalCount, variance, eligible: mean >= 2 };
}

/** Score one of the 2 kv candidates over the sampled lines. */
function scoreKv(
  sample: string[],
  outerSplit: (line: string) => string[],
  tokenPattern: RegExp,
): { fieldCount: number; variance: number; eligible: boolean } {
  const matchCounts: number[] = [];
  const unionKeys = new Set<string>();
  for (const line of sample) {
    let matches = 0;
    for (const rawToken of outerSplit(line)) {
      const token = rawToken.trim();
      const m = tokenPattern.exec(token);
      if (m) {
        matches++;
        unionKeys.add(m[1]!.trim());
      }
    }
    matchCounts.push(matches);
  }
  const { variance } = computeStats(matchCounts);
  // D-02a load-bearing gate: eligible only when the MAJORITY of sampled lines
  // produce >=2 matching tokens (Pitfall 2). A single key:value pair per line
  // produces exactly 1 match/line — never >=2 — so it is structurally excluded.
  const majorityCount = sample.filter((_l, i) => (matchCounts[i] ?? 0) >= 2).length;
  const eligible = sample.length > 0 && majorityCount / sample.length >= 0.5;
  return { fieldCount: unionKeys.size, variance, eligible };
}

/**
 * Score all 5 candidates against a sample of (non-empty) lines and pick the
 * lowest-variance eligible candidate as the default.
 *
 * @param lines Raw text lines (non-empty; caller has already filtered blanks).
 */
export function sniffFormat(lines: string[]): SniffResult {
  const sample = lines.slice(0, SNIFF_SAMPLE_SIZE);

  const scored: Record<SniffFormat, { fieldCount: number; variance: number; eligible: boolean }> = {
    comma: scorePositional(sample, splitComma),
    tab: scorePositional(sample, splitTab),
    whitespace: scorePositional(sample, splitWhitespace),
    'kv-equals': scoreKv(sample, splitKvEqualsOuter, KV_EQUALS_TOKEN),
    'kv-colon': scoreKv(sample, splitKvColonOuter, KV_COLON_TOKEN),
  };

  const candidates: SniffCandidate[] = CANDIDATE_ORDER.map((format) => ({
    format,
    label: LABELS[format],
    fieldCount: scored[format].fieldCount,
    variance: scored[format].variance,
    eligible: scored[format].eligible,
  }));

  const eligible = candidates.filter((c) => c.eligible);
  let bestFormat: SniffFormat;
  if (eligible.length === 0) {
    // Zero eligible candidates (e.g. a genuinely single-column list of bare
    // passwords) — fall back to whitespace with a 1-column model. The user
    // still must complete the mandatory column-map step downstream.
    bestFormat = 'whitespace';
  } else {
    const minVariance = Math.min(...eligible.map((c) => c.variance));
    const tied = eligible.filter((c) => c.variance === minVariance);
    tied.sort((a, b) => TIE_BREAK_ORDER.indexOf(a.format) - TIE_BREAK_ORDER.indexOf(b.format));
    bestFormat = tied[0]!.format;
  }

  return { candidates, bestFormat };
}

/**
 * Reason string for a positional row whose field count doesn't match the
 * detected column model. LOCKED per 32-UI-SPEC.md's Copywriting Contract —
 * do not change this string.
 */
const RAGGED_FIELD_COUNT_REASON = "field count didn't match the detected column layout";

/** Reason string for a kv row with zero matching key<delim>value tokens. */
const RAGGED_NO_KV_MATCH_REASON = 'no key/value pairs matched the detected format';

function positionalSplitterFor(format: 'comma' | 'tab' | 'whitespace'): (line: string) => string[] {
  if (format === 'comma') return splitComma;
  if (format === 'tab') return splitTab;
  return splitWhitespace;
}

function tokenizePositional(lines: string[], format: 'comma' | 'tab' | 'whitespace'): TokenizeResult {
  const splitter = positionalSplitterFor(format);
  const fieldCounts = lines.map((l) => splitter(l).length);
  const { modalCount } = computeStats(fieldCounts);
  const columnCount = Math.max(modalCount, 1);
  const headers = Array.from({ length: columnCount }, (_v, i) => `Column ${i + 1}`);

  const dataRows: string[][] = [];
  const raggedRows: RaggedRow[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const fields = splitter(line);
    if (fields.length === columnCount) {
      dataRows.push(fields);
    } else {
      raggedRows.push({ rowIndex: i + 1, reason: RAGGED_FIELD_COUNT_REASON });
    }
  }

  return { format, headers, dataRows, raggedRows };
}

function kvOuterSplitterFor(format: 'kv-colon' | 'kv-equals'): (line: string) => string[] {
  return format === 'kv-colon' ? splitKvColonOuter : splitKvEqualsOuter;
}

function kvTokenPatternFor(format: 'kv-colon' | 'kv-equals'): RegExp {
  return format === 'kv-colon' ? KV_COLON_TOKEN : KV_EQUALS_TOKEN;
}

function tokenizeKv(lines: string[], format: 'kv-colon' | 'kv-equals'): TokenizeResult {
  const outerSplit = kvOuterSplitterFor(format);
  const tokenPattern = kvTokenPatternFor(format);

  // Per-line parsed key/value pairs (insertion order preserved per line).
  const perLinePairs: Array<Array<{ key: string; value: string }>> = [];
  // Union header set, insertion-ordered by first encounter across ALL lines
  // (D-02: key-order is NOT guaranteed stable across self-labeling lines).
  const headers: string[] = [];
  const seenHeaders = new Set<string>();

  for (const line of lines) {
    const pairs: Array<{ key: string; value: string }> = [];
    for (const rawToken of outerSplit(line)) {
      const token = rawToken.trim();
      const m = tokenPattern.exec(token);
      if (m) {
        const key = m[1]!.trim();
        const value = m[2]!;
        pairs.push({ key, value });
        if (!seenHeaders.has(key)) {
          seenHeaders.add(key);
          headers.push(key);
        }
      }
    }
    perLinePairs.push(pairs);
  }

  const dataRows: string[][] = [];
  const raggedRows: RaggedRow[] = [];
  for (let i = 0; i < lines.length; i++) {
    const pairs = perLinePairs[i]!;
    if (pairs.length === 0) {
      raggedRows.push({ rowIndex: i + 1, reason: RAGGED_NO_KV_MATCH_REASON });
      continue;
    }
    // Project BY KEY NAME into the union header order (Anti-Pattern guard —
    // never by raw per-line token position). Missing key on this line -> ''.
    const byKey = new Map(pairs.map((p) => [p.key, p.value]));
    dataRows.push(headers.map((h) => byKey.get(h) ?? ''));
  }

  return { format, headers, dataRows, raggedRows };
}

/**
 * Tokenize ALL lines (not just the sniff sample) under a chosen format.
 *
 * Positional formats synthesize `Column N` headers sized to the modal field
 * count; kv formats synthesize smart-key headers as the union of matched
 * keys, projecting each row BY KEY NAME (never by raw token position — a
 * self-labeling line's keys are not guaranteed to appear in the same order
 * on every row). Rows whose field/match count doesn't fit the chosen model
 * are routed to `raggedRows`, never padded/truncated (D-04/SC-4). Values are
 * never mutated or prefixed (IMPORT-08 verbatim carry).
 *
 * @param lines  Raw text lines (non-empty; caller has already filtered blanks).
 * @param format The format to tokenize under (from `SniffResult.bestFormat`
 *               or a user override).
 */
export function tokenize(lines: string[], format: SniffFormat): TokenizeResult {
  if (format === 'comma' || format === 'tab' || format === 'whitespace') {
    return tokenizePositional(lines, format);
  }
  return tokenizeKv(lines, format);
}
