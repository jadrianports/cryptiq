// apps/extension/src/lib/fieldDetection.ts
//
// FILL-01/02/07, D-02/D-03: pure DOM-in/result-out field detection. Trusts
// `autocomplete` WHATWG Autofill tokens as the primary, highest-confidence
// signal; falls back to a conservative heuristic (input[type=password] as
// ground truth + nearest-preceding scored username pairing) ONLY when no
// autocomplete signal exists anywhere on the scanned root (D-02). Resolves
// label association via `<label for>` -> `aria-labelledby` -> `aria-label`
// (in that priority) and recurses into OPEN shadow roots only -- closed
// shadow roots are an accepted, documented detection gap (17-RESEARCH.md
// Field Detection Ruleset #4; do not attempt to pierce them). A
// minimum-confidence threshold gates every heuristic pairing/username-only
// candidate: a miss is safe (FILL-06's popup fallback is the escape hatch),
// a wrong-field guess is not (D-02).
//
// Stateless across calls: reads only the passed `root` via live DOM queries
// every call, writes no chrome.storage/module-level state (FILL-07 / D-03 --
// no cross-page/cross-call memory; each call/each page is independently
// re-detected). No crypto, no chrome.* IO, no @cryptiq/core import
// (CLAUDE.md thin-client boundary) -- bytes/elements in, elements out.
//
// Source: 17-CONTEXT.md D-02/D-03, 17-RESEARCH.md Field Detection Ruleset.

export interface FieldDetectionResult {
  user?: HTMLInputElement;
  pass?: HTMLInputElement;
}

/** WHATWG HTML Standard "Autofill field name" tokens this module trusts
 * directly. `email` is treated as a username-equivalent signal per D-02. */
const USERNAME_AUTOCOMPLETE_TOKENS = new Set(['username', 'email']);
const PASSWORD_AUTOCOMPLETE_TOKENS = new Set(['current-password', 'new-password']);

/** Strong username/login keyword pattern (17-RESEARCH.md Field Detection
 * Ruleset #2) applied to name/id/placeholder/label text. */
const STRONG_USERNAME_PATTERN = /user(name)?|e-?mail|login|identifier/i;

const TEXT_LIKE_USERNAME_TYPES = new Set(['text', 'email']);

/**
 * Recursively collects every `<input>` under `root`, descending into OPEN
 * shadow roots (`element.shadowRoot` is non-null only for `mode:'open'`).
 * Closed shadow roots are intentionally not pierced (documented gap).
 */
function collectInputs(root: ParentNode): HTMLInputElement[] {
  const inputs: HTMLInputElement[] = Array.from(root.querySelectorAll('input'));
  const descendants = root.querySelectorAll('*');
  for (const el of descendants) {
    const shadow = (el as Element).shadowRoot;
    if (shadow) {
      inputs.push(...collectInputs(shadow));
    }
  }
  return inputs;
}

function fieldType(el: HTMLInputElement): string {
  return (el.getAttribute('type') || 'text').toLowerCase();
}

/**
 * WHATWG-correct tokenization of the `autocomplete` attribute: it is a
 * space-separated token list, so the field-name token (username / email /
 * current-password / new-password) can be preceded by section/shipping/
 * billing prefixes and followed by `webauthn` (e.g. reddit emits
 * `autocomplete="username webauthn"` for passkey conditional UI). Membership
 * checks MUST test individual tokens, never the whole attribute string.
 */
function autocompleteTokens(el: HTMLInputElement): string[] {
  return (el.getAttribute('autocomplete') || '')
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean);
}

/**
 * Resolves the associated label text for `el`, trying `<label for="id">`
 * first, then `aria-labelledby`, then `aria-label` -- in that priority
 * order, stopping at the first source that exists (17-RESEARCH.md Field
 * Detection Ruleset #4). Searches within `el`'s own root node (so label
 * association works correctly for fields inside an open shadow root, where
 * `document.getElementById`/`querySelectorAll` would not see across the
 * shadow boundary).
 */
function getLabelText(el: HTMLInputElement): string {
  const root = el.getRootNode() as ParentNode;

  if (el.id) {
    const labels = root.querySelectorAll('label');
    for (const label of labels) {
      if ((label as HTMLLabelElement).htmlFor === el.id) {
        return label.textContent ?? '';
      }
    }
  }

  const labelledBy = el.getAttribute('aria-labelledby');
  if (labelledBy && typeof (root as Document | ShadowRoot).getElementById === 'function') {
    const texts = labelledBy
      .split(/\s+/)
      .filter(Boolean)
      .map((id) => (root as Document | ShadowRoot).getElementById(id)?.textContent ?? '')
      .filter((text) => text.length > 0);
    if (texts.length > 0) return texts.join(' ');
  }

  const ariaLabel = el.getAttribute('aria-label');
  if (ariaLabel) return ariaLabel;

  return '';
}

/**
 * Confidence score for `el` as a username candidate. 0 means "no signal at
 * all" -- callers treat a 0 score as below the minimum-confidence threshold
 * and refuse to pair it (D-02 conservative: a miss is safe, a guess is not).
 */
function scoreUsernameCandidate(el: HTMLInputElement): number {
  let score = 0;

  if (autocompleteTokens(el).some((t) => USERNAME_AUTOCOMPLETE_TOKENS.has(t))) score += 3;

  const nameIdPlaceholderLabel = [
    el.getAttribute('name') ?? '',
    el.getAttribute('id') ?? '',
    el.getAttribute('placeholder') ?? '',
    getLabelText(el),
  ].join(' ');
  if (STRONG_USERNAME_PATTERN.test(nameIdPlaceholderLabel)) score += 2;

  if (fieldType(el) === 'email') score += 1;

  return score;
}

/**
 * Primary signal (D-02 step 1): trust `autocomplete` tokens directly,
 * highest-confidence tier, no further scoring needed.
 */
function findByAutocomplete(inputs: HTMLInputElement[]): FieldDetectionResult {
  let user: HTMLInputElement | undefined;
  let pass: HTMLInputElement | undefined;

  for (const el of inputs) {
    const tokens = autocompleteTokens(el);
    if (tokens.length === 0) continue;
    if (!pass && tokens.some((t) => PASSWORD_AUTOCOMPLETE_TOKENS.has(t))) pass = el;
    if (!user && tokens.some((t) => USERNAME_AUTOCOMPLETE_TOKENS.has(t))) user = el;
  }

  return { user, pass };
}

/**
 * Conservative heuristic fallback step 2: `input[type=password]` is
 * authoritative ground truth (the browser itself restricts this type). Pairs
 * the NEAREST preceding text/email input within the same `<form>` (or the
 * field's own root node if no `<form>` wraps it -- common in SPA markup),
 * scored via `scoreUsernameCandidate`; a 0 score means no pairing (D-02).
 */
function findPairedUsername(passwordInput: HTMLInputElement, allInputs: HTMLInputElement[]): HTMLInputElement | undefined {
  const container = passwordInput.closest('form') ?? passwordInput.getRootNode();
  const scoped =
    container && typeof (container as ParentNode).querySelectorAll === 'function'
      ? Array.from((container as ParentNode).querySelectorAll<HTMLInputElement>('input'))
      : allInputs;

  const passwordIndex = scoped.indexOf(passwordInput);
  for (let i = passwordIndex - 1; i >= 0; i -= 1) {
    const candidate = scoped[i]!;
    if (!TEXT_LIKE_USERNAME_TYPES.has(fieldType(candidate))) continue;
    // Nearest preceding text/email field only -- do not keep scanning
    // further back past it even if this one scores 0 (D-02: a miss here is
    // the correct, safe outcome, not a reason to guess an earlier field).
    return scoreUsernameCandidate(candidate) > 0 ? candidate : undefined;
  }

  return undefined;
}

/**
 * D-02 step 3: a username-only page is a materially higher false-positive
 * risk than a password-anchored form -- require an `autocomplete` token OR
 * an exact `name`/`id` keyword match, AND the presence of a `<form>` or a
 * submit control, never a bare unlabeled text input.
 */
function hasSubmitControl(scope: ParentNode): boolean {
  return scope.querySelector('button[type="submit"], input[type="submit"], button:not([type])') !== null;
}

function findUsernameOnlyCandidate(inputs: HTMLInputElement[]): FieldDetectionResult {
  for (const el of inputs) {
    if (!TEXT_LIKE_USERNAME_TYPES.has(fieldType(el))) continue;

    const hasAutocompleteSignal = autocompleteTokens(el).some((t) => USERNAME_AUTOCOMPLETE_TOKENS.has(t));

    const nameOrId = `${el.getAttribute('name') ?? ''} ${el.getAttribute('id') ?? ''}`;
    const hasExactKeyword = STRONG_USERNAME_PATTERN.test(nameOrId);

    const form = el.closest('form');
    const scope = form ?? (el.getRootNode() as ParentNode);
    const hasFormContext = Boolean(form) || hasSubmitControl(scope);

    if ((hasAutocompleteSignal || hasExactKeyword) && hasFormContext) {
      return { user: el };
    }
  }

  return {};
}

/**
 * D-02 step 2 entry point: `input[type=password]` ground truth first; if
 * none exists, fall back to the stricter username-only-page bar (step 3).
 */
function findHeuristic(inputs: HTMLInputElement[]): FieldDetectionResult {
  const passwordInput = inputs.find((el) => fieldType(el) === 'password');
  if (passwordInput) {
    return { user: findPairedUsername(passwordInput, inputs), pass: passwordInput };
  }
  return findUsernameOnlyCandidate(inputs);
}

/**
 * Scan `root` for a username/password field pair. Trusts `autocomplete`
 * tokens directly when ANY are present anywhere on the page (D-02 step 1);
 * otherwise falls back to the conservative heuristic (steps 2-5). Returns an
 * empty result (`{}`) when nothing clears the minimum-confidence bar --
 * never a low-confidence guess (FILL-06's popup fallback is the deliberate
 * escape hatch for a genuine miss).
 *
 * Stateless: every call re-queries the live DOM under `root` fresh -- no
 * caching, no module-level state, safe to call repeatedly (FILL-02 re-scan
 * basis) and independently across unrelated roots/pages (FILL-07 / D-03).
 */
export function scanForLoginFields(root: ParentNode): FieldDetectionResult {
  const inputs = collectInputs(root);

  const byAutocomplete = findByAutocomplete(inputs);

  // Both halves via autocomplete tokens — highest-confidence tier, done.
  if (byAutocomplete.user && byAutocomplete.pass) {
    return byAutocomplete;
  }

  // No autocomplete signal anywhere — full conservative heuristic (steps 2-5).
  if (!byAutocomplete.user && !byAutocomplete.pass) {
    return findHeuristic(inputs);
  }

  // BUG-17-01: mixed-signal form — autocomplete resolved exactly ONE half
  // (e.g. nexusmods.com puts autocomplete="email" on the username but nothing
  // on the <input type=password>). Do NOT short-circuit to the half-pair;
  // complete the missing half via the same conservative heuristic
  // (input[type=password] ground truth for a missing pass, nearest-scored
  // paired username for a missing user), preferring the high-confidence
  // autocomplete field for the half it already resolved. `??` keeps the
  // autocomplete match authoritative; the heuristic only supplies the gap, so
  // a genuine heuristic miss still leaves that half undefined (FILL-06 fallback).
  const heuristic = findHeuristic(inputs);
  return {
    user: byAutocomplete.user ?? heuristic.user,
    pass: byAutocomplete.pass ?? heuristic.pass,
  };
}
