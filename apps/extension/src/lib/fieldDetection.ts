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

/**
 * Card-field detection result (CFILL-01, D-05). Elements only, never values —
 * mirrors `FieldDetectionResult`'s shape convention. `expiryMonth`/
 * `expiryYear` tolerate either `<select>` (WHATWG `cc-exp-month`/
 * `cc-exp-year`) or `<input>` markup; `ccExpCombined` is the single-field
 * `cc-exp` variant. `brand` maps `cc-type` — a direct forgiving-fill of an
 * already-stored brand string, distinct from deferred BIN/Luhn
 * auto-*detection* (D-06).
 */
export interface CardFieldDetectionResult {
  cardholderName?: HTMLInputElement | HTMLSelectElement;
  number?: HTMLInputElement | HTMLSelectElement;
  expiryMonth?: HTMLInputElement | HTMLSelectElement;
  expiryYear?: HTMLInputElement | HTMLSelectElement;
  cvv?: HTMLInputElement | HTMLSelectElement;
  ccExpCombined?: HTMLInputElement | HTMLSelectElement;
  brand?: HTMLInputElement | HTMLSelectElement;
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
 * Recursively collects every `<select>` under `root`, descending into OPEN
 * shadow roots — mirrors `collectInputs`'s shadow-DOM-aware traversal
 * exactly, for the new card-field scanner (D-02: `cc-exp-month`/
 * `cc-exp-year` may be `<select>` elements).
 */
function collectSelects(root: ParentNode): HTMLSelectElement[] {
  const selects: HTMLSelectElement[] = Array.from(root.querySelectorAll('select'));
  const descendants = root.querySelectorAll('*');
  for (const el of descendants) {
    const shadow = (el as Element).shadowRoot;
    if (shadow) {
      selects.push(...collectSelects(shadow));
    }
  }
  return selects;
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
 * D-05: extracts the field-name token for the payment/identity detection
 * tier via LAST-token extraction (`"section-x billing postal-code"` ->
 * `postal-code`), defensively stripping a trailing `webauthn` credential
 * modifier if present (WHATWG grammar: `webauthn` only ever trails
 * `username`/`current-password`/`new-password`/`one-time-code`, never a
 * `cc-*` or address/contact token — so this is correct-by-spec, not merely
 * defensive). Distinct from the existing username/password MEMBERSHIP test
 * (`USERNAME_/PASSWORD_AUTOCOMPLETE_TOKENS`) — do NOT reuse this helper for
 * login detection; the two rules solve different, non-interacting grammar
 * problems (suffix-tolerant membership vs prefix-tolerant last-token) and
 * merging them risks regressing BUG-17-01. Returns `undefined` when the
 * `autocomplete` attribute is empty/absent (a miss is safe — D-05).
 */
export function lastMeaningfulToken(el: Element): string | undefined {
  const tokens = (el.getAttribute('autocomplete') || '')
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean);
  if (tokens.length === 0) return undefined;
  const last = tokens[tokens.length - 1]!;
  return last === 'webauthn' ? tokens[tokens.length - 2] : last;
}

/** Closed allowlist (D-04/D-05, T-25-01): a token with no entry here is
 * skipped silently — never mis-routed to a semantically-different field
 * (e.g. `"section-x billing postal-code"` resolves to `postal-code`, which
 * has no entry, and is therefore skipped, never mis-routed to `billing`). */
const CARD_TOKEN_FIELD_MAP: Record<string, keyof CardFieldDetectionResult> = {
  'cc-name': 'cardholderName',
  'cc-number': 'number',
  'cc-exp-month': 'expiryMonth',
  'cc-exp-year': 'expiryYear',
  'cc-exp': 'ccExpCombined',
  'cc-csc': 'cvv',
  'cc-type': 'brand',
};

/**
 * Scans `root` for WHATWG `cc-*` payment-token fields (CFILL-01). Stateless
 * and re-queries the live DOM every call, like `scanForLoginFields`. Returns
 * element references only (never values) via a closed token->field
 * allowlist; first-match-wins per field. A miss (no `cc-*` token anywhere)
 * returns `{}` — safe, not a guess (D-03/D-05 stance).
 */
export function scanForCardFields(root: ParentNode): CardFieldDetectionResult {
  const result: CardFieldDetectionResult = {};
  const elements: (HTMLInputElement | HTMLSelectElement)[] = [...collectInputs(root), ...collectSelects(root)];

  for (const el of elements) {
    const token = lastMeaningfulToken(el);
    if (!token) continue;
    const field = CARD_TOKEN_FIELD_MAP[token];
    if (!field) continue;
    if (result[field]) continue;
    result[field] = el;
  }

  return result;
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

/**
 * Identity-field detection result (CFILL-01, D-05). Elements only, never
 * values. `EntryIdentity` is a flat shape (`name, email, phone, address` —
 * Phase 21 LOCKED); there is deliberately no `tel-country-code`/
 * `address-line2`-style sub-field here — those tokens have no corresponding
 * flat-address/flat-phone sub-field and are skipped silently at scan time
 * (D-04), never split/inferred.
 */
export interface IdentityFieldDetectionResult {
  email?: HTMLInputElement;
  tel?: HTMLInputElement;
  address?: HTMLInputElement;
}

/**
 * Scans `root` for `email`/`tel`/address identity-token fields (CFILL-01).
 * Reuses `collectInputs` + `lastMeaningfulToken` exactly like
 * `scanForCardFields`. Do NOT reuse this for login `email` fill — that is
 * `scanForLoginFields`'s separate job on a separate request, disambiguated
 * upstream by `FillRequest.kind`, never by DOM inference (Pitfall 4).
 *
 * Every address/tel SUB-token (`address-line2`, `tel-country-code`, etc.) has
 * no corresponding flat `EntryIdentity` field and is skipped silently (D-04)
 * — this is a direct consequence of the Phase-21-LOCKED flat-string shape,
 * not a detection limitation; no splitting/inference heuristic is added here
 * (that is the deferred "split address components" item).
 */
export function scanForIdentityFields(root: ParentNode): IdentityFieldDetectionResult {
  const result: IdentityFieldDetectionResult = {};
  const inputs = collectInputs(root);

  for (const el of inputs) {
    const token = lastMeaningfulToken(el);
    if (!token) continue;

    if (token === 'email') {
      if (!result.email) result.email = el;
    } else if (token === 'tel') {
      if (!result.tel) result.tel = el;
    } else if (token === 'street-address') {
      // street-address wins over address-line1 even if address-line1 was
      // seen first — prefer the more direct token (D-04 Pattern 2).
      result.address = el;
    } else if (token === 'address-line1') {
      if (!result.address) result.address = el;
    }
    // Every other token (address-line2/3, address-level1..4, postal-code,
    // country, country-name, tel-country-code, tel-national, tel-area-code,
    // tel-local*, tel-extension) has no EntryIdentity sub-field — skip
    // silently (D-04).
  }

  return result;
}
