// apps/extension/src/lib/domFill.ts
//
// FILL-04: the only DOM-write primitive in the extension. Sets a field's
// value via the element's NATIVE property setter (bypassing any per-
// instance `value` setter a framework -- React/Vue/Svelte -- has installed
// to intercept a plain `element.value = x` assignment) then dispatches real
// `input`/`change` events so framework-controlled forms observe the change
// via DOM-level event bubbling/delegation, exactly the way they'd observe a
// real keystroke. NEVER submits the form under any circumstance -- no
// `.submit()`/`.requestSubmit()` call and no synthetic 'submit' event
// anywhere in this module, under any code path (17-CONTEXT.md D-01: click-
// to-fill, never auto-submit).
//
// Pure DOM write: no crypto, no chrome.* IO, no @cryptiq/core import
// (CLAUDE.md thin-client boundary) -- element + value in, DOM mutated +
// events dispatched, nothing returned.
//
// Source: 17-RESEARCH.md "DOM Fill Technique" (setNativeValue/fillField,
// verbatim), 17-CONTEXT.md D-01.

/**
 * Resolves and invokes the native `value` property setter found on
 * `element`'s OWN prototype (or, defensively, `HTMLInputElement.prototype`
 * itself), bypassing any per-instance descriptor a framework has redefined
 * directly on `element` to intercept plain assignment.
 */
function setNativeValue(element: HTMLInputElement, value: string): void {
  const proto = Object.getPrototypeOf(element) as HTMLInputElement;
  const descriptor =
    Object.getOwnPropertyDescriptor(proto, 'value') ?? Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
  descriptor?.set?.call(element, value);
}

/**
 * Fill `element` with `value` and notify any framework listening at the DOM
 * event layer. This is the ONLY function in the extension that writes into
 * page DOM (FILL-04) -- every caller (fill.content.ts's cryptiq-fill
 * handler) must route through here, never assign `.value` directly.
 */
export function fillField(element: HTMLInputElement, value: string): void {
  setNativeValue(element, value);
  // bubbles:true so a listener on a parent form/container (common in React)
  // observes the change via event delegation, matching what a real keypress
  // would dispatch.
  element.dispatchEvent(new Event('input', { bubbles: true }));
  element.dispatchEvent(new Event('change', { bubbles: true }));
  // NEVER: element.form?.submit() / element.form?.requestSubmit() / a
  // 'submit' event. FILL-04 is explicit: click-to-fill, never auto-submit,
  // under any circumstance.
}

// ---------------------------------------------------------------------------
// CFILL-02: <select>-aware writing (card-expiry month/year selects).
//
// Setting `.value` on a <select> fires NO event on its own, and silently
// no-ops (selectedIndex left at -1) when no <option> matches the assigned
// value -- neither a thrown error nor any other observable signal. This is
// the D-03 fail-safe surface: fillSelectField reads `element.value` back
// after the native-setter write and treats a mismatch as "nothing matched",
// skipping (never forcing a wrong/non-matching value).
// Source: 25-RESEARCH.md Pattern 3, Pitfall 3.
// ---------------------------------------------------------------------------

/**
 * Resolves and invokes the native `value` property setter found on
 * `element`'s OWN prototype (or, defensively, `HTMLSelectElement.prototype`
 * itself) -- the <select> sibling of `setNativeValue` above.
 */
function setNativeSelectValue(element: HTMLSelectElement, value: string): void {
  const proto = Object.getPrototypeOf(element) as HTMLSelectElement;
  const descriptor =
    Object.getOwnPropertyDescriptor(proto, 'value') ?? Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value');
  descriptor?.set?.call(element, value);
}

const MONTH_NAME_MAP: ReadonlyArray<{ num: string; names: readonly string[] }> = [
  { num: '01', names: ['january', 'jan'] },
  { num: '02', names: ['february', 'feb'] },
  { num: '03', names: ['march', 'mar'] },
  { num: '04', names: ['april', 'apr'] },
  { num: '05', names: ['may'] },
  { num: '06', names: ['june', 'jun'] },
  { num: '07', names: ['july', 'jul'] },
  { num: '08', names: ['august', 'aug'] },
  { num: '09', names: ['september', 'sep', 'sept'] },
  { num: '10', names: ['october', 'oct'] },
  { num: '11', names: ['november', 'nov'] },
  { num: '12', names: ['december', 'dec'] },
];

function numericCandidates(value: string): string[] {
  const trimmed = value.trim();
  if (!/^\d+$/.test(trimmed)) return [trimmed];
  const candidates = new Set<string>([trimmed]);
  const asInt = String(Number.parseInt(trimmed, 10));
  candidates.add(asInt);
  candidates.add(asInt.padStart(2, '0'));
  if (trimmed.length === 2) {
    candidates.add(`20${trimmed}`);
  } else if (trimmed.length === 4) {
    candidates.add(trimmed.slice(2));
  }
  return Array.from(candidates);
}

function monthNameCandidates(value: string): string[] {
  const trimmed = value.trim().padStart(2, '0');
  const entry = MONTH_NAME_MAP.find((m) => m.num === trimmed);
  return entry ? [...entry.names] : [];
}

/**
 * Walks `select.options` applying the D-03 fail-safe heuristic ladder
 * (verbatim -> numeric zero-pad/unpad -> 2/4-digit year -> month-name map),
 * comparing each candidate against BOTH an option's `value` AND its trimmed
 * `textContent`. Returns the matching option's `value`, or `undefined` when
 * nothing confidently matches -- detection is pure/read-only, same
 * discipline as `fieldDetection.ts`'s "a miss is safe, a guess is not".
 */
export function resolveSelectOption(select: HTMLSelectElement, intended: string): string | undefined {
  const candidates = new Set<string>([intended.trim(), ...numericCandidates(intended), ...monthNameCandidates(intended)]);

  for (const option of Array.from(select.options)) {
    const optionValue = option.value.trim().toLowerCase();
    const optionText = (option.textContent ?? '').trim().toLowerCase();
    for (const candidate of candidates) {
      const normalized = candidate.trim().toLowerCase();
      if (normalized.length === 0) continue;
      if (optionValue === normalized || optionText === normalized) {
        return option.value;
      }
    }
  }
  return undefined;
}

export interface FillSelectResult {
  filled: boolean;
}

/**
 * Writes a matched <option> value into `select` via the native-setter
 * bypass, dispatches bubbling `input` + `change` events, and reads back
 * `element.value` to confirm the write took. If `resolveSelectOption` finds
 * no confident match, writes NOTHING and returns `{ filled: false }` --
 * D-03's safe-skip outcome, never a forced/wrong value.
 * NEVER: element.form?.submit() / element.form?.requestSubmit() / a
 * 'submit' event -- same never-auto-submit discipline as `fillField`.
 */
export function fillSelectField(element: HTMLSelectElement, value: string): FillSelectResult {
  const resolved = resolveSelectOption(element, value);
  if (resolved === undefined) {
    return { filled: false };
  }
  setNativeSelectValue(element, resolved);
  element.dispatchEvent(new Event('input', { bubbles: true }));
  element.dispatchEvent(new Event('change', { bubbles: true }));
  // Read-back fail-safe (Pitfall 3): a crafted/rebuilt option set could
  // still leave selectedIndex at -1 despite resolveSelectOption's earlier
  // match (e.g. options mutated between resolve and write) -- confirm.
  if (element.value !== resolved) {
    return { filled: false };
  }
  // NEVER: element.form?.submit() / element.form?.requestSubmit() / a
  // 'submit' event.
  return { filled: true };
}

// ---------------------------------------------------------------------------
// CFILL-03: per-field visibility gate. NET-NEW control -- no prior
// visibility guard exists anywhere in this codebase. Write-time gate, run
// immediately before every card/identity write, not part of detection
// (detection stays pure/side-effect-free per fieldDetection.ts's own
// convention). Guards against a malicious page placing a hidden decoy
// field to harvest an auto-filled secret (T-25-04).
//
// MUST use getComputedStyle/checkVisibility only -- NEVER offsetWidth/
// offsetHeight/offsetParent/getClientRects. happy-dom (this project's test
// environment) hardcodes those layout-geometry properties to 0/empty
// regardless of actual CSS state, which would make every test fixture
// report "hidden" and make this control untestable.
// Source: 25-RESEARCH.md Pattern 4, Pitfall 1.
// ---------------------------------------------------------------------------

/**
 * Returns false if `el` (or any ancestor) is display:none, visibility:hidden,
 * or opacity:0. Prefers the native `Element.checkVisibility()` (Chrome 98+;
 * this extension is Chrome/MV3-only) and falls back to a `getComputedStyle`
 * ancestor-walk when unavailable (e.g. under happy-dom in tests).
 */
export function isFieldVisible(el: Element): boolean {
  const withCheckVisibility = el as Element & { checkVisibility?: (opts?: object) => boolean };
  if (typeof withCheckVisibility.checkVisibility === 'function') {
    return withCheckVisibility.checkVisibility({
      opacityProperty: true,
      visibilityProperty: true,
    });
  }
  let node: Element | null = el;
  while (node) {
    const style = getComputedStyle(node);
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
      return false;
    }
    node = node.parentElement;
  }
  return true;
}

// ---------------------------------------------------------------------------
// D-02: combined single `cc-exp` text field formatting. Routes through the
// existing text `fillField` path (no <select> to match against, so this is
// a formatting judgment call within the D-03 fail-safe boundary, not a hard
// match/no-match gate -- Claude's Discretion per 25-CONTEXT.md).
// ---------------------------------------------------------------------------

/**
 * Formats a stored month/year pair for a combined `cc-exp` text field.
 * Defaults to `MM/YY` (the most common vendor default); switches to
 * `MM/YYYY` when the field's `maxlength` or `placeholder` hints at a
 * 4-digit year.
 */
export function formatExpiryForField(el: HTMLInputElement, month: string, year: string): string {
  const mm = month.trim().padStart(2, '0');
  const maxLength = el.maxLength;
  const placeholder = (el.getAttribute('placeholder') ?? '').toUpperCase();
  const wantsFourDigitYear = (maxLength >= 7 && maxLength <= 9) || placeholder.includes('YYYY');

  if (wantsFourDigitYear) {
    const yyyy = year.trim().length === 2 ? `20${year.trim()}` : year.trim();
    return `${mm}/${yyyy}`;
  }
  const yy = year.trim().length === 4 ? year.trim().slice(2) : year.trim().padStart(2, '0');
  return `${mm}/${yy}`;
}
