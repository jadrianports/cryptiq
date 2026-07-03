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
