// apps/extension/src/lib/domFill.test.ts
//
// FILL-04 (Task 1 TDD RED): fillField sets a value via the native prototype
// setter, dispatches input+change (both bubbling), NEVER submits the form
// under any circumstance, and still works on a field whose OWN instance has
// an overridden `value` setter (simulating a framework like React that
// shadows the prototype's setter per-instance). Mirrors
// apps/desktop/src/lib/bridge/rpcDispatch.test.ts's vi.hoisted/vi.fn
// forbidden-call spy pattern (lockSpy) for the submit/requestSubmit
// assertions.

import { describe, expect, it, vi } from 'vitest';
import { fillField } from './domFill';

function makeInput(type = 'text'): HTMLInputElement {
  const input = document.createElement('input');
  input.type = type;
  return input;
}

describe('domFill', () => {
  it('fillField sets input.value via the native prototype setter', () => {
    const input = makeInput();
    fillField(input, 'secret');
    expect(input.value).toBe('secret');
  });

  it('fillField dispatches BOTH input and change events, both bubbling', () => {
    const input = makeInput();
    const seen: Array<{ type: string; bubbles: boolean }> = [];
    input.addEventListener('input', (e) => seen.push({ type: e.type, bubbles: e.bubbles }));
    input.addEventListener('change', (e) => seen.push({ type: e.type, bubbles: e.bubbles }));

    fillField(input, 'secret');

    expect(seen).toEqual([
      { type: 'input', bubbles: true },
      { type: 'change', bubbles: true },
    ]);
  });

  it('fillField inside a <form> NEVER calls submit()/requestSubmit() and never dispatches a submit event (FILL-04)', () => {
    const form = document.createElement('form');
    const input = makeInput('password');
    form.appendChild(input);
    document.body.appendChild(form);

    const submitSpy = vi.spyOn(HTMLFormElement.prototype, 'submit').mockImplementation(() => {});
    const requestSubmitSpy = vi.spyOn(HTMLFormElement.prototype, 'requestSubmit').mockImplementation(() => {});
    const submitEventSpy = vi.fn();
    form.addEventListener('submit', submitEventSpy);

    fillField(input, 'super-secret');

    expect(submitSpy).not.toHaveBeenCalled();
    expect(requestSubmitSpy).not.toHaveBeenCalled();
    expect(submitEventSpy).not.toHaveBeenCalled();

    submitSpy.mockRestore();
    requestSubmitSpy.mockRestore();
    document.body.removeChild(form);
  });

  it('fillField still updates the value via the prototype setter when the INSTANCE has an overridden value setter (framework simulation)', () => {
    const input = makeInput();
    let shadowedValue = '';
    // Simulate a framework (e.g. React) installing its OWN per-instance
    // `value` accessor that shadows HTMLInputElement.prototype's setter, so
    // a naive `element.value = x` would never reach the real native slot.
    Object.defineProperty(input, 'value', {
      configurable: true,
      get() {
        return shadowedValue;
      },
      set(v: string) {
        shadowedValue = `intercepted:${v}`;
      },
    });

    fillField(input, 'secret');

    // The shadowing instance setter must never have been invoked...
    expect(shadowedValue).toBe('');
    // ...because fillField bypassed it via the PROTOTYPE's own descriptor —
    // read the real underlying value back the same way, not through the
    // now-shadowing instance getter.
    const protoDescriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
    expect(protoDescriptor?.get?.call(input)).toBe('secret');
  });
});
