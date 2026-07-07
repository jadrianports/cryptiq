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
import { fillField, fillSelectField, resolveSelectOption } from './domFill';

function makeInput(type = 'text'): HTMLInputElement {
  const input = document.createElement('input');
  input.type = type;
  return input;
}

function makeSelect(options: Array<{ value?: string; label?: string }>): HTMLSelectElement {
  const select = document.createElement('select');
  for (const opt of options) {
    const option = document.createElement('option');
    if (opt.value !== undefined) option.value = opt.value;
    option.textContent = opt.label ?? opt.value ?? '';
    select.appendChild(option);
  }
  return select;
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

  describe('fillSelectField (CFILL-02, D-02/D-03)', () => {
    it('sets value via the native setter and dispatches a bubbling change event on a confident match', () => {
      const select = makeSelect([{ value: '01', label: 'January' }, { value: '03', label: 'March' }]);
      document.body.appendChild(select);
      const seen: Array<{ type: string; bubbles: boolean }> = [];
      select.addEventListener('change', (e) => seen.push({ type: e.type, bubbles: e.bubbles }));

      const result = fillSelectField(select, '03');

      expect(result.filled).toBe(true);
      expect(select.value).toBe('03');
      expect(seen).toEqual([{ type: 'change', bubbles: true }]);
      document.body.removeChild(select);
    });

    it('leaves the select unchanged and returns filled:false when no option matches (D-03 read-back fail-safe)', () => {
      const select = makeSelect([{ value: '01', label: 'January' }]);
      select.value = '01';

      const result = fillSelectField(select, '99');

      expect(result.filled).toBe(false);
      expect(select.value).toBe('01');
      expect(select.selectedIndex).toBe(0);
    });

    it('resolves a 2-digit year against an option VALUE of the 4-digit form', () => {
      const select = makeSelect([{ value: '2027', label: '2027' }]);
      expect(resolveSelectOption(select, '27')).toBe('2027');
    });

    it('resolves a 4-digit year against an option TEXT CONTENT of the 2-digit form', () => {
      const select = makeSelect([{ value: '27', label: '2027' }]);
      expect(resolveSelectOption(select, '2027')).toBe('27');
    });

    it('resolves a numeric month against a month-name option label', () => {
      const select = makeSelect([{ value: 'March', label: 'March' }]);
      expect(resolveSelectOption(select, '03')).toBe('March');
    });

    it('fillSelectField inside a <form> NEVER calls submit()/requestSubmit() and never dispatches a submit event (never-auto-submit invariant)', () => {
      const form = document.createElement('form');
      const select = makeSelect([{ value: '03', label: 'March' }]);
      form.appendChild(select);
      document.body.appendChild(form);

      const submitSpy = vi.spyOn(HTMLFormElement.prototype, 'submit').mockImplementation(() => {});
      const requestSubmitSpy = vi.spyOn(HTMLFormElement.prototype, 'requestSubmit').mockImplementation(() => {});
      const submitEventSpy = vi.fn();
      form.addEventListener('submit', submitEventSpy);

      fillSelectField(select, '03');
      fillSelectField(select, 'no-match-here');

      expect(submitSpy).not.toHaveBeenCalled();
      expect(requestSubmitSpy).not.toHaveBeenCalled();
      expect(submitEventSpy).not.toHaveBeenCalled();

      submitSpy.mockRestore();
      requestSubmitSpy.mockRestore();
      document.body.removeChild(form);
    });
  });
});
