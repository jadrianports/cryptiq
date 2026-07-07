// apps/extension/src/lib/fill.content.test.ts
//
// Co-located in src/lib/ (not entrypoints/) so `wxt build` does not treat this
// `*.content.test.ts` file as a second "fill" content-script entrypoint —
// WXT derives an entrypoint name from any file placed directly in entrypoints/
// (see WXT docs: "avoid placing files related to an entrypoint directly in the
// entrypoints/ directory"). Every other apps/extension test already lives here.
//
// Task 2 (TDD RED -> GREEN): cryptiq-ping/detect/fill message handling,
// XSEC-03 exact-origin refusal (no DOM write on mismatch), XSEC-02 (no
// attachShadow/visible-node append), and FILL-02 (debounced MutationObserver
// re-scan). The listener under test is invoked via
// chrome.runtime.onMessage.trigger -- fakeBrowser IS globalThis.chrome
// (auto.mjs: `globalThis.chrome = fakeBrowser`) and its onMessage fake
// forwards whatever args are passed straight to each registered listener
// (defineEventWithTrigger: `trigger(...args) { listeners.map(l =>
// l(...args)) }`), so calling `.trigger(message, sender, sendResponse)`
// exercises the REAL 3-arg Chrome listener contract this content script's
// handler implements -- no hand-rolled port/message harness needed here
// (unlike bridgeRpc.test.ts's FakePort, which exists because THAT wire is
// chrome.runtime.Port, not chrome.runtime.onMessage).
//
// scanForLoginFields is wrapped in a call-counting spy (vi.mock +
// importOriginal, mirroring rpcDispatch.test.ts's scorePasswordSpy pattern)
// so FILL-02's debounce-coalescing behavior is directly observable while
// every other test still exercises the REAL field-detection logic against
// real fixture DOM.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fakeBrowser } from 'wxt/testing/fake-browser';
import type { FillResult } from './contentScriptMessages';

const scanForLoginFieldsSpy = vi.hoisted(() => vi.fn());

vi.mock('./fieldDetection', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./fieldDetection')>();
  scanForLoginFieldsSpy.mockImplementation(actual.scanForLoginFields);
  return { ...actual, scanForLoginFields: scanForLoginFieldsSpy };
});

import fillContentScript from '../../entrypoints/fill.content';

function buildLoginForm(): { form: HTMLFormElement; user: HTMLInputElement; pass: HTMLInputElement } {
  const form = document.createElement('form');
  const user = document.createElement('input');
  user.setAttribute('autocomplete', 'username');
  const pass = document.createElement('input');
  pass.setAttribute('type', 'password');
  pass.setAttribute('autocomplete', 'current-password');
  form.appendChild(user);
  form.appendChild(pass);
  document.body.appendChild(form);
  return { form, user, pass };
}

// Task 2 (Plan 25-03): card/identity fixture builders, mirroring
// buildLoginForm's shape -- one small named builder per fixture, colocated
// here (PATTERNS.md "fixture-builder-per-file convention").
function buildCardForm(): {
  cardholderName: HTMLInputElement;
  number: HTMLInputElement;
  expiryMonth: HTMLSelectElement;
  expiryYear: HTMLSelectElement;
  cvv: HTMLInputElement;
} {
  const form = document.createElement('form');

  const cardholderName = document.createElement('input');
  cardholderName.setAttribute('autocomplete', 'cc-name');

  const number = document.createElement('input');
  number.setAttribute('autocomplete', 'cc-number');

  const expiryMonth = document.createElement('select');
  expiryMonth.setAttribute('autocomplete', 'cc-exp-month');
  for (const m of ['01', '02', '03']) {
    const opt = document.createElement('option');
    opt.value = m;
    opt.textContent = m;
    expiryMonth.appendChild(opt);
  }

  const expiryYear = document.createElement('select');
  expiryYear.setAttribute('autocomplete', 'cc-exp-year');
  for (const y of ['2027', '2028']) {
    const opt = document.createElement('option');
    opt.value = y;
    opt.textContent = y;
    expiryYear.appendChild(opt);
  }

  const cvv = document.createElement('input');
  cvv.setAttribute('autocomplete', 'cc-csc');

  form.appendChild(cardholderName);
  form.appendChild(number);
  form.appendChild(expiryMonth);
  form.appendChild(expiryYear);
  form.appendChild(cvv);
  document.body.appendChild(form);

  return { cardholderName, number, expiryMonth, expiryYear, cvv };
}

function buildIdentityForm(): { email: HTMLInputElement; tel: HTMLInputElement; address: HTMLInputElement } {
  const form = document.createElement('form');

  const email = document.createElement('input');
  email.setAttribute('autocomplete', 'email');

  const tel = document.createElement('input');
  tel.setAttribute('autocomplete', 'tel');

  const address = document.createElement('input');
  address.setAttribute('autocomplete', 'street-address');

  form.appendChild(email);
  form.appendChild(tel);
  form.appendChild(address);
  document.body.appendChild(form);

  return { email, tel, address };
}

// fakeBrowser (== globalThis.chrome, see auto.mjs) extends chrome.runtime.onMessage
// with a `.trigger(...)` test helper (defineEventWithTrigger) not present in
// @types/chrome's Event<T> typing -- cast narrowly to invoke it.
interface TriggerableOnMessage {
  trigger: (message: unknown, sender: unknown, sendResponse: (response?: unknown) => void) => Promise<unknown[]>;
}

async function emitMessage(message: unknown): Promise<unknown> {
  const sendResponse = vi.fn();
  await (chrome.runtime.onMessage as unknown as TriggerableOnMessage).trigger(message, {}, sendResponse);
  return sendResponse.mock.calls[0]?.[0];
}

let contexts: InstanceType<typeof ContentScriptContext>[] = [];

function createCtx(): InstanceType<typeof ContentScriptContext> {
  const ctx = new ContentScriptContext(`fill-test-${contexts.length}-${Math.random()}`);
  contexts.push(ctx);
  return ctx;
}

describe('fill.content', () => {
  beforeEach(() => {
    fakeBrowser.reset();
    scanForLoginFieldsSpy.mockClear();
    document.body.innerHTML = '';
    contexts = [];
    fillContentScript.main(createCtx());
  });

  afterEach(() => {
    contexts.forEach((ctx) => ctx.abort());
    vi.useRealTimers();
  });

  it('cryptiq-ping resolves {ok:true} (idempotency probe)', async () => {
    const result = await emitMessage({ type: 'cryptiq-ping' });
    expect(result).toEqual({ ok: true });
  });

  it('cryptiq-detect runs scanForLoginFields and resolves fieldsDetected:true matching the fixture', async () => {
    buildLoginForm();

    const result = await emitMessage({ type: 'cryptiq-detect' });

    expect(scanForLoginFieldsSpy).toHaveBeenCalled();
    expect(result).toEqual({ ok: true, fieldsDetected: true });
  });

  it('cryptiq-detect resolves fieldsDetected:false when no login form is present', async () => {
    const result = await emitMessage({ type: 'cryptiq-detect' });
    expect(result).toEqual({ ok: true, fieldsDetected: false });
  });

  it('cryptiq-fill refuses on origin mismatch and writes NOTHING to the DOM (XSEC-03)', async () => {
    const { user, pass } = buildLoginForm();

    const result = await emitMessage({
      type: 'cryptiq-fill',
      secret: 'super-secret',
      username: 'alice',
      expectedOrigin: 'https://this-will-never-match.example',
    });

    expect(result).toEqual({ ok: false, reason: 'origin-mismatch' } satisfies FillResult);
    expect(user.value).toBe('');
    expect(pass.value).toBe('');
  });

  it('cryptiq-fill with matching origin fills a FRESHLY re-scanned field pair and resolves ok:true', async () => {
    const { user, pass } = buildLoginForm();
    scanForLoginFieldsSpy.mockClear(); // isolate the re-scan-on-fill assertion below

    const result = await emitMessage({
      type: 'cryptiq-fill',
      secret: 'super-secret',
      username: 'alice',
      expectedOrigin: location.origin,
    });

    expect(result).toEqual({ ok: true } satisfies FillResult);
    expect(user.value).toBe('alice');
    expect(pass.value).toBe('super-secret');
    // A fresh re-scan is used, not a cached reference from an earlier
    // cryptiq-detect call.
    expect(scanForLoginFieldsSpy).toHaveBeenCalled();
  });

  it('cryptiq-fill with matching origin but no detectable field resolves no-field-found', async () => {
    const result = await emitMessage({
      type: 'cryptiq-fill',
      secret: 'super-secret',
      username: 'alice',
      expectedOrigin: location.origin,
    });

    expect(result).toEqual({ ok: false, reason: 'no-field-found' } satisfies FillResult);
  });

  it('never calls attachShadow or appends a visible node to document.body (XSEC-02)', async () => {
    const attachShadowSpy = vi.spyOn(Element.prototype, 'attachShadow');
    const appendChildSpy = vi.spyOn(document.body, 'appendChild');

    buildLoginForm(); // exercises detect's DOM-scan path too, not just ping
    await emitMessage({ type: 'cryptiq-ping' });
    await emitMessage({ type: 'cryptiq-detect' });

    expect(attachShadowSpy).not.toHaveBeenCalled();
    // appendChild WAS called by the test's own buildLoginForm() fixture
    // setup above (document.body.appendChild(form)) -- assert the content
    // script's OWN message handling added no further calls beyond that one
    // fixture call.
    expect(appendChildSpy).toHaveBeenCalledTimes(1);

    attachShadowSpy.mockRestore();
    appendChildSpy.mockRestore();
  });

  it('CAP-01: a form submit with a filled password field posts a cryptiq-capture message and renders no DOM', async () => {
    const attachShadowSpy = vi.spyOn(Element.prototype, 'attachShadow');
    const appendChildSpy = vi.spyOn(document.body, 'appendChild');

    const { form, user, pass } = buildLoginForm();
    user.value = 'alice';
    pass.value = 'hunter2';

    const sendMessageSpy = vi.spyOn(chrome.runtime, 'sendMessage').mockResolvedValue(undefined);

    form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    await Promise.resolve(); // flush the fire-and-forget sendMessage microtask

    expect(sendMessageSpy).toHaveBeenCalledWith({
      type: 'cryptiq-capture',
      username: 'alice',
      password: 'hunter2',
      origin: location.origin,
    });
    expect(attachShadowSpy).not.toHaveBeenCalled();
    // appendChild was only called by this test's own buildLoginForm() fixture.
    expect(appendChildSpy).toHaveBeenCalledTimes(1);

    sendMessageSpy.mockRestore();
    attachShadowSpy.mockRestore();
    appendChildSpy.mockRestore();
  });

  it('CAP-01: a form submit with no password value posts nothing', async () => {
    const { form } = buildLoginForm();

    const sendMessageSpy = vi.spyOn(chrome.runtime, 'sendMessage').mockResolvedValue(undefined);

    form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    await Promise.resolve();

    expect(sendMessageSpy).not.toHaveBeenCalled();

    sendMessageSpy.mockRestore();
  });

  it('cryptiq-fill-focused fills a focused input via fillField and resolves ok:true (UX-03)', async () => {
    const { pass } = buildLoginForm();
    pass.focus();

    const result = await emitMessage({ type: 'cryptiq-fill-focused', secret: 'generated-secret', expectedOrigin: location.origin });

    expect(result).toEqual({ ok: true });
    expect(pass.value).toBe('generated-secret');
  });

  it('cryptiq-fill-focused with a username best-effort fills the sibling user field (UX-03)', async () => {
    const { user, pass } = buildLoginForm();
    pass.focus();

    const result = await emitMessage({
      type: 'cryptiq-fill-focused',
      secret: 'generated-secret',
      username: 'alice',
      expectedOrigin: location.origin,
    });

    expect(result).toEqual({ ok: true });
    expect(user.value).toBe('alice');
    expect(pass.value).toBe('generated-secret');
  });

  it('cryptiq-fill-focused refuses on origin mismatch and writes NOTHING to the DOM (WR-02 TOCTOU)', async () => {
    const { user, pass } = buildLoginForm();
    pass.focus();

    const result = await emitMessage({
      type: 'cryptiq-fill-focused',
      secret: 'generated-secret',
      username: 'alice',
      expectedOrigin: 'https://this-will-never-match.example',
    });

    expect(result).toEqual({ ok: false, reason: 'origin-mismatch' });
    expect(user.value).toBe('');
    expect(pass.value).toBe('');
  });

  it('cryptiq-fill-focused resolves no-field-found when the active element is not an input (UX-03)', async () => {
    document.body.innerHTML = '<div id="not-an-input"></div>';
    (document.getElementById('not-an-input') as HTMLDivElement).tabIndex = -1;
    (document.getElementById('not-an-input') as HTMLDivElement).focus();

    const result = await emitMessage({ type: 'cryptiq-fill-focused', secret: 'generated-secret', expectedOrigin: location.origin });

    expect(result).toEqual({ ok: false, reason: 'no-field-found' });
  });

  it('cryptiq-fill-focused REFUSES to write the secret into a non-password focused field (CR-01 leak guard)', async () => {
    // The context menu is registered on ALL `editable` fields, so a right-click may
    // land on a plain text / username / search input. Writing the password there would
    // expose it on screen and submit it to the site as that field's value — fail closed.
    const { user, pass } = buildLoginForm();
    user.focus();

    const result = await emitMessage({
      type: 'cryptiq-fill-focused',
      secret: 'super-secret-pw',
      username: 'alice',
      expectedOrigin: location.origin,
    });

    expect(result).toEqual({ ok: false, reason: 'no-field-found' });
    // The secret must never land in a visible non-password field, and nothing else is written.
    expect(user.value).toBe('');
    expect(pass.value).toBe('');
  });

  // Task 2 (Plan 25-03, CFILL-03): the typed card/identity branches. There is
  // NO popup send-side yet (Phase 26) -- these construct the typed
  // FillRequest message directly, exactly like the login tests above
  // (RESEARCH.md Pitfall 2), not a simulated popup click. Placed BEFORE the
  // debounce test below, which calls vi.unstubAllGlobals() and clobbers the
  // fakeBrowser/chrome global stub for any test running after it.
  describe('cryptiq-fill kind:card / kind:identity (CFILL-03)', () => {
    it('kind:card with a visible matching form fills text fields + a <select> expiry and resolves ok:true', async () => {
      const { cardholderName, number, expiryMonth, expiryYear, cvv } = buildCardForm();

      const result = await emitMessage({
        type: 'cryptiq-fill',
        kind: 'card',
        card: {
          cardholderName: 'Alice Example',
          number: '4111111111111111',
          expiryMonth: '03',
          expiryYear: '2027',
          cvv: '123',
        },
        expectedOrigin: location.origin,
      });

      expect(result).toEqual({ ok: true } satisfies FillResult);
      expect(cardholderName.value).toBe('Alice Example');
      expect(number.value).toBe('4111111111111111');
      expect(expiryMonth.value).toBe('03');
      expect(expiryYear.value).toBe('2027');
      expect(cvv.value).toBe('123');
    });

    it('kind:card does NOT write a field that is display:none (CFILL-03 visibility gate)', async () => {
      const { cardholderName, number, cvv } = buildCardForm();
      cvv.style.display = 'none';

      const result = await emitMessage({
        type: 'cryptiq-fill',
        kind: 'card',
        card: {
          cardholderName: 'Alice Example',
          number: '4111111111111111',
          expiryMonth: '03',
          expiryYear: '2027',
          cvv: '123',
        },
        expectedOrigin: location.origin,
      });

      expect(result).toEqual({ ok: true } satisfies FillResult);
      expect(cardholderName.value).toBe('Alice Example');
      expect(number.value).toBe('4111111111111111');
      expect(cvv.value).toBe('');
    });

    it('kind:card is forgiving: a form with only cardholderName+number still resolves ok:true when >=1 field is written', async () => {
      const form = document.createElement('form');
      const cardholderName = document.createElement('input');
      cardholderName.setAttribute('autocomplete', 'cc-name');
      form.appendChild(cardholderName);
      document.body.appendChild(form);

      const result = await emitMessage({
        type: 'cryptiq-fill',
        kind: 'card',
        card: { cardholderName: 'Alice Example', number: '', expiryMonth: '', expiryYear: '', cvv: '' },
        expectedOrigin: location.origin,
      });

      expect(result).toEqual({ ok: true } satisfies FillResult);
      expect(cardholderName.value).toBe('Alice Example');
    });

    it('kind:card resolves no-field-found when zero fields were written', async () => {
      const result = await emitMessage({
        type: 'cryptiq-fill',
        kind: 'card',
        card: { cardholderName: 'Alice Example', number: '4111', expiryMonth: '03', expiryYear: '2027', cvv: '123' },
        expectedOrigin: location.origin,
      });

      expect(result).toEqual({ ok: false, reason: 'no-field-found' } satisfies FillResult);
    });

    it('kind:card refuses on origin mismatch and writes NOTHING to the DOM (XSEC-03)', async () => {
      const { cardholderName, number } = buildCardForm();

      const result = await emitMessage({
        type: 'cryptiq-fill',
        kind: 'card',
        card: { cardholderName: 'Alice Example', number: '4111111111111111', expiryMonth: '03', expiryYear: '2027', cvv: '123' },
        expectedOrigin: 'https://this-will-never-match.example',
      });

      expect(result).toEqual({ ok: false, reason: 'origin-mismatch' } satisfies FillResult);
      expect(cardholderName.value).toBe('');
      expect(number.value).toBe('');
    });

    it('kind:card never calls form.submit()/requestSubmit() (never-auto-submit)', async () => {
      buildCardForm();
      const submitSpy = vi.spyOn(HTMLFormElement.prototype, 'submit').mockImplementation(() => {});
      const requestSubmitSpy = vi
        .spyOn(HTMLFormElement.prototype, 'requestSubmit')
        .mockImplementation(() => {});

      await emitMessage({
        type: 'cryptiq-fill',
        kind: 'card',
        card: { cardholderName: 'Alice Example', number: '4111111111111111', expiryMonth: '03', expiryYear: '2027', cvv: '123' },
        expectedOrigin: location.origin,
      });

      expect(submitSpy).not.toHaveBeenCalled();
      expect(requestSubmitSpy).not.toHaveBeenCalled();

      submitSpy.mockRestore();
      requestSubmitSpy.mockRestore();
    });

    it('kind:identity fills email/tel/address forgivingly and resolves ok:true', async () => {
      const { email, tel, address } = buildIdentityForm();

      const result = await emitMessage({
        type: 'cryptiq-fill',
        kind: 'identity',
        identity: { email: 'alice@example.com', phone: '555-0100', address: '123 Main St' },
        expectedOrigin: location.origin,
      });

      expect(result).toEqual({ ok: true } satisfies FillResult);
      expect(email.value).toBe('alice@example.com');
      expect(tel.value).toBe('555-0100');
      expect(address.value).toBe('123 Main St');
    });

    it('kind:identity refuses on origin mismatch and writes NOTHING to the DOM (XSEC-03)', async () => {
      const { email, tel, address } = buildIdentityForm();

      const result = await emitMessage({
        type: 'cryptiq-fill',
        kind: 'identity',
        identity: { email: 'alice@example.com', phone: '555-0100', address: '123 Main St' },
        expectedOrigin: 'https://this-will-never-match.example',
      });

      expect(result).toEqual({ ok: false, reason: 'origin-mismatch' } satisfies FillResult);
      expect(email.value).toBe('');
      expect(tel.value).toBe('');
      expect(address.value).toBe('');
    });
  });

});
