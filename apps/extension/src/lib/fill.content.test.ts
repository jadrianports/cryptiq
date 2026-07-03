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
  return { scanForLoginFields: scanForLoginFieldsSpy };
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

  it('debounces the MutationObserver re-scan to exactly ONE call per mutation batch (FILL-02)', () => {
    vi.useFakeTimers();

    let capturedCallback: MutationCallback | undefined;
    class FakeMutationObserver {
      constructor(cb: MutationCallback) {
        capturedCallback = cb;
      }
      observe(): void {}
      disconnect(): void {}
    }
    vi.stubGlobal('MutationObserver', FakeMutationObserver);

    fillContentScript.main(createCtx());
    scanForLoginFieldsSpy.mockClear();

    expect(capturedCallback).toBeDefined();
    // Simulate a burst of mutation-record batches arriving inside the same
    // debounce window -- the debounce must coalesce all of them into one
    // scheduled re-scan, not one per callback invocation.
    capturedCallback?.([], {} as MutationObserver);
    capturedCallback?.([], {} as MutationObserver);
    capturedCallback?.([], {} as MutationObserver);

    vi.advanceTimersByTime(300);

    expect(scanForLoginFieldsSpy).toHaveBeenCalledTimes(1);

    vi.unstubAllGlobals();
  });
});
