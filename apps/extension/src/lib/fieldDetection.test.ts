// apps/extension/src/lib/fieldDetection.test.ts
//
// FILL-01/02/07, D-02/D-03 coverage over happy-dom DOM fixtures. Mirrors
// packages/core/src/entries/matchByOrigin.test.ts's fixture-builder pattern
// (makeEntry -> makeFormFixture here).

import { beforeEach, describe, expect, it } from 'vitest';
import { fakeBrowser } from 'wxt/testing/fake-browser';
import { scanForLoginFields } from './fieldDetection';

/** Builds a detached-then-attached container from an HTML string, mirroring
 * matchByOrigin.test.ts's makeEntry(overrides) fixture-builder convention. */
function makeFormFixture(html: string): HTMLDivElement {
  const container = document.createElement('div');
  container.innerHTML = html;
  document.body.appendChild(container);
  return container;
}

describe('fieldDetection — scanForLoginFields (FILL-01/02/07, D-02/D-03)', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
    fakeBrowser.reset();
  });

  it('trusts autocomplete="username" + autocomplete="current-password" directly (highest-confidence tier)', () => {
    const container = makeFormFixture(`
      <form>
        <input type="text" autocomplete="username" id="u" />
        <input type="password" autocomplete="current-password" id="p" />
      </form>
    `);

    const result = scanForLoginFields(container);

    expect(result.user?.id).toBe('u');
    expect(result.pass?.id).toBe('p');
  });

  it('treats autocomplete="email" as a username-equivalent signal', () => {
    const container = makeFormFixture(`
      <form>
        <input type="text" autocomplete="email" id="e" />
        <input type="password" autocomplete="current-password" id="p" />
      </form>
    `);

    const result = scanForLoginFields(container);

    expect(result.user?.id).toBe('e');
    expect(result.pass?.id).toBe('p');
  });

  it('detects input[type=password] with NO autocomplete and pairs the nearest preceding strong-pattern username field', () => {
    const container = makeFormFixture(`
      <form>
        <input type="text" name="username" id="u" />
        <input type="password" id="p" />
      </form>
    `);

    const result = scanForLoginFields(container);

    expect(result.pass?.id).toBe('p');
    expect(result.user?.id).toBe('u');
  });

  it('does NOT report a bare unlabeled text input with no form/submit and no keyword (D-02 conservative-miss)', () => {
    const container = makeFormFixture(`<input type="text" id="bare" />`);

    const result = scanForLoginFields(container);

    expect(result.user).toBeUndefined();
    expect(result.pass).toBeUndefined();
  });

  it('finds a form injected AFTER an initial scan on a second scan (FILL-02 re-scan basis)', () => {
    const container = makeFormFixture(`<div id="empty-slot"></div>`);

    const firstScan = scanForLoginFields(container);
    expect(firstScan.user).toBeUndefined();
    expect(firstScan.pass).toBeUndefined();

    const slot = container.querySelector('#empty-slot')!;
    slot.innerHTML = `
      <form>
        <input type="text" name="username" id="late-u" />
        <input type="password" id="late-p" />
      </form>
    `;

    const secondScan = scanForLoginFields(container);
    expect(secondScan.user?.id).toBe('late-u');
    expect(secondScan.pass?.id).toBe('late-p');
  });

  it('resolves label[for] > aria-labelledby > aria-label priority: falls back to aria-labelledby when no label[for] exists', () => {
    const container = makeFormFixture(`
      <form>
        <span id="lbl">Email</span>
        <input type="text" id="u" aria-labelledby="lbl" aria-label="something" />
        <input type="password" id="p" />
      </form>
    `);

    const result = scanForLoginFields(container);

    expect(result.user?.id).toBe('u');
  });

  it('resolves label[for] > aria-labelledby > aria-label priority: falls back to aria-label when neither label[for] nor aria-labelledby exist', () => {
    const container = makeFormFixture(`
      <form>
        <input type="text" id="u" aria-label="Email address" />
        <input type="password" id="p" />
      </form>
    `);

    const result = scanForLoginFields(container);

    expect(result.user?.id).toBe('u');
  });

  it('resolves label[for] > aria-labelledby > aria-label priority: label[for] wins even when it does not itself match the pattern', () => {
    // label[for] text "Something" does not match the strong-pattern; the
    // aria-label DOES match ("username field") -- proves label[for] is
    // consulted first and aria-label is never reached.
    const container = makeFormFixture(`
      <form>
        <label for="u">Something</label>
        <input type="text" id="u" aria-label="username field" />
        <input type="password" id="p" />
      </form>
    `);

    const result = scanForLoginFields(container);

    expect(result.user).toBeUndefined();
  });

  it('recurses into an OPEN shadow root and finds a field pair inside it', () => {
    const container = document.createElement('div');
    document.body.appendChild(container);
    const host = document.createElement('div');
    container.appendChild(host);
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = `
      <form>
        <input type="text" name="username" id="shadow-u" />
        <input type="password" id="shadow-p" />
      </form>
    `;

    const result = scanForLoginFields(container);

    expect(result.pass?.id).toBe('shadow-p');
    expect(result.user?.id).toBe('shadow-u');
  });

  it('FILL-07/D-03: carries no cross-call state — two independent calls on different roots do not leak into each other', () => {
    const rootWithFields = makeFormFixture(`
      <form>
        <input type="text" name="username" id="u1" />
        <input type="password" id="p1" />
      </form>
    `);
    const rootWithoutFields = makeFormFixture(`<input type="text" id="bare2" />`);

    const emptyBefore = scanForLoginFields(rootWithoutFields);
    expect(emptyBefore.user).toBeUndefined();
    expect(emptyBefore.pass).toBeUndefined();

    const populated = scanForLoginFields(rootWithFields);
    expect(populated.user?.id).toBe('u1');
    expect(populated.pass?.id).toBe('p1');

    const emptyAfter = scanForLoginFields(rootWithoutFields);
    expect(emptyAfter.user).toBeUndefined();
    expect(emptyAfter.pass).toBeUndefined();
  });

  it('FILL-07/D-03: writes no chrome.storage state during detection', async () => {
    const container = makeFormFixture(`
      <form>
        <input type="text" name="username" id="u" />
        <input type="password" id="p" />
      </form>
    `);

    scanForLoginFields(container);

    const allStorage = await chrome.storage.local.get(null);
    expect(Object.keys(allStorage)).toHaveLength(0);
  });
});
