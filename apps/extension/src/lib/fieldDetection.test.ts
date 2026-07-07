// apps/extension/src/lib/fieldDetection.test.ts
//
// FILL-01/02/07, D-02/D-03 coverage over happy-dom DOM fixtures. Mirrors
// packages/core/src/entries/matchByOrigin.test.ts's fixture-builder pattern
// (makeEntry -> makeFormFixture here).

import { beforeEach, describe, expect, it } from 'vitest';
import { fakeBrowser } from 'wxt/testing/fake-browser';
import { lastMeaningfulToken, scanForCardFields, scanForLoginFields } from './fieldDetection';

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

  it('BUG-17-01: completes the pair when ONLY the username has an autocomplete token and the password field has none (real nexusmods.com shape)', () => {
    // Nexus Mods: autocomplete="email" on the username, but the password
    // <input> carries NO autocomplete attribute. The autocomplete-first pass
    // must not short-circuit to username-only — it must fall through to the
    // input[type=password] ground-truth heuristic to complete the pair.
    const container = makeFormFixture(`
      <form>
        <input type="text" autocomplete="email" name="user[login]" id="login" />
        <input type="password" name="user[password]" id="password" />
        <button type="submit">Log in</button>
      </form>
    `);

    const result = scanForLoginFields(container);

    expect(result.user?.id).toBe('login');
    expect(result.pass?.id).toBe('password');
  });

  it('BUG-17-01 (symmetric): completes the pair when ONLY the password has an autocomplete token and the username field has none', () => {
    const container = makeFormFixture(`
      <form>
        <input type="text" name="username" id="u" />
        <input type="password" autocomplete="current-password" id="p" />
      </form>
    `);

    const result = scanForLoginFields(container);

    expect(result.pass?.id).toBe('p');
    expect(result.user?.id).toBe('u');
  });

  it('FILL-08: tokenizes a multi-token autocomplete — reddit-shaped `autocomplete="username webauthn"` + `current-password` resolves BOTH fields', () => {
    // Reddit appends `webauthn` to the username autocomplete for passkey
    // conditional UI, producing the space-separated token list
    // `autocomplete="username webauthn"`. An exact whole-string match against
    // the single-token set misses it; WHATWG tokenization catches the
    // `username` token. The password field is single-token and always matched.
    const container = makeFormFixture(`
      <form>
        <input type="text" name="username" autocomplete="username webauthn" id="u" />
        <input type="password" autocomplete="current-password" id="p" />
      </form>
    `);

    const result = scanForLoginFields(container);

    expect(result.user?.id).toBe('u');
    expect(result.pass?.id).toBe('p');
  });

  it('FILL-08: tokenizes a multi-token `autocomplete="new-password webauthn"` password field', () => {
    const container = makeFormFixture(`
      <form>
        <input type="text" name="username" autocomplete="username webauthn" id="u" />
        <input type="password" autocomplete="new-password webauthn" id="p" />
      </form>
    `);

    const result = scanForLoginFields(container);

    expect(result.user?.id).toBe('u');
    expect(result.pass?.id).toBe('p');
  });

  it('FILL-08: tokenizes a section-prefixed token list (`section-login username`)', () => {
    const container = makeFormFixture(`
      <form>
        <input type="text" autocomplete="section-login username" id="u" />
        <input type="password" autocomplete="section-login current-password" id="p" />
      </form>
    `);

    const result = scanForLoginFields(container);

    expect(result.user?.id).toBe('u');
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

describe('fieldDetection — lastMeaningfulToken (CFILL-01, D-05)', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  it('resolves a section/billing-prefixed multi-token string on its LAST token', () => {
    const container = makeFormFixture(`<input autocomplete="section-x billing postal-code" id="pc" />`);
    const el = container.querySelector('#pc')!;

    expect(lastMeaningfulToken(el)).toBe('postal-code');
  });

  it('strips a trailing webauthn credential modifier (reddit-shaped username field)', () => {
    const container = makeFormFixture(`<input autocomplete="username webauthn" id="u" />`);
    const el = container.querySelector('#u')!;

    expect(lastMeaningfulToken(el)).toBe('username');
  });

  it('returns undefined when the autocomplete attribute is empty/absent', () => {
    const container = makeFormFixture(`<input id="bare" />`);
    const el = container.querySelector('#bare')!;

    expect(lastMeaningfulToken(el)).toBeUndefined();
  });

  it('resolves a bare single-token attribute directly', () => {
    const container = makeFormFixture(`<input autocomplete="cc-number" id="cc" />`);
    const el = container.querySelector('#cc')!;

    expect(lastMeaningfulToken(el)).toBe('cc-number');
  });
});

describe('fieldDetection — scanForCardFields (CFILL-01, D-04/D-05)', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  it('resolves "billing cc-number" to result.number via last-token routing', () => {
    const container = makeFormFixture(`<input autocomplete="billing cc-number" id="num" />`);

    const result = scanForCardFields(container);

    expect(result.number?.id).toBe('num');
  });

  it('resolves cc-exp-month / cc-exp-year <select> elements to expiryMonth / expiryYear', () => {
    const container = makeFormFixture(`
      <select autocomplete="cc-exp-month" id="month"><option value="03">03</option></select>
      <select autocomplete="cc-exp-year" id="year"><option value="2027">2027</option></select>
    `);

    const result = scanForCardFields(container);

    expect(result.expiryMonth?.id).toBe('month');
    expect(result.expiryYear?.id).toBe('year');
    expect(result.expiryMonth).toBeInstanceOf(HTMLSelectElement);
    expect(result.expiryYear).toBeInstanceOf(HTMLSelectElement);
  });

  it('resolves a single "cc-exp" field to result.ccExpCombined', () => {
    const container = makeFormFixture(`<input autocomplete="cc-exp" id="exp" />`);

    const result = scanForCardFields(container);

    expect(result.ccExpCombined?.id).toBe('exp');
  });

  it('resolves cc-csc / cc-name / cc-type to cvv / cardholderName / brand', () => {
    const container = makeFormFixture(`
      <input autocomplete="cc-csc" id="csc" />
      <input autocomplete="cc-name" id="name" />
      <input autocomplete="cc-type" id="type" />
    `);

    const result = scanForCardFields(container);

    expect(result.cvv?.id).toBe('csc');
    expect(result.cardholderName?.id).toBe('name');
    expect(result.brand?.id).toBe('type');
  });

  it('returns {} (all-absent) when no cc-* token is present anywhere', () => {
    const container = makeFormFixture(`
      <input type="text" name="username" id="u" />
      <input type="password" id="p" />
    `);

    const result = scanForCardFields(container);

    expect(result).toEqual({});
  });

  it('is stateless: two calls after a DOM mutation return independently-current elements', () => {
    const container = makeFormFixture(`<div id="slot"></div>`);

    const firstScan = scanForCardFields(container);
    expect(firstScan.number).toBeUndefined();

    const slot = container.querySelector('#slot')!;
    slot.innerHTML = `<input autocomplete="cc-number" id="late-num" />`;

    const secondScan = scanForCardFields(container);
    expect(secondScan.number?.id).toBe('late-num');
  });
});
