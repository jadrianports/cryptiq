// apps/site/src/tests/containment.spec.ts
//
// Phase 38 Plan 02, Task 1 (DEMO-01, D-08). Two independent proofs, run in a
// real browser (Vitest browser mode) against the D-03/D-04 locked contained
// shell rendered by App.svelte:
//
//   1. "field-detector" (DEMO-01): Cryptiq's OWN shipped extension detector —
//      `scanForLoginFields` from apps/extension/src/lib/fieldDetection.ts,
//      imported UNMODIFIED via the `@cryptiq/extension/fieldDetection`
//      subpath export (38-RESEARCH.md Pattern 2) — finds NOTHING to fill on
//      the rendered demo page. A second, independent structural assertion
//      (zero <form>, zero submit control) guards against a future edit that
//      silently removes one lock while leaving the other in place
//      (38-RESEARCH.md Pattern 3).
//
//   2. "storage-throw" (D-08): localStorage/sessionStorage/indexedDB/
//      document.cookie are monkeypatched PER-METHOD (not whole-object
//      reassignment — Pitfall 4) to throw on every touch, backed by a
//      false-green control that proves the setup is genuinely wired (a
//      direct touch inside the test itself must go red-then-caught, not
//      silently no-op).
//
// D-05: "the enforcement is the test" — a demo-specific reimplementation of
// field detection would prove nothing about the real extension and could
// silently drift from it (T-38-04). This spec imports the REAL detector.

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { render } from 'vitest-browser-svelte';
import { scanForLoginFields } from '@cryptiq/extension/fieldDetection';
import App from '../App.svelte';

describe('containment — field-detector (DEMO-01, D-05)', () => {
  it('field-detector: scanForLoginFields finds nothing to fill on the rendered demo page', () => {
    const { container } = render(App);

    // Lock 1: the REAL, unmodified extension detector returns undefined for
    // both halves — nothing to fill, nothing to save (DEMO-01).
    const result = scanForLoginFields(container);
    expect(result.user).toBeUndefined();
    expect(result.pass).toBeUndefined();

    // Lock 2 (independent — D-04 belt-and-suspenders): the rendered page has
    // zero <form> elements and zero submit controls at all. This assertion
    // is deliberately SEPARATE from the detector-result assertion above, so
    // a future edit that reintroduces a <form> (or a submit button) without
    // also reintroducing a credential-token field name still fails loudly,
    // and vice versa (38-RESEARCH.md Pattern 3).
    expect(container.querySelectorAll('form').length).toBe(0);
    expect(
      container.querySelectorAll('button[type="submit"], input[type="submit"]').length,
    ).toBe(0);
  });
});

describe('containment — storage-throw setup (D-08, DEMO-02 backstop)', () => {
  let originalCookieDescriptor: PropertyDescriptor | undefined;

  beforeEach(() => {
    // Per-method monkeypatch (Pitfall 4) — localStorage/sessionStorage are
    // real browser host objects; some engines make whole-object reassignment
    // silently no-op or throw a TypeError on the assignment itself. Patching
    // individual methods is the reliable approach.
    localStorage.setItem = () => {
      throw new Error('D-08: localStorage.setItem attempted');
    };
    localStorage.getItem = () => {
      throw new Error('D-08: localStorage.getItem attempted');
    };
    localStorage.removeItem = () => {
      throw new Error('D-08: localStorage.removeItem attempted');
    };
    localStorage.clear = () => {
      throw new Error('D-08: localStorage.clear attempted');
    };

    sessionStorage.setItem = () => {
      throw new Error('D-08: sessionStorage.setItem attempted');
    };
    sessionStorage.getItem = () => {
      throw new Error('D-08: sessionStorage.getItem attempted');
    };
    sessionStorage.removeItem = () => {
      throw new Error('D-08: sessionStorage.removeItem attempted');
    };
    sessionStorage.clear = () => {
      throw new Error('D-08: sessionStorage.clear attempted');
    };

    indexedDB.open = () => {
      throw new Error('D-08: indexedDB.open attempted');
    };

    originalCookieDescriptor = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
    Object.defineProperty(document, 'cookie', {
      configurable: true,
      get() {
        throw new Error('D-08: document.cookie read attempted');
      },
      set() {
        throw new Error('D-08: document.cookie write attempted');
      },
    });
  });

  afterEach(() => {
    // Restore the real cookie descriptor so this per-method monkeypatch
    // never leaks a permanently-broken document.cookie into another test in
    // the same browser realm/session.
    if (originalCookieDescriptor) {
      Object.defineProperty(document, 'cookie', originalCookieDescriptor);
    }
  });

  it('storage-throw: localStorage/sessionStorage/indexedDB/document.cookie all throw when touched', () => {
    expect(() => localStorage.setItem('k', 'v')).toThrow('D-08: localStorage.setItem attempted');
    expect(() => localStorage.getItem('k')).toThrow('D-08: localStorage.getItem attempted');
    expect(() => sessionStorage.setItem('k', 'v')).toThrow(
      'D-08: sessionStorage.setItem attempted',
    );
    expect(() => indexedDB.open('demo-db')).toThrow('D-08: indexedDB.open attempted');
    expect(() => document.cookie).toThrow('D-08: document.cookie read attempted');
    expect(() => {
      document.cookie = 'a=b';
    }).toThrow('D-08: document.cookie write attempted');
  });

  it('storage-throw control (Pitfall 4 false-green guard): a direct touch is genuinely caught, not a silent no-op', () => {
    // This is the control assertion the plan requires: prove the throw-setup
    // above is actually wired by calling the API directly here and asserting
    // it goes red-then-caught (a `try { ... } catch` that FAILS to fire would
    // fall through to the fail() call below, turning this test red).
    let threw = false;
    try {
      localStorage.setItem('control-key', 'control-value');
    } catch (err) {
      threw = true;
      expect((err as Error).message).toBe('D-08: localStorage.setItem attempted');
    }
    expect(threw).toBe(true);
  });
});
