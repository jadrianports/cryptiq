// apps/extension/src/lib/popupFill.test.ts
//
// Covers Plan 17-04 Task 1's behaviors: ensureContentScript's ping-then-inject
// idempotency + XSEC-01 no-allFrames guarantee, recheckTabUnchanged's XSEC-03
// TOCTOU refusal, buildPickerViewModel's order-preserving no-password shaping
// (FILL-05/HEALTH-02), and decideFillFlow's 0/1/many + fill-anyway decision
// (FILL-04/05/06). Mirrors bridgeRpc.test.ts's `fakeBrowser.reset()` in
// beforeEach; chrome.tabs.sendMessage/chrome.scripting.executeScript are not
// implemented by @webext-core/fake-browser (they throw "not implemented"), so
// each is stubbed per-test via a direct `Object.assign` override (avoids
// @types/chrome's overloaded-signature inference defeating vi.spyOn's
// generic mockResolvedValue/mockRejectedValue typing) -- chrome.tabs.query IS
// a real fake implementation (in-memory tab list), stubbed here anyway for
// determinism, via the same override helper for consistency.

import { beforeEach, describe, expect, it, vi, type Mock } from 'vitest';
import { fakeBrowser } from 'wxt/testing/fake-browser';
import type { EntryMatchMetadata } from './contentScriptMessages';
import {
  buildPickerViewModel,
  buildSearchViewModel,
  decideFillFlow,
  ensureContentScript,
  recheckTabUnchanged,
  type SearchEntryResult,
} from './popupFill';

function makeSearchResult(overrides: Partial<SearchEntryResult> = {}): SearchEntryResult {
  return {
    id: 'entry-1',
    title: 'Example',
    username: 'me@example.com',
    currentTab: false,
    ...overrides,
  };
}

function makeCandidate(overrides: Partial<EntryMatchMetadata> = {}): EntryMatchMetadata {
  return {
    id: 'entry-1',
    title: 'Example',
    username: 'me@example.com',
    domainHint: 'example.com',
    ...overrides,
  };
}

/** Directly overrides a chrome.* namespace method with a fresh vi.fn(),
 * sidestepping @types/chrome's overloaded-signature inference (which defeats
 * vi.spyOn(...).mockResolvedValue's generic typing for sendMessage/
 * executeScript/query). Returns the mock for call-args assertions. */
function stubChromeMethod<T extends (...args: never[]) => unknown>(
  namespace: Record<string, unknown>,
  method: string,
  impl: T,
): Mock<T> {
  const fn = vi.fn(impl);
  Object.assign(namespace, { [method]: fn });
  return fn;
}

describe('popupFill', () => {
  beforeEach(() => {
    fakeBrowser.reset();
  });

  describe('ensureContentScript', () => {
    it('does NOT call executeScript when the ping succeeds (idempotent, already injected)', async () => {
      const pingSpy = stubChromeMethod(
        chrome.tabs,
        'sendMessage',
        async (_tabId: number, _message: unknown) => ({ ok: true }),
      );
      const injectSpy = stubChromeMethod(chrome.scripting, 'executeScript', async (_opts: unknown) => []);

      const result = await ensureContentScript(42);

      expect(result).toBe(true);
      expect(pingSpy).toHaveBeenCalledWith(42, { type: 'cryptiq-ping' });
      expect(injectSpy).not.toHaveBeenCalled();
    });

    it('injects via executeScript only after a caught ping rejection, targeting the tab with NO allFrames key (XSEC-01)', async () => {
      stubChromeMethod(chrome.tabs, 'sendMessage', async (_tabId: number, _message: unknown) => {
        throw new Error('Could not establish connection.');
      });
      const injectSpy = stubChromeMethod(chrome.scripting, 'executeScript', async (_opts: unknown) => []);

      const result = await ensureContentScript(7);

      expect(result).toBe(true);
      expect(injectSpy).toHaveBeenCalledTimes(1);
      const callArgs = injectSpy.mock.calls[0]![0] as Record<string, unknown>;
      const target = callArgs.target as Record<string, unknown>;
      expect(target.tabId).toBe(7);
      expect(Object.prototype.hasOwnProperty.call(callArgs, 'allFrames')).toBe(false);
      expect(Object.prototype.hasOwnProperty.call(target, 'allFrames')).toBe(false);
    });

    it('fails closed to false when executeScript throws (e.g. a chrome:// page)', async () => {
      stubChromeMethod(chrome.tabs, 'sendMessage', async (_tabId: number, _message: unknown) => {
        throw new Error('Could not establish connection.');
      });
      stubChromeMethod(chrome.scripting, 'executeScript', async (_opts: unknown) => {
        throw new Error('Cannot access a chrome:// URL');
      });

      const result = await ensureContentScript(99);

      expect(result).toBe(false);
    });
  });

  describe('recheckTabUnchanged (XSEC-03 TOCTOU)', () => {
    it('returns true when the active tab id and origin are unchanged', async () => {
      stubChromeMethod(chrome.tabs, 'query', async (_queryInfo: unknown) => [
        { id: 5, url: 'https://example.com/login' },
      ]);

      const result = await recheckTabUnchanged(5, 'https://example.com');

      expect(result).toBe(true);
    });

    it('returns false when the active tab id has changed', async () => {
      stubChromeMethod(chrome.tabs, 'query', async (_queryInfo: unknown) => [
        { id: 6, url: 'https://example.com/login' },
      ]);

      const result = await recheckTabUnchanged(5, 'https://example.com');

      expect(result).toBe(false);
    });

    it('returns false when the origin has changed (tab navigated away)', async () => {
      stubChromeMethod(chrome.tabs, 'query', async (_queryInfo: unknown) => [
        { id: 5, url: 'https://evil.example.net/phish' },
      ]);

      const result = await recheckTabUnchanged(5, 'https://example.com');

      expect(result).toBe(false);
    });

    it('fails closed to false when the tab query throws', async () => {
      stubChromeMethod(chrome.tabs, 'query', async () => {
        throw new Error('boom');
      });

      const result = await recheckTabUnchanged(5, 'https://example.com');

      expect(result).toBe(false);
    });
  });

  describe('buildPickerViewModel (FILL-05, HEALTH-02)', () => {
    it('preserves app-side order and maps weak/reused badge flags', () => {
      const candidates = [
        makeCandidate({ id: 'a', title: 'First', weak: true }),
        makeCandidate({ id: 'b', title: 'Second', reused: true }),
        makeCandidate({ id: 'c', title: 'Third' }),
      ];

      const rows = buildPickerViewModel(candidates);

      expect(rows.map((r) => r.id)).toEqual(['a', 'b', 'c']);
      expect(rows[0]).toEqual({ id: 'a', title: 'First', username: 'me@example.com', weak: true, reused: false });
      expect(rows[1]).toEqual({ id: 'b', title: 'Second', username: 'me@example.com', weak: false, reused: true });
      expect(rows[2]).toEqual({ id: 'c', title: 'Third', username: 'me@example.com', weak: false, reused: false });
    });

    it('never carries a password field on any row', () => {
      const rows = buildPickerViewModel([makeCandidate()]);
      for (const row of rows) {
        expect(Object.prototype.hasOwnProperty.call(row, 'password')).toBe(false);
        expect(Object.prototype.hasOwnProperty.call(row, 'secret')).toBe(false);
      }
    });
  });

  describe('buildSearchViewModel (UX-01)', () => {
    it('preserves order and maps { id, title, username, currentTab } 1:1 (no re-sort, no filter)', () => {
      const results = [
        makeSearchResult({ id: 'a', title: 'First', currentTab: true }),
        makeSearchResult({ id: 'b', title: 'Second', currentTab: false }),
        makeSearchResult({ id: 'c', title: 'Third', currentTab: false }),
      ];

      const rows = buildSearchViewModel(results);

      expect(rows.map((r) => r.id)).toEqual(['a', 'b', 'c']);
      expect(rows[0]).toEqual({ id: 'a', title: 'First', username: 'me@example.com', currentTab: true });
      expect(rows[1]).toEqual({ id: 'b', title: 'Second', username: 'me@example.com', currentTab: false });
      expect(rows[2]).toEqual({ id: 'c', title: 'Third', username: 'me@example.com', currentTab: false });
    });

    it('never carries a password field on any row', () => {
      const rows = buildSearchViewModel([makeSearchResult()]);
      for (const row of rows) {
        expect(Object.prototype.hasOwnProperty.call(row, 'password')).toBe(false);
        expect(Object.prototype.hasOwnProperty.call(row, 'secret')).toBe(false);
      }
    });

    it('maps an empty results array to an empty rows array', () => {
      expect(buildSearchViewModel([])).toEqual([]);
    });
  });

  describe('decideFillFlow (FILL-04/05/06)', () => {
    it('returns no-matches for zero candidates, fillAnyway always false', () => {
      expect(decideFillFlow({ candidates: [], fieldsDetected: true })).toEqual({ kind: 'no-matches', fillAnyway: false });
      expect(decideFillFlow({ candidates: [], fieldsDetected: false })).toEqual({ kind: 'no-matches', fillAnyway: false });
    });

    it('returns single for exactly one candidate', () => {
      const result = decideFillFlow({ candidates: [makeCandidate()], fieldsDetected: true });
      expect(result).toEqual({ kind: 'single', fillAnyway: false });
    });

    it('returns picker for more than one candidate', () => {
      const result = decideFillFlow({
        candidates: [makeCandidate({ id: 'a' }), makeCandidate({ id: 'b' })],
        fieldsDetected: true,
      });
      expect(result).toEqual({ kind: 'picker', fillAnyway: false });
    });

    it('sets fillAnyway true when no field was detected, for both single and picker', () => {
      expect(decideFillFlow({ candidates: [makeCandidate()], fieldsDetected: false })).toEqual({
        kind: 'single',
        fillAnyway: true,
      });
      expect(
        decideFillFlow({ candidates: [makeCandidate({ id: 'a' }), makeCandidate({ id: 'b' })], fieldsDetected: false }),
      ).toEqual({ kind: 'picker', fillAnyway: true });
    });
  });
});
