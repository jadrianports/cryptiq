// apps/extension/src/lib/contextMenu.test.ts
//
// Plan 18-02 (UX-03): pure-helper unit tests for contextMenu.ts -- no
// chrome.* mocking needed since both exports are plain functions.

import { describe, expect, it } from 'vitest';
import { pickTopCandidate, shouldRefuseFrame } from './contextMenu';
import type { EntryMatchMetadata } from './contentScriptMessages';

describe('shouldRefuseFrame (T-18-07, XSEC-01 consistency)', () => {
  it('refuses when frameId is a nonzero sub-frame id', () => {
    expect(shouldRefuseFrame(2)).toBe(true);
  });

  it('proceeds when frameId is 0 (top frame)', () => {
    expect(shouldRefuseFrame(0)).toBe(false);
  });

  it('proceeds when frameId is undefined (older Chrome that omits it)', () => {
    expect(shouldRefuseFrame(undefined)).toBe(false);
  });
});

describe('pickTopCandidate (Open Question 1 rec (a), best-effort)', () => {
  function makeCandidate(id: string, username: string): EntryMatchMetadata {
    return { id, title: 'Example', username, domainHint: 'example.com' };
  }

  it('returns null for an empty candidate list', () => {
    expect(pickTopCandidate([])).toBeNull();
  });

  it('returns the FIRST candidate id/username for a non-empty list, preserving app-side order', () => {
    const candidates = [makeCandidate('id-1', 'alice'), makeCandidate('id-2', 'bob')];
    expect(pickTopCandidate(candidates)).toEqual({ id: 'id-1', username: 'alice' });
  });
});
