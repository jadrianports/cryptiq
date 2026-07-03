// apps/extension/src/lib/neverSaveStore.test.ts
//
// fake-browser (wxt/testing/fake-browser) provides an in-memory
// chrome.storage.local implementation. Reset between tests per the
// associationStore.test.ts precedent.

import { beforeEach, describe, expect, it } from 'vitest';
import { fakeBrowser } from 'wxt/testing/fake-browser';
import { isNeverSave, markNeverSave } from './neverSaveStore';

describe('neverSaveStore', () => {
  beforeEach(() => {
    fakeBrowser.reset();
  });

  it('isNeverSave returns false for an unmarked domain', async () => {
    const result = await isNeverSave('example.com');
    expect(result).toBe(false);
  });

  it('markNeverSave then isNeverSave returns true for that domain', async () => {
    await markNeverSave('example.com');

    const result = await isNeverSave('example.com');

    expect(result).toBe(true);
  });

  it('marking one domain does not mark another', async () => {
    await markNeverSave('example.com');

    const marked = await isNeverSave('example.com');
    const unmarked = await isNeverSave('other.com');

    expect(marked).toBe(true);
    expect(unmarked).toBe(false);
  });

  it('marking a second domain preserves the first', async () => {
    await markNeverSave('example.com');
    await markNeverSave('other.com');

    expect(await isNeverSave('example.com')).toBe(true);
    expect(await isNeverSave('other.com')).toBe(true);
  });
});
