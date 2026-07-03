// apps/extension/src/lib/captureBuffer.test.ts
//
// fake-browser (wxt/testing/fake-browser) provides in-memory
// chrome.storage.session + chrome.action implementations. Reset between
// tests per the associationStore.test.ts precedent so each test starts
// clean.

import { beforeEach, describe, expect, it } from 'vitest';
import { fakeBrowser } from 'wxt/testing/fake-browser';
import { captureKey, clearCaptureForTab, readCapture, writeCapture, type CaptureBufferEntry } from './captureBuffer';

function makeEntry(overrides: Partial<CaptureBufferEntry> = {}): CaptureBufferEntry {
  return {
    username: 'me@example.com',
    password: 'typed-password-123',
    origin: 'https://example.com',
    ts: 1720000000000,
    ...overrides,
  };
}

describe('captureBuffer', () => {
  beforeEach(() => {
    fakeBrowser.reset();
  });

  it('captureKey yields distinct keys for distinct tabIds', () => {
    expect(captureKey(1)).not.toBe(captureKey(2));
    expect(captureKey(1)).toBe(captureKey(1));
  });

  it('writeCapture then readCapture round-trips the entry including origin and password', async () => {
    const entry = makeEntry();
    await writeCapture(7, entry);

    const result = await readCapture(7);

    expect(result).toEqual(entry);
  });

  it('writing tab A does not surface under tab B', async () => {
    await writeCapture(1, makeEntry({ username: 'tab-a@example.com' }));
    await writeCapture(2, makeEntry({ username: 'tab-b@example.com' }));

    const resultA = await readCapture(1);
    const resultB = await readCapture(2);

    expect(resultA?.username).toBe('tab-a@example.com');
    expect(resultB?.username).toBe('tab-b@example.com');
  });

  it('readCapture returns null when no capture is buffered for the tab', async () => {
    const result = await readCapture(99);
    expect(result).toBeNull();
  });

  it('writeCapture lights the badge for the tab', async () => {
    await writeCapture(7, makeEntry());

    const text = await chrome.action.getBadgeText({ tabId: 7 });
    expect(text).toBe('1');
  });

  it('clearCaptureForTab clears BOTH the session buffer key and the badge', async () => {
    await writeCapture(7, makeEntry());

    await clearCaptureForTab(7);

    const result = await readCapture(7);
    expect(result).toBeNull();

    const text = await chrome.action.getBadgeText({ tabId: 7 });
    expect(text).toBe('');
  });

  it('clearCaptureForTab on a tab with no buffered capture never throws', async () => {
    await expect(clearCaptureForTab(123)).resolves.toBeUndefined();
  });
});
