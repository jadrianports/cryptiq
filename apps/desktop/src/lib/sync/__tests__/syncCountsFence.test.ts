// apps/desktop/src/lib/sync/__tests__/syncCountsFence.test.ts
//
// Wave-0 node test: UI-18 counts-only fence.
// Asserts that formatSyncSummary emits ONLY integer counts + static labels —
// never entry titles, usernames, passwords, or URLs.
//
// Environment: node (vitest.config.ts — no browser provider invoked).

import { describe, it, expect } from 'vitest';
import { formatSyncSummary, formatRelativeLastSynced } from '../syncFormat';

describe('formatSyncSummary — counts-only fence (UI-18)', () => {
  it('formats a non-zero-change sync correctly', () => {
    const result = formatSyncSummary({ added: 2, updated: 1, deleted: 0, unchanged: 47 });
    expect(result).toBe('Synced — 2 added, 1 updated, 0 deleted, 47 unchanged');
  });

  it('matches the exact regex contract', () => {
    const result = formatSyncSummary({ added: 2, updated: 1, deleted: 0, unchanged: 47 });
    expect(result).toMatch(/^Synced — \d+ added, \d+ updated, \d+ deleted, \d+ unchanged$/);
  });

  it('returns "Already up to date." when added, updated, deleted are all 0', () => {
    const result = formatSyncSummary({ added: 0, updated: 0, deleted: 0, unchanged: 100 });
    expect(result).toBe('Already up to date.');
  });

  it('returns the summary string when unchanged is 0 but other counts are non-zero', () => {
    const result = formatSyncSummary({ added: 1, updated: 0, deleted: 0, unchanged: 0 });
    expect(result).toBe('Synced — 1 added, 0 updated, 0 deleted, 0 unchanged');
    expect(result).toMatch(/^Synced — \d+ added, \d+ updated, \d+ deleted, \d+ unchanged$/);
  });

  it('contains no http patterns (UI-18 fence — no URL interpolation)', () => {
    const result = formatSyncSummary({ added: 2, updated: 1, deleted: 0, unchanged: 47 });
    expect(result).not.toMatch(/https?:\/\//);
  });

  it('contains no entry-field tokens (UI-18 fence)', () => {
    // Even with large counts, no entry data should appear.
    const result = formatSyncSummary({ added: 999, updated: 888, deleted: 777, unchanged: 666 });
    // The output must only contain the static template tokens and integers.
    expect(result).toMatch(/^Synced — \d+ added, \d+ updated, \d+ deleted, \d+ unchanged$/);
    // Must not contain quote chars that would appear around entry titles.
    expect(result).not.toContain('"');
    expect(result).not.toContain("'");
    // Must not contain colon (would appear in URLs like https://...).
    // (The dash in "Synced —" is an em-dash, not a colon.)
    expect(result).not.toContain('://');
  });

  it('handles large counts without overflow or entry-data leak', () => {
    const result = formatSyncSummary({
      added: 1000000,
      updated: 999999,
      deleted: 500000,
      unchanged: 0,
    });
    expect(result).toMatch(/^Synced — \d+ added, \d+ updated, \d+ deleted, \d+ unchanged$/);
  });
});

describe('formatRelativeLastSynced — D-16 relative time', () => {
  const now = new Date('2024-06-01T12:00:00.000Z').getTime();

  it('returns "Never synced" for null', () => {
    expect(formatRelativeLastSynced(null, now)).toBe('Never synced');
  });

  it('returns "Never synced" for empty string', () => {
    expect(formatRelativeLastSynced('', now)).toBe('Never synced');
  });

  it('returns "Last synced just now" for a timestamp within the last 60 seconds', () => {
    const ts = new Date(now - 30 * 1000).toISOString();
    expect(formatRelativeLastSynced(ts, now)).toBe('Last synced just now');
  });

  it('returns "Last synced just now" for a timestamp 0 seconds ago', () => {
    const ts = new Date(now).toISOString();
    expect(formatRelativeLastSynced(ts, now)).toBe('Last synced just now');
  });

  it('returns minutes for 1-59 minutes ago', () => {
    const ts2Min = new Date(now - 2 * 60 * 1000).toISOString();
    expect(formatRelativeLastSynced(ts2Min, now)).toBe('Last synced 2 minutes ago');

    const ts1Min = new Date(now - 61 * 1000).toISOString();
    expect(formatRelativeLastSynced(ts1Min, now)).toBe('Last synced 1 minute ago');
  });

  it('returns hours for 1-23 hours ago', () => {
    const ts2h = new Date(now - 2 * 60 * 60 * 1000).toISOString();
    expect(formatRelativeLastSynced(ts2h, now)).toBe('Last synced 2 hours ago');

    const ts1h = new Date(now - 61 * 60 * 1000).toISOString();
    expect(formatRelativeLastSynced(ts1h, now)).toBe('Last synced 1 hour ago');
  });

  it('returns days for 24+ hours ago', () => {
    const ts2d = new Date(now - 2 * 24 * 60 * 60 * 1000).toISOString();
    expect(formatRelativeLastSynced(ts2d, now)).toBe('Last synced 2 days ago');

    const ts1d = new Date(now - 25 * 60 * 60 * 1000).toISOString();
    expect(formatRelativeLastSynced(ts1d, now)).toBe('Last synced 1 day ago');
  });
});
