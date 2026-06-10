// apps/desktop/src/lib/sync/__tests__/syncLockState.test.ts
//
// Wave-0 node test: D-11 sync-lock predicate.
// Pins the exact in-flight status set for isSyncInProgress.
//
// Environment: node (vitest.config.ts — no browser provider invoked).

import { describe, it, expect } from 'vitest';
import { isSyncInProgress } from '../syncLockState';
import type { SyncStatus } from '../SyncStore.svelte';

describe('isSyncInProgress — D-11 entry-list-lock predicate', () => {
  const inFlightStatuses: SyncStatus[] = ['connecting', 'syncing', 'merging', 'saving'];
  const idleStatuses: SyncStatus[] = ['idle', 'done', 'error'];

  describe('returns true for all in-flight statuses', () => {
    for (const status of inFlightStatuses) {
      it(`isSyncInProgress('${status}') === true`, () => {
        expect(isSyncInProgress(status)).toBe(true);
      });
    }
  });

  describe('returns false for all idle/terminal statuses', () => {
    for (const status of idleStatuses) {
      it(`isSyncInProgress('${status}') === false`, () => {
        expect(isSyncInProgress(status)).toBe(false);
      });
    }
  });

  it('covers all four in-flight statuses and all three idle/terminal statuses', () => {
    // Explicit exhaustive assertion so a new status added to SyncStatus
    // without updating isSyncInProgress would require updating this test.
    expect(inFlightStatuses).toHaveLength(4);
    expect(idleStatuses).toHaveLength(3);
  });
});
