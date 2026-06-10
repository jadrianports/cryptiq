// apps/desktop/src/lib/sync/syncLockState.ts
//
// Pure lock-state predicate for the D-11 entry-list lock (UI-17).
//
// Consumed by:
//   - Plan 12-04 MainView.svelte: `pointer-events-none opacity-60` on the entry list
//     and the Sync Now header button in-progress state.
//   - SyncNowButton.svelte: disabled state + spinner icon.
//
// The predicate is a pure function (no store import) so it is trivially testable
// in node mode without mocking the store.
//
// Source: 12-01-PLAN.md Task 1, 12-CONTEXT.md D-11, 12-PATTERNS.md §MainView.

import type { SyncStatus } from './SyncStore.svelte';

/**
 * Returns true when a sync operation is actively in-flight (D-11).
 *
 * In-flight statuses: 'connecting' | 'syncing' | 'merging' | 'saving'
 * Idle/terminal statuses: 'idle' | 'done' | 'error'
 *
 * This is the canonical predicate for:
 *   - Disabling/locking the entry list and entry detail pane
 *   - Showing the spinner state on the Sync Now button
 *   - Disabling the Sync Now button to prevent concurrent syncs
 *
 * @param status The current SyncStatus from syncStore.status.
 * @returns      true when a sync is in-flight; false otherwise.
 */
export function isSyncInProgress(status: SyncStatus): boolean {
  return (
    status === 'connecting' ||
    status === 'syncing' ||
    status === 'merging' ||
    status === 'saving'
  );
}
