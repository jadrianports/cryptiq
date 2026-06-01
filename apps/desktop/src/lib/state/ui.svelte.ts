// apps/desktop/src/lib/state/ui.svelte.ts
//
// Shared UI state (UI-12 / P4-11): toast queue, selected-entry ID, search query.
// These hold no secret data — plain $state (NOT $state.raw) is correct here.
//
// Toast IDs use a module-scoped incrementing counter — NO Math.random (T-04-02 /
// project-wide Math.random ban). The counter is not exposed externally.

/** A single toast notification. */
export interface Toast {
  id: string;
  msg: string;
}

/** Monotonically incrementing counter for generating unique toast IDs. */
let _counter = 0;

/**
 * The active list filter applied in the center entry list.
 *
 * all              — active (non-deleted) entries (default)
 * favorites        — active entries with favorite === true
 * needs-update     — active entries with needsSiteUpdate === true (UI-09)
 * recently-deleted — tombstoned entries (deletedAt !== null); read-only in Phase 4 (ENTRY-05)
 */
export type ListFilter = 'all' | 'favorites' | 'needs-update' | 'recently-deleted';

/**
 * Shared UI state singleton. Plain $state — nothing here is secret data.
 *
 * toasts          — queue of active toast notifications (UI-12 / P4-11).
 * selectedEntryId — the ID of the currently selected entry (null = nothing selected).
 * searchQuery     — live search / filter string (debounced by the consumer, UI-04).
 * listFilter      — the active list filter (P4-04 sidebar, UI-09, ENTRY-05).
 */
export const ui = $state({
  toasts: [] as Toast[],
  selectedEntryId: null as string | null,
  searchQuery: '',
  listFilter: 'all' as ListFilter,
});

/**
 * Push a toast notification onto the queue.
 *
 * The ID is generated via a monotonic counter — never Math.random (T-04-02).
 * The caller is responsible for scheduling removal (via clearToast) or relying on
 * the Toast.svelte $effect timer (D-TIMING: 2000ms).
 *
 * @param msg   The human-readable message to display.
 */
export function pushToast(msg: string): void {
  const id = String(_counter++);
  ui.toasts = [...ui.toasts, { id, msg }];
}

/**
 * Remove a toast from the queue by ID.
 * Idempotent: removing a non-existent ID is a no-op.
 */
export function clearToast(id: string): void {
  ui.toasts = ui.toasts.filter((t) => t.id !== id);
}
