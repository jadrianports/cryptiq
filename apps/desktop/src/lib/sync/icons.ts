// apps/desktop/src/lib/sync/icons.ts
//
// Inline SVG path constants for sync UI (D-04 / D-13).
// Follows the Sidebar.svelte inline-constant pattern (lines 49-78).
//
// All paths are for viewBox="0 0 24 24" fill="currentColor".
// No imports, no runtime logic — pure constants.
//
// Source: 12-PATTERNS.md "icons.ts (NEW)", 12-UI-SPEC.md §"Sync Icon".

/**
 * Circular-arrows sync icon path (D-04 header Sync Now button).
 *
 * This is the SAME path as the Sidebar "Needs update" filter icon — the header
 * Sync Now button uses the same visual vocabulary as the "Needs update" filter
 * to signal "refresh / sync".
 *
 * viewBox="0 0 24 24" fill="currentColor"
 */
export const SYNC_ICON_PATH =
  'M12 4V1L8 5l4 4V6c3.31 0 6 2.69 6 6a5.96 5.96 0 0 1-1.12 3.52l1.46 1.46A7.93 7.93 0 0 0 20 12c0-4.42-3.58-8-8-8zm0 14c-3.31 0-6-2.69-6-6a5.96 5.96 0 0 1 1.12-3.52L5.66 7.02A7.93 7.93 0 0 0 4 12c0 4.42 3.58 8 8 8v3l4-4-4-4v3z';
