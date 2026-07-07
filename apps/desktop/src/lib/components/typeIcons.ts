// apps/desktop/src/lib/components/typeIcons.ts
//
// Inline SVG path constants for per-type entry icons (D-11 / D-12).
// Follows the sync/icons.ts + Sidebar.svelte inline-constant idiom.
//
// All paths are for viewBox="0 0 24 24" fill="currentColor".
// No imports beyond the Entry type, no runtime logic — pure constants.

import type { Entry } from '@cryptiq/core';

/**
 * Per-type icon path map keyed by Entry['type'].
 *
 * VisualIdentity only renders the icon for non-login types (login keeps its
 * letter/gradient tile) — the `login` entry exists purely to satisfy
 * Record<Entry['type'], string> completeness.
 */
export const TYPE_ICON: Record<Entry['type'], string> = {
  // Key / lock glyph — unused by VisualIdentity today (login keeps the letter
  // tile) but present for Record completeness.
  login:
    'M12 17a2 2 0 0 0 2-2 2 2 0 0 0-2-2 2 2 0 0 0-2 2 2 2 0 0 0 2 2zm6-9a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V10a2 2 0 0 1 2-2h1V6a5 5 0 0 1 10 0v2h1zM12 3a3 3 0 0 0-3 3v2h6V6a3 3 0 0 0-3-3z',
  // Credit-card glyph.
  card: 'M20 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 14H4v-6h16v6zm0-10H4V6h16v2z',
  // Person / ID card glyph.
  identity:
    'M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z',
  // Document glyph.
  'secure-note':
    'M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z',
};
