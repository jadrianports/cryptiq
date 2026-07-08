// apps/extension/src/lib/icons.ts
//
// Phase 27 (XUI-02, D-02/D-03/D-04/D-05): hand-authored, zero-dependency
// entry-type iconography for the popup's picker/search rows. Mirrors the
// desktop's `TYPE_ICON: Record<Entry['type'], string>` naming/shape
// convention (apps/desktop/src/lib/components/typeIcons.ts, Phase 23) --
// same idea (a per-type constant lookup), NOT the same glyph style: the
// desktop's icons are solid 24x24 `fill="currentColor"` path data; these are
// thin-stroke ~16px line icons (`stroke="currentColor" fill="none"`, D-02),
// matching the popup's more restrained surface.
//
// Redeclares the fillable-type union inline rather than importing
// `packages/core/src/entries/types.ts`'s `Entry['type']` -- apps/extension is
// a thin client with no `@cryptiq/core` workspace dependency (CLAUDE.md).
//
// `secure-note` intentionally has NO entry in `TYPE_ICON` (D-04 -- it is not
// a fillable type; `fill-entry` returns `not-found` for it). `iconForType`
// returns `undefined` for it rather than a bespoke glyph.
//
// Every glyph is mono-color `currentColor` -- callers MUST wrap the rendered
// markup in an element using a muted text token (`text-cryptiq-fg-muted` /
// `text-cryptiq-fg-subtle`), NEVER `text-cryptiq-accent` (D-05). This module
// has no opinion on color itself -- it only emits `currentColor`-based SVG
// strings, so the wrapping element's class is what actually colors them.

/** The three fillable entry types this popup renders an icon for.
 * `secure-note` is deliberately excluded (D-04) -- see `iconForType` below. */
export type FillableType = 'login' | 'card' | 'identity';

/**
 * Hand-authored inline-SVG glyph strings, keyed by fillable type (D-02/D-03).
 * Each is a ~16px line-style icon: `stroke="currentColor" fill="none"`,
 * `stroke-width="1.5"`, rounded joins -- no hardcoded hex, no `fill` other
 * than `none`, never the accent (D-05, enforced by the wrapping element's
 * class, not this constant).
 *
 * login = key, card = credit card, identity = ID badge (per CONTEXT.md's
 * icon legend).
 */
const TYPE_ICON: Record<FillableType, string> = {
  login:
    '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="8" cy="15" r="3.25"/><path d="M10.3 12.7 18 5m0 0h-3.5M18 5v3.5"/></svg>',
  card: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="6" width="18" height="12" rx="2"/><path d="M3 10h18"/><path d="M6.5 14.5h4"/></svg>',
  identity:
    '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="4.5" width="16" height="15" rx="2"/><circle cx="12" cy="10.5" r="2.25"/><path d="M8.25 16.5c.6-1.8 2-2.5 3.75-2.5s3.15.7 3.75 2.5"/></svg>',
};

/**
 * Pure icon selector: returns the hand-authored inline-SVG markup for a
 * fillable type, or `undefined` for `secure-note` (D-04 -- no bespoke glyph;
 * a neutral alignment placeholder, if the row layout needs one, is a
 * popup-layout concern handled by the caller, not this module).
 */
export function iconForType(type: 'login' | 'card' | 'identity' | 'secure-note'): string | undefined {
  if (type === 'secure-note') return undefined;
  return TYPE_ICON[type];
}

/**
 * WR-01 (27-05 follow-up): is this entry type fillable? True for
 * login/card/identity, false for `secure-note`. The popup's full-vault search
 * rows gate their Fill button on this -- a secure-note's `fill-entry` returns
 * `not-found` (rpcDispatch.ts D-04), so an ungated Fill button on those rows
 * always errors. Mirrors `iconForType`'s fillable/non-fillable split exactly
 * (a type is fillable iff it has a bespoke glyph); the shared `FillableType`
 * union keeps the two in lockstep if a future type is added.
 */
export function isFillableType(type: 'login' | 'card' | 'identity' | 'secure-note'): type is FillableType {
  return type !== 'secure-note';
}
