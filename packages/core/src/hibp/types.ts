// packages/core/src/hibp/types.ts
//
// Phase 36 — DEBT-01/W-1. Shared HIBP seam types: the purpose discriminator that lets the Rust
// `hibp_range_lookup` command enforce consent AT THE SEAM (D-13) rather than at the call site,
// and the injected `HibpInvoke` shape `lookupHibpRange` calls through (D-07 dependency
// injection, matches the VaultStorageAdapter injection precedent in storage/).
//
// `HibpLookupPurpose` reuses HibpConsentDialog.svelte's EXISTING 'entry-scan'/'master-check'
// vocabulary verbatim — do not invent a second vocabulary for the same two concepts. The two
// underlying consent flags (hibpEntryScanEnabled / hibpMasterCheckEnabled) are deliberately
// INDEPENDENT (Phase 31 D-16): `purpose` selects WHICH consent field governs a given call. It is
// a closed two-value enum, never a widening egress parameter — see hibp.rs's header comment for
// the full rationale on why this does not erode the module's "no url/host/endpoint parameter"
// discipline (Pitfall 3).
//
// Core purity: no @tauri-apps/*, svelte, node:fs, node:path imports.

/** The two HIBP consent purposes, gating hibpEntryScanEnabled / hibpMasterCheckEnabled respectively. */
export type HibpLookupPurpose = 'entry-scan' | 'master-check';

/** The shape of an injected Tauri `invoke`-like function (D-07 dependency injection). */
export type HibpInvoke = (
  cmd: string,
  args: { prefix: string; purpose: HibpLookupPurpose },
) => Promise<string>;
