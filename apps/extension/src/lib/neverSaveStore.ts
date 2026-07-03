// apps/extension/src/lib/neverSaveStore.ts
//
// Plan 19-02: registrable-domain-keyed never-save suppression store (CAP-04,
// D-04). Mirrors associationStore.ts's single-constant-key get-with-default
// idiom. Uses chrome.storage.local (disk-backed, persistent) -- correct for
// a durable user preference, in deliberate contrast to captureBuffer.ts's
// chrome.storage.session (memory-only, reserved for the transient in-flight
// credential pair, T-19-09).
//
// Keys by the SAME `registrableDomain` string Plan 01's matchByOrigin surfaces
// on match-origin (packages/core/src/entries/matchByOrigin.ts), so the
// never-save key space is identical to the match key space by construction
// (D-04, T-19-07) -- this module does not compute a second eTLD+1 lookup.
//
// Pure of DOM/Svelte; depends only on chrome.storage.local. No vault key ever
// touches this module (thin-client boundary) -- it is a transport-only store.

const NEVER_SAVE_KEY = 'cryptiq-never-save';

/**
 * Whether the given registrable domain has been marked "never save" by the
 * user. Never throws; an unmarked or unknown domain returns false.
 */
export async function isNeverSave(domain: string): Promise<boolean> {
  const existing = await chrome.storage.local.get(NEVER_SAVE_KEY);
  const map = (existing[NEVER_SAVE_KEY] as Record<string, true> | undefined) ?? {};
  return map[domain] === true;
}

/** Mark a registrable domain as "never save" (persists across SW restarts). */
export async function markNeverSave(domain: string): Promise<void> {
  const existing = await chrome.storage.local.get(NEVER_SAVE_KEY);
  const map = (existing[NEVER_SAVE_KEY] as Record<string, true> | undefined) ?? {};
  map[domain] = true;
  await chrome.storage.local.set({ [NEVER_SAVE_KEY]: map });
}
