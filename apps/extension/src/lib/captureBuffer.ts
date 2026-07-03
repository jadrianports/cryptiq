// apps/extension/src/lib/captureBuffer.ts
//
// Plan 19-02: the SHARED cross-entrypoint capture-buffer module. This lives
// in src/lib/ -- NOT in entrypoints/background.ts -- because BOTH
// entrypoints/background.ts (Plan 03, the writer that buffers a captured
// credential + lights the toolbar badge) and entrypoints/popup/Popup.svelte
// (Plan 04, the dismissal/clear caller) import it; entrypoints/* files may
// never import each other (this codebase's 100%-consistent convention:
// cross-context shared helpers live in src/lib/, popup<->background
// otherwise talk via runtime messages). Both callers are legitimate direct
// users of chrome.storage.session/chrome.action, so this is correct module
// placement, not a message round-trip.
//
// Wraps ONLY chrome.storage.session (memory-only, survives an MV3 SW
// restart, cleared on browser restart, never disk) + chrome.action (toolbar
// badge). Holds a transient in-flight password only in this memory-backed
// storage area -- never chrome.storage.local (that is disk-backed and
// reserved for neverSaveStore's persistent domain map, T-19-09). No vault
// key ever touches this module (thin-client boundary).
//
// Deliberately does NOT call chrome.storage.session.setAccessLevel(...) --
// leaves the default extension-context-only access level (T-19-08) so
// page/content-script JS cannot read the buffered password back out.

const CAPTURE_KEY_PREFIX = 'cryptiq-capture';

/** Per-tab key space -- writing under tab A never surfaces under tab B. */
export function captureKey(tabId: number): string {
  return `${CAPTURE_KEY_PREFIX}:${tabId}`;
}

/**
 * The buffered capture pair. `origin` is load-bearing for Plan 04's TOCTOU
 * recheck (the popup re-derives the active tab's current origin and refuses
 * to offer save/update if it no longer matches). `password` is the one
 * transient secret this module handles -- NEVER logged (Pitfall 6: any
 * future diagnostic must redact to `{ username, origin, hasPassword: true }`).
 */
export interface CaptureBufferEntry {
  username: string;
  password: string;
  origin: string;
  ts: number;
}

/** Buffer a captured credential for a tab and light the toolbar badge. */
export async function writeCapture(tabId: number, entry: CaptureBufferEntry): Promise<void> {
  await chrome.storage.session.set({ [captureKey(tabId)]: entry });
  await chrome.action.setBadgeText({ text: '1', tabId });
  await chrome.action.setBadgeBackgroundColor({ color: '#a15c00', tabId });
}

/** Read back a tab's buffered capture, or null if none -- never throws. */
export async function readCapture(tabId: number): Promise<CaptureBufferEntry | null> {
  try {
    const existing = await chrome.storage.session.get(captureKey(tabId));
    const stored = existing[captureKey(tabId)] as CaptureBufferEntry | undefined;
    return stored ?? null;
  } catch {
    return null;
  }
}

/**
 * The SINGLE clear-together seam (Pitfall 5 / SC-3 no-ghost-prompt): removes
 * both the session buffer key AND the toolbar badge so the two states never
 * drift apart. Both background.ts's own tab-close/replace path and every
 * Plan-04 dismissal path (save, discard, never-save-this-domain) route
 * through THIS function -- never a partial clear of just one side. Never
 * throws (e.g. the tab may already be closed by the time this runs).
 */
export async function clearCaptureForTab(tabId: number): Promise<void> {
  try {
    await chrome.storage.session.remove(captureKey(tabId));
  } catch {
    // Best-effort -- nothing left to clear.
  }
  try {
    await chrome.action.setBadgeText({ text: '', tabId });
  } catch {
    // Tab may already be closed -- nothing left to un-badge.
  }
}
