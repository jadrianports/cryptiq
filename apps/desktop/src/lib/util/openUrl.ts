// apps/desktop/src/lib/util/openUrl.ts
//
// Thin wrapper over @tauri-apps/plugin-opener for the "Open URL" action (UI-07, FLAG-1).
//
// Security contract (T-04-16):
//   - Guards https?:// BEFORE calling the plugin (belt-and-suspenders — the plugin
//     also validates against its own regex, but we check first so intent is clear).
//   - Only http and https schemes are permitted; mailto:, tel:, file:, etc. are rejected
//     silently (openInBrowser is safe to call with any user-supplied string).
//   - Does NOT use plugin-shell (broader attack surface — CLAUDE.md bans it for URL-opening).
//   - The corresponding capability is scoped to http/https only: opener:allow-open-url.

import { openUrl } from '@tauri-apps/plugin-opener';

/**
 * Open a URL in the system default browser.
 *
 * Silently no-ops for non-http(s) URLs (e.g. empty string, mailto:, file:).
 * The plugin provides a second layer of validation via its own URL regex.
 *
 * @param url  The URL to open. Must start with https:// or http://.
 */
export async function openInBrowser(url: string): Promise<void> {
  if (!/^https?:\/\//i.test(url)) return;
  await openUrl(url);
}
