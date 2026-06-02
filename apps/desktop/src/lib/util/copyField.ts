// apps/desktop/src/lib/util/copyField.ts
//
// Write-only clipboard copy for per-field copy actions (UI-06, T-04-17).
//
// Security contract:
//   - For 'password' kind: routes through the Rust `clipboard_write_sensitive` command
//     which writes text, injects sensitive platform markers (Windows exclusion formats,
//     macOS concealed/transient types), and stashes a hash — all in Rust. The JS side
//     never reads back the clipboard (LOCK-02/06 / P5-08).
//   - For 'other' kind (username, URL, notes): calls writeText ONLY — never readText
//     (CLAUDE.md hard ban: clipboard is write-only from JS).
//   - `clipboard-manager:allow-write-text` capability is already granted in default.json.
//   - `clipboard-manager:allow-read-text` is NOT added here or anywhere in the project.
//   - The still-ours read for auto-clear is Rust-side only (clipboard_clear_if_ours).
//   - The 25s auto-clear timer lives in the clipboardGuard module (survives component unmount);
//     ClipboardToast is value-free — it reads only the countdown state, never the copied value.

import { writeText } from '@tauri-apps/plugin-clipboard-manager';
import { invoke } from '@tauri-apps/api/core';

/**
 * Discriminates which clipboard path to use.
 * 'password' → Rust clipboard_write_sensitive (markers + stash).
 * 'other'    → plain writeText plugin (username, URL, notes).
 */
export type CopyKind = 'password' | 'other';

/**
 * Write a field value to the system clipboard (write-only from JS).
 *
 * For password copies, routes through the Rust command which sets platform-sensitive
 * markers and stashes a hash for the still-ours auto-clear check. No value is returned.
 *
 * For other fields (username, URL, notes), uses the clipboard-manager plugin writeText path.
 * Both paths never read the clipboard from JS.
 *
 * @param value  The string to copy.
 * @param kind   'password' to arm Rust markers + stash; 'other' (default) for plain write.
 */
export async function copyField(value: string, kind: CopyKind = 'other'): Promise<void> {
  if (kind === 'password') {
    // Route through Rust: writes text + injects sensitive markers + stashes a hash.
    // Returns Ok(()) — no payload carries the secret back to JS.
    // Caller arms clipboardGuard (the auto-clear timer) and mounts the value-free ClipboardToast.
    await invoke('clipboard_write_sensitive', { value });
  } else {
    // Non-sensitive fields: existing plugin path (username, URL, notes).
    await writeText(value);
  }
}
