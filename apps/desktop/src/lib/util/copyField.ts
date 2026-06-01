// apps/desktop/src/lib/util/copyField.ts
//
// Write-only clipboard copy for per-field copy actions (UI-06, T-04-17).
//
// Security contract:
//   - Calls writeText ONLY — never readText (CLAUDE.md hard ban: clipboard is write-only).
//   - The `clipboard-manager:allow-write-text` capability is already granted in default.json.
//   - `clipboard-manager:allow-read-text` is NOT added here or anywhere in the project.
//   - Auto-clear UX (LOCK-02/06) is Phase 5 — this plan wires per-field write only.

import { writeText } from '@tauri-apps/plugin-clipboard-manager';

/**
 * Write a secret field value to the system clipboard (write-only).
 *
 * Safe to call with any string — never reads back the clipboard.
 * The returned promise resolves when the OS clipboard has been updated.
 *
 * @param value  The string to copy. Typically a password, username, or URL.
 */
export async function copyField(value: string): Promise<void> {
  await writeText(value);
}
