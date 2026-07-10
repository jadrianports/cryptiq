// apps/desktop/src/lib/adapters/hibpInvoke.ts
//
// Dependency-injected `HibpInvoke` adapter binding @tauri-apps/api/core's `invoke`
// to the core `HibpInvoke` seam type (Phase 30, LOCKED). Mirrors the exact
// dependency-injection shape already used by TauriVaultStorageAdapter.ts
// (`invoke('vault_write_atomic', ...)` called directly) — no new pattern.
//
// No new Tauri capability entry needed: `hibp_range_lookup` is an app-defined
// #[tauri::command], already invokable under `core:default` (confirmed by
// Phase 30's zero-diff capabilities verification — 31-RESEARCH.md section 1).

import { invoke } from '@tauri-apps/api/core';
import type { HibpInvoke } from '@cryptiq/core';

/** Production HibpInvoke: shuttles the 5-char SHA-1 prefix to the Rust `hibp_range_lookup` command. */
export const hibpInvoke: HibpInvoke = (cmd, args) => invoke<string>(cmd, args);
