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
//
// DEBT-01/W-1 (Phase 36, D-13/D-14): consent is enforced RUST-SIDE, at the `hibp_range_lookup`
// seam itself — NOT here. This file is the exact DI seam where a TS choke-point wrapper adding
// a consent check was explicitly REJECTED (D-14): anything reaching invoke() directly still
// egresses, which would relocate W-1 rather than close it. This adapter's only job is to
// forward `{ prefix, purpose }` to the real Rust command unchanged — do not add a config/
// consent read here.

import { invoke } from '@tauri-apps/api/core';
import type { HibpInvoke } from '@cryptiq/core';

/** Production HibpInvoke: shuttles the 5-char SHA-1 prefix to the Rust `hibp_range_lookup` command. */
export const hibpInvoke: HibpInvoke = (cmd, args) => invoke<string>(cmd, args);
