// packages/core/src/import/normalize.ts
//
// Row normalization for the CSV import pipeline (IMPORT-06).
//
// `normalizeRow` converts a `MappedRow` into an `EntryInput` suitable for
// passing to `addEntry()` in entries/crud.ts. It is the final pure-core step
// before the desktop wizard hands entries off to `VaultSession.addEntry()`.
//
// CSPRNG UUID note (IMPORT-06): The comment below explains the responsibility
// split. `normalizeRow` does NOT generate the UUID itself — that is done by
// `addEntry()` via `uuidV4FromBytes(sodium.randombytes_buf(16))` (P3-03).
// The `getSodium()` call here is included to warm the WASM module and confirm
// the sodium instance is available; it also documents the dependency for any
// future extension where normalize might need sodium directly (e.g. MAC-tagged
// source provenance). For now it is a no-op warm-up.
//
// Core purity: no @tauri-apps/*, svelte, node:fs, node:path imports.
// No console.*, no Math.random.
// getSodium() is the ONLY libsodium entry point (no raw libsodium-wrappers-sumo).

import { getSodium } from '../crypto/sodium';
import type { EntryInput } from '../entries/types';
import type { MappedRow } from './types';

/**
 * Normalize a `MappedRow` into an `EntryInput` ready for `addEntry()`.
 *
 * The returned `EntryInput` contains the five string fields from the mapped row.
 * `addEntry()` in `entries/crud.ts` assigns the CSPRNG-backed UUID (`id`),
 * `type: 'login'`, `createdAt`, `modifiedAt`, and initialises `passwordHistory`
 * to `[]` (IMPORT-06 — CSPRNG UUID is addEntry's responsibility, not this fn's).
 *
 * `password` and `notes` survive verbatim from the `MappedRow` — no mutation
 * is applied here either (IMPORT-08 / Pitfall 4 carry-through).
 *
 * @param row The `MappedRow` produced by `mapRow()`.
 * @returns   A `Promise<EntryInput>` (async to warm the sodium WASM module).
 */
export async function normalizeRow(row: MappedRow): Promise<EntryInput> {
  // Warm the WASM module. This is a no-op if already initialised (getSodium() memoises).
  // Keeping it here documents that the import pipeline depends on sodium being ready,
  // and ensures the caller doesn't need an out-of-band getSodium() call.
  await getSodium();

  // NOTE: id / createdAt / modifiedAt / passwordHistory / type are all set by addEntry().
  // normalizeRow only produces the user-visible content fields (EntryInput).
  return {
    title:    row.title,
    username: row.username,
    password: row.password, // verbatim (IMPORT-08 — no leading-quote prefix)
    url:      row.url,
    notes:    row.notes,    // verbatim (IMPORT-08)
  };
}
