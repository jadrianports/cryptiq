// packages/core/src/internal.ts
//
// Barrel for the `@cryptiq/core/internal` subpath export (DC-12).
//
// Purpose: expose the crypto primitives + typed errors to the per-checkpoint demo
// scripts (scripts/demo/02-<N>-<name>.mjs) and the KAT tests WITHOUT enlarging the
// main `.` public API surface (which only re-exports the verb-first vault API + errors).
//
// This barrel grows as each Phase 2 wave lands its primitive:
//   Wave 1 (this plan): sodium, kdf, errors
//   Wave 2: + aead, wrap
//   Wave 3: + recovery, padding, vault/format, vault/serialize
//   Wave 4: + vault/migrations
//
// NOTE: crypto/sodium and crypto/kdf re-exports are added in Tasks 2 and 3 of this plan
// as those modules are created. For Wave 0 (pre-checkpoint) only ./errors existed.
export * from './errors';
export * from './crypto/sodium';
export * from './crypto/kdf';
export * from './crypto/aead';
export * from './crypto/wrap';
