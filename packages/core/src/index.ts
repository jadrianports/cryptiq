// packages/core/src/index.ts
//
// THE PUBLIC `@cryptiq/core` API SURFACE (the `.` subpath). DC-8: a verb-first functional
// API — the vault VERBS (createVault/unlockVault/saveVault/changeMasterPassword/
// addWrappedKey/removeWrappedKey) + the UnlockedVault data interface, the DC-9 typed error
// classes, and the on-disk format types. The raw crypto PRIMITIVES (sodium/kdf/aead/wrap/
// recovery/padding) are deliberately NOT re-exported here — they live behind the
// `@cryptiq/core/internal` subpath (see internal.ts, DC-12) so the public surface stays the
// small "bytes in, bytes out" verb set Phase 3 / Phase 4 consume.

export * from './storage/VaultStorageAdapter';
export * from './config/types';
export * from './config/config';

// Phase 2 public surface (DC-8 / DC-9):
export * from './errors';
export * from './vault/format';
export * from './vault/serialize';
export * from './vault/vault';
export * from './vault/migrations/types';
export * from './vault/migrations/index';

// Phase 3 public surface:
// Entries — types, CRUD verbs, UUID helper, password-age utility
export * from './entries/types';
export * from './entries/crud';
export * from './entries/uuid';
// Generator — options types, defaults, and verb exports
export * from './generator/types';
export * from './generator/random';
export * from './generator/passphrase';
export * from './generator/entropy';
// Storage — pure lock-decision seam (consumed by TauriVaultStorageAdapter)
export * from './storage/lockLogic';

// Phase 6 public surface:
// Import pipeline — types, mappers, detection, mapping, dedup, normalization
export * from './import/types';
export * from './import/mappers';
export * from './import/detect';
export * from './import/map';
export * from './import/dedup';
export * from './import/normalize';
// Audit — types and orchestration verb
export * from './audit/types';
export * from './audit/audit';

// Phase 8 public surface:
// Sync merge engine — pure merge verb, types, and duplicate-detection helper
export * from './sync/types';
export * from './sync/merge';
export * from './sync/duplicate';
// Note: merge errors (MergeClockSkewError, MergeSchemaMismatchError, MergeInvalidInputError)
// are in ./errors (already exported above by the Phase 2 block on line 16).
// They are deliberately NOT re-exported here to avoid a duplicate-export conflict (TS2308).

// Phase 9 public surface:
// Pairing code validator + D-18 unlock guard (pure core, no Tauri/Svelte/node imports).
// Note: pairing errors (PairingCodeInvalidError, PairingRequiresUnlockError, etc.)
// are in ./errors (already exported above). Not re-exported here to avoid TS2308.
export * from './sync/pairingCode';
