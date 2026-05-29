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
