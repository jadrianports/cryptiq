// apps/desktop/src/tests/fixtures/fakeAdapter.ts
//
// FakeVaultStorageAdapter — in-memory implementation of the TauriVaultStorageAdapter
// interface used exclusively in component tests (Layer-2 / TEST-09).
//
// SECURITY BOUNDARY (T-04-05):
//   - Stores only test bytes in memory — no real secrets, no filesystem writes, no network.
//   - Performs NO crypto (no Argon2id, no AEAD, no libsodium calls).
//   - Issues NO Tauri `invoke` calls — no @tauri-apps/api/core dependency whatsoever.
//
// SURFACE (mirrors what VaultSession actually calls on the adapter):
//   vaultPath      — getter, returns the configured test path string
//   vaultLabel     — getter, same as vaultPath (for VaultStorageAdapter compat)
//   load()         — returns the stored bytes (or empty Uint8Array if none)
//   save(bytes,opts)— stores bytes, increments saveCount, records lastSavedBytes
//   isSaving       — getter, always false (synchronous fake mutex)
//   awaitSaveMutex()— returns Promise.resolve() immediately
//   initLastSavedHash(hash) — records the hash, no-op side-effect
//
// SPY FIELDS (for test assertions):
//   saveCount      — how many times save() was called (asserts UI-12 dedup behavior)
//   lastSavedBytes — the last bytes passed to save() (asserts content was persisted)
//   lastContentHash— the last contentHash passed in opts (asserts dedup signal)
//   initHashCalls  — number of times initLastSavedHash was called
//
// Also exposes listBackups / loadBackup / savePreMigrationBackup to fully satisfy the
// VaultStorageAdapter interface (for type compatibility), returning safe no-ops.

import type { VaultBytes } from '@cryptiq/core';

export interface FakeSaveOpts {
  maxBackups?: number;
  contentHash?: string;
}

export class FakeVaultStorageAdapter {
  // The configured vault path (test fixture value — not a real FS path).
  readonly vaultPath: string;

  // VaultStorageAdapter compat: vaultLabel == vaultPath in this fake.
  get vaultLabel(): string {
    return this.vaultPath;
  }

  // Internal byte store — seeded via constructor, overwritten on each save().
  private _storedBytes: Uint8Array;

  // Spy fields for test assertions.
  saveCount = 0;
  lastSavedBytes: Uint8Array | null = null;
  lastContentHash: string | null = null;
  initHashCalls = 0;
  /** The last hash passed to initLastSavedHash — readable by tests for assertions. */
  lastInitHash: string | null = null;

  /**
   * @param vaultPath   Test path label (e.g. '/fake/vault.cryptiq'). Not a real FS path.
   * @param initialBytes Optional seed bytes to return from load(). Defaults to empty array.
   */
  constructor(vaultPath = '/fake/vault.cryptiq', initialBytes?: Uint8Array) {
    this.vaultPath = vaultPath;
    this._storedBytes = initialBytes ?? new Uint8Array(0);
  }

  // ---------------------------------------------------------------------------
  // VaultStorageAdapter: exists / load
  // ---------------------------------------------------------------------------

  async exists(): Promise<boolean> {
    return this._storedBytes.length > 0;
  }

  async load(): Promise<VaultBytes> {
    // Return a copy so callers cannot mutate the stored bytes directly.
    return new Uint8Array(this._storedBytes);
  }

  // ---------------------------------------------------------------------------
  // VaultStorageAdapter: save (in-memory, with spy recording)
  // ---------------------------------------------------------------------------

  async save(bytes: VaultBytes, opts?: FakeSaveOpts): Promise<void> {
    // Store a copy of the bytes.
    this._storedBytes = new Uint8Array(bytes);
    this.lastSavedBytes = new Uint8Array(bytes);
    this.lastContentHash = opts?.contentHash ?? null;
    this.saveCount++;
  }

  // ---------------------------------------------------------------------------
  // VaultSession compat: isSaving / awaitSaveMutex / initLastSavedHash
  // ---------------------------------------------------------------------------

  /** Always false — the fake has no async save pipeline. */
  get isSaving(): boolean {
    return false;
  }

  /** Resolves immediately — no real mutex to await. */
  awaitSaveMutex(): Promise<void> {
    return Promise.resolve();
  }

  /**
   * Records the hash seed (Pitfall 8 defense analog). No-op for the fake since
   * no backup-rotation dedup occurs. Exposes a spy counter for test assertions.
   */
  initLastSavedHash(hash: string): void {
    this.lastInitHash = hash;
    this.initHashCalls++;
  }

  // ---------------------------------------------------------------------------
  // VaultStorageAdapter: backup methods (no-op in-memory stubs)
  // ---------------------------------------------------------------------------

  async listBackups(): Promise<Array<{ slot: number; modifiedAt: string; byteLength: number }>> {
    return [];
  }

  async loadBackup(_slot: number): Promise<VaultBytes> {
    return new Uint8Array(0);
  }

  async savePreMigrationBackup(_name: string, _bytes: VaultBytes): Promise<void> {
    // No-op — component tests never trigger migration.
  }

  // ---------------------------------------------------------------------------
  // Test utilities
  // ---------------------------------------------------------------------------

  /** Reset spy counters and clear stored bytes (useful between sub-tests). */
  reset(newBytes?: Uint8Array): void {
    this._storedBytes = newBytes ?? new Uint8Array(0);
    this.lastSavedBytes = null;
    this.lastContentHash = null;
    this.lastInitHash = null;
    this.saveCount = 0;
    this.initHashCalls = 0;
  }
}
