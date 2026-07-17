// apps/site/src/storage/InMemoryVaultStorageAdapter.ts
//
// Phase 38 Plan 02, Task 2 (SC-3). A ~30-line VaultStorageAdapter implementing
// the FULL packages/core interface, backed by a single module-instance-level
// Uint8Array. NEVER touches the filesystem, the network, or any browser
// persistence API — no page-level storage/database/cookie writes of any
// kind (D-08 covers those in the test suite) — that is the entire point of
// the demo's zero-persistence property (DEMO-02). Only save()/load()/exists()
// are exercised by the round-trip proof; the other three interface members
// are minimal "not implemented for demo" stubs since the demo round trip
// never exercises backups or migration.

// VaultStorageAdapter/VaultBytes/the typed storage errors live on the PUBLIC
// `@cryptiq/core` surface (packages/core/src/index.ts re-exports
// storage/VaultStorageAdapter.ts) — they are not part of the crypto-primitive
// `./internal` barrel, so this file imports them from the public entry point.
import {
  VaultCorruptError,
  VaultNotFoundError,
  type VaultBytes,
  type VaultStorageAdapter,
} from '@cryptiq/core';

export class InMemoryVaultStorageAdapter implements VaultStorageAdapter {
  readonly vaultLabel = 'demo-in-memory-vault';

  #bytes: VaultBytes | null = null;

  async exists(): Promise<boolean> {
    return this.#bytes !== null;
  }

  async load(): Promise<VaultBytes> {
    if (this.#bytes === null) throw new VaultNotFoundError();
    // Zero-byte defensive check mirrors the adapter contract's
    // "catastrophic FS-level issue" semantics even though this in-memory
    // store can never actually be truncated by an external process.
    if (this.#bytes.length === 0) throw new VaultCorruptError('empty in-memory vault bytes');
    return this.#bytes.slice();
  }

  async save(bytes: VaultBytes): Promise<void> {
    this.#bytes = bytes.slice();
  }

  async listBackups(): Promise<Array<{ slot: number; modifiedAt: string; byteLength: number }>> {
    throw new Error('InMemoryVaultStorageAdapter: backups not implemented for demo');
  }

  async loadBackup(): Promise<VaultBytes> {
    throw new Error('InMemoryVaultStorageAdapter: backups not implemented for demo');
  }

  async savePreMigrationBackup(): Promise<void> {
    throw new Error('InMemoryVaultStorageAdapter: migration not implemented for demo');
  }
}
