// packages/core/src/storage/VaultStorageAdapter.ts
//
// Phase 1: types only. Phase 2 will use these signatures (storage adapter implementation
// itself lives in Phase 3 inside apps/desktop). Source-of-truth contract for the
// core-vs-platform boundary. core never sees a Path or a tauri::AppHandle.

/** UTF-8-encoded bytes of an outer JSON vault document. */
export type VaultBytes = Uint8Array;

// --- Error types (concrete classes so callers branch on `instanceof`) ---

export class VaultNotFoundError extends Error {
  readonly code = 'VAULT_NOT_FOUND';
}

export class VaultLockedByOtherProcessError extends Error {
  readonly code = 'VAULT_LOCKED_BY_OTHER_PROCESS';
  constructor(public readonly holderPid?: number) {
    super(`Vault is currently held by another Cryptiq process (pid=${holderPid ?? 'unknown'}).`);
  }
}

export class VaultIOError extends Error {
  readonly code = 'VAULT_IO_ERROR';
  constructor(
    message: string,
    public override readonly cause?: unknown,
  ) {
    super(message);
  }
}

export class VaultCorruptError extends Error {
  readonly code = 'VAULT_CORRUPT';
  constructor(message: string) {
    super(message);
  }
}

/**
 * The platform-bridging interface. `core` orchestrates WHEN to load/save;
 * the adapter (Phase 3) decides HOW.
 *
 * Error semantics:
 *   - exists() never throws for "not found" — returns false.
 *     MAY throw VaultIOError for permission / device errors.
 *   - load() throws VaultNotFoundError if !exists().
 *     Throws VaultCorruptError ONLY for catastrophic FS-level issues
 *     (zero-byte file, truncated read). Crypto-level corruption (bad AEAD tag,
 *     bad JSON) is core's responsibility — adapter just hands bytes back.
 *   - save() is atomic per VAULT-05 (write tmp → fsync → rotate backups → rename → dir-fsync).
 *     Throws VaultLockedByOtherProcessError if held by another process.
 *     Throws VaultIOError on disk-full / permission-denied.
 *     Does NOT throw on a partial-write interruption — the atomic-rename pattern
 *     means the partial file is at most `.tmp`, never the live vault.
 */
export interface VaultStorageAdapter {
  /** Resolve the user-facing path/label for diagnostics. NEVER for crypto. */
  readonly vaultLabel: string;

  /** Does a vault exist at the configured path? */
  exists(): Promise<boolean>;

  /** Read the encrypted bytes. */
  load(): Promise<VaultBytes>;

  /**
   * Atomically write encrypted bytes, rotating up to maxBackups encrypted
   * backups beside the live file. Sequence:
   *   1. Acquire exclusive lock (advisory). Fail with VaultLockedByOtherProcessError if held.
   *   2. Write bytes to `<vault>.tmp`.
   *   3. fsync the tmp file.
   *   4. Shift backups: bak.4 → bak.5, bak.3 → bak.4, ..., live → bak.1.
   *   5. Rename tmp → live.
   *   6. fsync the directory.
   *   7. Release lock.
   *
   * @param bytes the encrypted vault payload
   * @param opts.maxBackups default 5 per VAULT-06
   */
  save(bytes: VaultBytes, opts?: { maxBackups?: number }): Promise<void>;

  /**
   * List the encrypted backup files (newest first) for disaster-recovery UI.
   * The bytes themselves are loaded on demand via loadBackup(slot).
   */
  listBackups(): Promise<Array<{ slot: number; modifiedAt: string; byteLength: number }>>;

  /** Load a specific backup slot. */
  loadBackup(slot: number): Promise<VaultBytes>;

  /**
   * Save a one-shot, NEVER-rotated, named backup beside the vault.
   * Used by the migration framework before transforming the file.
   * Persists until the user explicitly deletes it via the UI.
   *
   * @param name e.g., 'pre-v2-backup-2026-08-01T14-22-09Z'
   * @param bytes the (already-encrypted) pre-migration vault bytes
   */
  savePreMigrationBackup(name: string, bytes: VaultBytes): Promise<void>;
}
