// apps/desktop/src/lib/adapters/TauriVaultStorageAdapter.ts
//
// Tauri-side implementation of VaultStorageAdapter (Phase 3, Plan 05).
//
// Architecture:
//   - Reads (exists/load/listBackups/loadBackup) use @tauri-apps/plugin-fs directly —
//     it is already capability-scoped and returns Uint8Array end-to-end (no base64).
//   - Writes (save/savePreMigrationBackup) go through custom Rust commands
//     (vault_write_atomic / vault_write_named) for fsync + atomic-rename semantics
//     that the JS fs plugin cannot provide.
//   - Lock re-verify (vault_lock_check) is a Rust command that checks PID + hostname
//     ownership before every write (P3-08).
//
// Save-mutex (P3-12):
//   save() chains onto a `saveMutex` promise so concurrent calls are serialized.
//   `isSaving` is exposed for Phase-5 LOCK-04.
//
// Content-hash dedup (P3-11):
//   save() accepts an optional `contentHash` in opts. When the hash matches
//   `lastSavedHash` (set after each successful save), maxBackups is passed as 0
//   to vault_write_atomic so the Rust side does NOT rotate backups. When the hash
//   differs (content genuinely changed), maxBackups is passed as the configured
//   limit (default 5) so the Rust side rotates. After the write, `lastSavedHash`
//   is updated to the new hash.
//
//   Pitfall 8 defense: call `initLastSavedHash(hash)` after load() to seed the
//   hash from the loaded content, avoiding a spurious first-save backup rotation.
//
// IPC (Pitfall 1): vault bytes are sent as Array.from(bytes) (a plain JS number
// array), which serde_json correctly deserializes as Vec<u8> on the Rust side.
// NEVER base64-encode vault bytes (Uint8Array end-to-end contract).
//
// Pre-migration backup (P3-13): uses a custom Rust command `vault_write_named`
// (not plugin-fs) to write a never-rotated named backup beside the vault directory,
// ensuring fsync semantics that match the main vault path.
//
// Threat model:
//   T-03-17: lock() awaits isSaving (via the saveMutex) BEFORE zeroing the vault key —
//            the adapter exposes `awaitSaveMutex()` so VaultSession can await in-flight
//            saves before memzero (Pitfall 4 defense).
//   T-03-18: only already-encrypted bytes cross the IPC boundary — no decrypted entry
//            data, no logging of entry content.
//   T-03-19: atomic Rust rename guarantees old-or-new on disk; verified at checkpoint.
//   T-03-20: lastSavedHash prevents spurious backup rotation when entries are unchanged.

import { invoke } from '@tauri-apps/api/core';
import { readFile, exists, stat } from '@tauri-apps/plugin-fs';
import type { VaultStorageAdapter, VaultBytes } from '@cryptiq/core';
import {
  VaultLockedByOtherProcessError,
  VaultIOError,
  VaultNotFoundError,
} from '@cryptiq/core';

/** Extended save options that include the optional content-hash dedup signal (P3-11). */
export interface TauriSaveOpts {
  /**
   * Maximum number of backup slots to rotate (default 5 per VAULT-06).
   * Passed through to vault_write_atomic as-is unless contentHash suppresses rotation.
   */
  maxBackups?: number;
  /**
   * P3-11 dedup signal. When provided and equal to `lastSavedHash`, backup rotation
   * is suppressed (maxBackups=0 sent to Rust). When different (or null/undefined on
   * first call), rotation proceeds normally and lastSavedHash is updated.
   */
  contentHash?: string;
}

export class TauriVaultStorageAdapter implements VaultStorageAdapter {
  readonly vaultLabel: string;
  readonly vaultPath: string;

  /** P3-12: serializes concurrent save() calls. Never reassigned — always chained. */
  private saveMutex: Promise<void> = Promise.resolve();

  /** P3-12: true while a save is in-flight. Read by Phase-5 LOCK-04 via `isSaving`. */
  private _isSaving = false;

  /**
   * P3-11: hash of the last successfully-persisted entries content.
   * Set on construction (null = no save yet), updated after each successful save,
   * and seeded via `initLastSavedHash()` on load() to avoid spurious first-save
   * backup rotation (Pitfall 8).
   */
  private lastSavedHash: string | null = null;

  /**
   * @param vaultPath  Absolute filesystem path to the vault file (e.g. "C:\...\vault.cryptiq").
   * @param vaultLabel Human-readable path label for diagnostics (same as vaultPath by default).
   */
  constructor(vaultPath: string, vaultLabel?: string) {
    this.vaultPath = vaultPath;
    this.vaultLabel = vaultLabel ?? vaultPath;
  }

  // ---------------------------------------------------------------------------
  // P3-12 save-in-progress flag (Phase-5 LOCK-04 reads this)
  // ---------------------------------------------------------------------------

  /** True while a save is in-flight. Read by Phase-5 LOCK-04. */
  get isSaving(): boolean {
    return this._isSaving;
  }

  /**
   * T-03-17 Pitfall-4 defense: return the current saveMutex promise so VaultSession's
   * lock() can await it BEFORE zeroing the vault key. Ensures no save races a key wipe.
   */
  awaitSaveMutex(): Promise<void> {
    return this.saveMutex;
  }

  // ---------------------------------------------------------------------------
  // Pitfall 8 defense: seed lastSavedHash from the loaded content
  // ---------------------------------------------------------------------------

  /**
   * Seed the content hash from the entries loaded off disk so the FIRST save after
   * an unlock does NOT trigger a spurious backup rotation (Pitfall 8).
   *
   * Call this from VaultSession.mount() after load() + decryption, passing
   * `hashEntriesContent(vault.entries)`.
   */
  initLastSavedHash(hash: string): void {
    this.lastSavedHash = hash;
  }

  // ---------------------------------------------------------------------------
  // VaultStorageAdapter: exists / load
  // ---------------------------------------------------------------------------

  async exists(): Promise<boolean> {
    try {
      return await exists(this.vaultPath);
    } catch {
      return false;
    }
  }

  async load(): Promise<VaultBytes> {
    if (!(await this.exists())) {
      throw new VaultNotFoundError(
        `Vault not found at path: ${this.vaultLabel}`,
      );
    }
    try {
      // plugin-fs returns a Uint8Array directly — no decode needed. End-to-end bytes.
      return await readFile(this.vaultPath);
    } catch (e) {
      throw new VaultIOError(`Failed to read vault: ${String(e)}`, e);
    }
  }

  // ---------------------------------------------------------------------------
  // VaultStorageAdapter: save (with save-mutex + lock re-verify + dedup)
  // ---------------------------------------------------------------------------

  /**
   * Atomically write encrypted bytes via the Rust `vault_write_atomic` command,
   * serializing concurrent calls through the save-mutex (P3-12) and re-verifying
   * lock ownership before each write (P3-08).
   *
   * Content-hash dedup (P3-11): if `opts.contentHash` equals `lastSavedHash`,
   * the backup rotation is suppressed (maxBackups=0 sent to Rust). Otherwise,
   * the Rust side rotates up to `maxBackups` slots.
   */
  async save(bytes: VaultBytes, opts?: TauriSaveOpts): Promise<void> {
    const maxBackupsDefault = opts?.maxBackups ?? 5;
    const contentHash = opts?.contentHash;

    // Chain onto the mutex. We MUST prevent errors from poisoning the mutex chain:
    // if the callback throws and `saveMutex` becomes a rejected promise, subsequent
    // `.then()` calls on it would skip their callbacks and propagate the old rejection.
    // The fix: capture a per-save reject handle and let `saveMutex` always resolve.
    let resolveThisSave!: () => void;
    let rejectThisSave!: (e: unknown) => void;
    const thisSavePromise = new Promise<void>((res, rej) => {
      resolveThisSave = res;
      rejectThisSave = rej;
    });

    // saveMutex itself ALWAYS resolves (never rejects), so the chain is never poisoned.
    this.saveMutex = this.saveMutex.then(async () => {
      this._isSaving = true;
      try {
        // P3-08: re-verify lock ownership before every write.
        await this._checkLock();

        // P3-11: dedup — suppress rotation when content hasn't changed.
        const shouldRotate =
          contentHash === undefined || contentHash !== this.lastSavedHash;
        const maxBackups = shouldRotate ? maxBackupsDefault : 0;

        // Pitfall 1: Array.from(bytes) sends a plain JS number array that serde_json
        // correctly deserializes as Vec<u8>. Never base64. Never raw Uint8Array object.
        await invoke('vault_write_atomic', {
          path: this.vaultPath,
          bytes: Array.from(bytes),
          maxBackups,
        });

        // Update the dedup marker ONLY on successful write.
        if (contentHash !== undefined) {
          this.lastSavedHash = contentHash;
        }

        resolveThisSave();
      } catch (e) {
        rejectThisSave(this._mapError(e));
      } finally {
        this._isSaving = false;
      }
      // Mutex callback ALWAYS returns void (resolved) — does not propagate the error.
    });

    return thisSavePromise;
  }

  // ---------------------------------------------------------------------------
  // VaultStorageAdapter: listBackups / loadBackup / savePreMigrationBackup (P3-13)
  // ---------------------------------------------------------------------------

  /**
   * List the encrypted backup slots that exist beside the vault, newest-first.
   * Checks slots 1..5 via plugin-fs `exists` + `stat` (verified: FileInfo has
   * `size: number` and `mtime: Date | null` — see RESEARCH A4).
   */
  async listBackups(): Promise<
    Array<{ slot: number; modifiedAt: string; byteLength: number }>
  > {
    const result: Array<{ slot: number; modifiedAt: string; byteLength: number }> = [];
    for (let slot = 1; slot <= 5; slot++) {
      const bakPath = `${this.vaultPath}.bak.${slot}`;
      try {
        const fileExists = await exists(bakPath);
        if (!fileExists) continue;
        const info = await stat(bakPath);
        result.push({
          slot,
          // `mtime` is `Date | null` per verified plugin-fs types (RESEARCH A4).
          modifiedAt: (info.mtime ?? new Date(0)).toISOString(),
          byteLength: info.size,
        });
      } catch {
        // Stat failed (race condition: file disappeared between exists() and stat()).
        // Skip this slot silently — it is not present from the user's perspective.
      }
    }
    // Newest-first: slot 1 is the most recent backup (Rust shifts 1→2→3→4→5 on rotate).
    // The loop iterates slots 1..5 in ascending order, so result is already newest-first
    // (slot 1 at index 0). No reversal needed — reversing would produce oldest-first (CR-02).
    return result;
  }

  /**
   * Load the encrypted bytes of a specific backup slot.
   *
   * @param slot  The backup slot number (1 = most recent, 5 = oldest).
   * @throws VaultNotFoundError if the slot does not exist.
   * @throws VaultIOError on read failure.
   */
  async loadBackup(slot: number): Promise<VaultBytes> {
    const bakPath = `${this.vaultPath}.bak.${slot}`;
    if (!(await exists(bakPath))) {
      throw new VaultNotFoundError(`Backup slot ${slot} not found: ${bakPath}`);
    }
    try {
      return await readFile(bakPath);
    } catch (e) {
      throw new VaultIOError(`Failed to read backup slot ${slot}: ${String(e)}`, e);
    }
  }

  /**
   * Write a never-rotated named backup beside the vault via the Rust
   * `vault_write_named` command (not through the save-mutex — migration writes
   * happen before the vault is unlocked and concurrent saves are not possible at
   * that point). Uses the same Rust fsync + atomic-rename guarantees as the main
   * vault write path.
   *
   * @param name    Backup file name WITHOUT extension (e.g. `'pre-v2-backup-2026-08-01T14-22-09Z'`).
   * @param bytes   The already-encrypted pre-migration vault bytes.
   */
  async savePreMigrationBackup(name: string, bytes: VaultBytes): Promise<void> {
    // Derive the directory from the vault path (works on both Windows and POSIX).
    const dir = this.vaultPath.replace(/[/\\][^/\\]+$/, '');
    const backupPath = `${dir}/${name}.cryptiq`;
    try {
      await invoke('vault_write_named', {
        vaultPath: this.vaultPath,
        path: backupPath,
        bytes: Array.from(bytes),
      });
    } catch (e) {
      throw this._mapError(e);
    }
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /**
   * Re-verify that this process still holds the advisory lock before a write (P3-08).
   * vault_lock_check returns:
   *   Ok(())            → still the owner
   *   Err("VAULT_LOCK_LOST")         → lock file is gone
   *   Err("VAULT_LOCK_STOLEN:…")     → another process took the lock
   */
  private async _checkLock(): Promise<void> {
    try {
      await invoke('vault_lock_check', { vaultPath: this.vaultPath });
    } catch (e) {
      // Any error from vault_lock_check means we no longer own the lock.
      const msg = String(e);
      if (msg.startsWith('VAULT_LOCK_STOLEN:')) {
        // "VAULT_LOCK_STOLEN:<pid>:<hostname>"
        const parts = msg.split(':');
        const pid = parts[1] !== undefined ? Number(parts[1]) : undefined;
        throw new VaultLockedByOtherProcessError(
          pid !== undefined && !Number.isNaN(pid) ? pid : undefined,
        );
      }
      // VAULT_LOCK_LOST or any other error — treat as lock lost.
      throw new VaultLockedByOtherProcessError();
    }
  }

  /**
   * Map a caught error from invoke() to the appropriate typed VaultStorageAdapter
   * error. The Rust commands use a "PREFIX:..." string convention:
   *   "VAULT_LOCKED:<pid>:<hostname>"     → VaultLockedByOtherProcessError
   *   "VAULT_LOCK_WARN:<pid>:<hostname>"  → VaultLockedByOtherProcessError (warn, allow)
   *   "VAULT_LOCK_LOST"                   → VaultLockedByOtherProcessError
   *   "VAULT_LOCK_STOLEN:<pid>:<hostname>"→ VaultLockedByOtherProcessError
   *   anything else                        → VaultIOError
   */
  private _mapError(e: unknown): Error {
    const msg = String(e);
    if (
      msg.startsWith('VAULT_LOCKED:') ||
      msg.startsWith('VAULT_LOCK_WARN:') ||
      msg.startsWith('VAULT_LOCK_LOST') ||
      msg.startsWith('VAULT_LOCK_STOLEN:')
    ) {
      const parts = msg.split(':');
      const pid = parts[1] !== undefined ? Number(parts[1]) : undefined;
      return new VaultLockedByOtherProcessError(
        pid !== undefined && !Number.isNaN(pid) ? pid : undefined,
      );
    }
    if (e instanceof VaultLockedByOtherProcessError || e instanceof VaultIOError) {
      return e;
    }
    return new VaultIOError(`Vault operation failed: ${msg}`, e);
  }
}
