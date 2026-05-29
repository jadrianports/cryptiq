// apps/desktop/src/lib/state/vault.svelte.ts
//
// The in-memory unlocked-vault session singleton. Phase 1 scaffolded the shape; Phase 2
// (Plan 02-04) fills the method bodies against the @cryptiq/core verb-first API; Phase 3
// (Plan 03-05) wires the lock lifecycle, CRUD-through-session, and adapter save.
//
// LOCKED DECISIONS (do not change without cross-phase decision):
//
//  - $state.raw (NOT $state): avoid Svelte's deep reactive proxy on the decrypted vault
//    data (defends Pitfall 7 — a deep proxy could surface decrypted secrets through
//    DevTools / the reactivity graph). $state.raw stores the value by reference and only
//    reacts to WHOLE-OBJECT reassignment. This MUST NOT become `$state`.
//  - The vault KEY is a NON-reactive private field (#vaultKey): the UI never needs to react
//    to raw key bytes, and keeping it out of the reactive graph is part of the Pitfall-7
//    defense. lock() zeroes it via @cryptiq/core's secureWipe (SEC-09) so the desktop layer
//    never imports raw libsodium (the ESLint no-restricted-imports ban stays intact).
//  - Adapter injected at mount/create (not a module-level singleton) so the test can pass
//    a mock adapter without touching the Tauri runtime.
//
// LOCK LIFECYCLE (P3-08):
//   - unlock()/create(): acquire advisory lock via vault_lock_acquire Rust command.
//   - lock(): MUST await adapter.awaitSaveMutex() BEFORE zeroing #vaultKey (Pitfall 4),
//             then release the advisory lock via vault_lock_release.
//   - A "VAULT_LOCK_WARN:" result from vault_lock_acquire surfaces a cross-host warning
//     signal (P3-10): stored in #lockWarning, exposed as get lockWarning(). Does not block.
//   - A "VAULT_LOCKED:" result → VaultLockedByOtherProcessError (P3-09 fresh same-host).
//
// CRUD-THROUGH-SESSION (P3-02):
//   After any mutation (addEntry, updateEntry, etc.), the session REASSIGNS #vault to a
//   new top-level reference (`this.#vault = { ...this.#vault }`) so Svelte's $state.raw
//   reactivity fires. Deep $state is deliberately NOT used.
//
// SAVE FLOW:
//   session.save() → saveVault(vault, key) [core → bytes] →
//   hashEntriesContent(vault.entries) →
//   adapter.save(bytes, { maxBackups, contentHash }) [TauriVaultStorageAdapter]
//   The contentHash dedup (P3-11) lives in the adapter — the session just computes + passes it.

import { invoke } from '@tauri-apps/api/core';
import type { UnlockedVault, UnlockSecret, EntryInput, EntryUpdate } from '@cryptiq/core';
import {
  secureWipe,
  saveVault,
  unlockVault,
  createVault,
  addEntry,
  updateEntry,
  softDeleteEntry,
  purgeEntry,
  regenerateFromPreset,
  VaultLockedByOtherProcessError,
} from '@cryptiq/core';
import type { KdfParams } from '@cryptiq/core/internal';
import type { TauriVaultStorageAdapter } from '../adapters/TauriVaultStorageAdapter';
import { hashEntriesContent } from '../adapters/contentHash';

/** The advisory lock warning for cross-host lock scenarios (P3-10). */
export interface LockWarning {
  /** The hostname of the process that holds (or recently held) the lock. */
  hostname: string;
}

class VaultSession {
  // $state.raw — Svelte 5 runes pattern for "whole-object reassignment without deep proxying."
  #vault = $state.raw<UnlockedVault | null>(null);
  // NON-reactive: never in the reactive graph (Pitfall 7 + SEC-09).
  #vaultKey: Uint8Array | null = null;
  // The storage adapter for this session — injected at unlock/create time.
  #adapter: TauriVaultStorageAdapter | null = null;
  // The vault filesystem path — used for lock acquire/release.
  #vaultPath: string | null = null;
  // P3-10: cross-host lock warning (surface to UI; does not block).
  #lockWarning: LockWarning | null = null;

  // ---------------------------------------------------------------------------
  // Readable state
  // ---------------------------------------------------------------------------

  get vault(): UnlockedVault | null {
    return this.#vault;
  }

  get isUnlocked(): boolean {
    return this.#vault !== null;
  }

  /**
   * P3-10: populated when vault_lock_acquire returns "VAULT_LOCK_WARN:…".
   * The UI should surface this to the user (non-blocking warn).
   */
  get lockWarning(): LockWarning | null {
    return this.#lockWarning;
  }

  /**
   * True while the adapter's save-mutex is active (P3-12).
   * Phase-5 LOCK-04 reads this to defer auto-lock until the save completes.
   */
  get isSaving(): boolean {
    return this.#adapter?.isSaving ?? false;
  }

  // ---------------------------------------------------------------------------
  // Unlock / Create
  // ---------------------------------------------------------------------------

  /**
   * Unlock an existing vault from disk and acquire the advisory lock (P3-08).
   *
   * @param adapter  The TauriVaultStorageAdapter for this vault.
   * @param secret   Master password or recovery key (DC-10 open union).
   * @throws VaultLockedByOtherProcessError if a live same-host lock is found (P3-09).
   * @returns A LockWarning if a cross-host lock was present but overridden (P3-10), else null.
   */
  async unlock(
    adapter: TauriVaultStorageAdapter,
    secret: UnlockSecret,
  ): Promise<LockWarning | null> {
    const bytes = await adapter.load();
    const { vault, vaultKey } = await unlockVault(bytes, secret);

    // Acquire advisory lock BEFORE mounting — fail if another live process holds it.
    const warning = await this._acquireLock(adapter.vaultPath);

    // Seed the content-hash dedup from the loaded content (Pitfall 8 defense).
    adapter.initLastSavedHash(hashEntriesContent(vault.entries));

    this.#vault = vault;
    this.#vaultKey = vaultKey;
    this.#adapter = adapter;
    this.#vaultPath = adapter.vaultPath;
    this.#lockWarning = warning;
    return warning;
  }

  /**
   * Create a new vault file, write it to disk, and acquire the advisory lock (P3-08).
   *
   * @param adapter       The TauriVaultStorageAdapter for the new vault.
   * @param masterPassword The master password bytes.
   * @param withRecoveryKey Whether to generate a recovery key.
   * @param kdfParams     Optional test seam to skip calibration.
   * @returns `{ recoveryKey?, creationReport }` from createVault.
   */
  async create(
    adapter: TauriVaultStorageAdapter,
    masterPassword: Uint8Array,
    withRecoveryKey: boolean,
    kdfParams?: KdfParams,
  ): Promise<{ recoveryKey?: string; creationReport: import('@cryptiq/core').CreationReport }> {
    const result = await createVault(
      kdfParams !== undefined
        ? { masterPassword, withRecoveryKey, kdfParams }
        : { masterPassword, withRecoveryKey },
    );
    const { vault, vaultKey, recoveryKey, creationReport } = result;

    // Acquire advisory lock BEFORE the first write so _checkLock() finds the
    // lockfile that save() will immediately verify (CR-01: prior ordering caused
    // every create() to throw VaultLockedByOtherProcessError because vault_lock_check
    // returns VAULT_LOCK_LOST when the lockfile does not yet exist).
    const warning = await this._acquireLock(adapter.vaultPath);

    // Now that the lock exists, write the newly-created vault to disk.
    const bytes = await saveVault(vault, vaultKey);
    await adapter.save(bytes, { contentHash: hashEntriesContent(vault.entries) });

    // Seed the content-hash dedup marker.
    adapter.initLastSavedHash(hashEntriesContent(vault.entries));

    this.#vault = vault;
    this.#vaultKey = vaultKey;
    this.#adapter = adapter;
    this.#vaultPath = adapter.vaultPath;
    this.#lockWarning = warning;

    const out: { recoveryKey?: string; creationReport: import('@cryptiq/core').CreationReport } = {
      creationReport,
    };
    if (recoveryKey !== undefined) out.recoveryKey = recoveryKey;
    return out;
  }

  // ---------------------------------------------------------------------------
  // Mount (internal / test seam — used by Phase-2 tests that call createVault
  // directly and hand the result to the session without going through the adapter).
  // ---------------------------------------------------------------------------

  /**
   * Mount a freshly unlocked vault + its 32-byte key after a successful
   * createVault()/unlockVault() call. The caller hands ownership of `vaultKey` to the
   * session; from here only lock() may zero it.
   *
   * NOTE: For real app code, prefer `unlock()` or `create()` which also wire the
   * adapter and the advisory lock. `mount()` is retained for compatibility with
   * Phase-2 tests and for the boot-self-test.
   */
  mount(vault: UnlockedVault, vaultKey: Uint8Array): void {
    this.#vault = vault;
    this.#vaultKey = vaultKey;
  }

  // ---------------------------------------------------------------------------
  // Lock / Quit
  // ---------------------------------------------------------------------------

  /**
   * Lock the session: await any in-flight save (Pitfall 4), zero the vault key
   * buffer in place (SEC-09), drop all references, and release the advisory lock.
   *
   * Idempotent: locking an already-locked session is a no-op.
   *
   * PITFALL 4 DEFENSE: `await adapter.awaitSaveMutex()` BEFORE zeroing #vaultKey
   * to guarantee that no concurrent save() is using the key when we wipe it.
   */
  async lock(): Promise<void> {
    const adapter = this.#adapter;
    const vaultPath = this.#vaultPath;
    const key = this.#vaultKey;

    // Clear all references FIRST so the session is visually locked immediately.
    this.#vault = null;
    this.#vaultKey = null;
    this.#adapter = null;
    this.#vaultPath = null;
    this.#lockWarning = null;

    // Pitfall 4: wait for any in-flight save to finish before zeroing the key.
    if (adapter !== null) {
      await adapter.awaitSaveMutex();
    }

    // Zero the key buffer (SEC-09). secureWipe calls sodium.memzero — the desktop layer
    // never touches raw libsodium. Best-effort defense (JS GC may have copied bytes).
    if (key !== null) {
      await secureWipe(key);
    }

    // Release the advisory lock (P3-08). Fire-and-forget any error — if the lock
    // file is already gone (e.g. OS cleaned it), that is acceptable.
    if (vaultPath !== null) {
      try {
        await invoke('vault_lock_release', { vaultPath });
      } catch {
        // Lock was already released or file was already removed — acceptable.
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Save
  // ---------------------------------------------------------------------------

  /**
   * Serialize the current in-memory vault to encrypted bytes and persist via the
   * adapter's save-mutex. Includes content-hash dedup (P3-11) to suppress spurious
   * backup rotation when entries have not changed.
   *
   * @throws if the session is locked (no adapter mounted).
   * @throws VaultLockedByOtherProcessError if the lock was lost or stolen (via adapter).
   * @throws VaultIOError on disk failures (via adapter).
   */
  async save(opts?: { maxBackups?: number }): Promise<void> {
    const vault = this.#vault;
    const key = this.#vaultKey;
    const adapter = this.#adapter;

    if (vault === null || key === null || adapter === null) {
      throw new Error('VaultSession.save: session is locked — cannot save.');
    }

    // saveVault re-encrypts the entries blob under the vault key with a FRESH nonce (SEC-04).
    const bytes = await saveVault(vault, key);

    // Compute the content hash for P3-11 dedup AFTER saveVault (which may have mutated
    // vault.doc.data and vault.doc.meta.modifiedAt). The entries object itself is unchanged
    // by saveVault, so the hash reflects the current entry state.
    const contentHash = hashEntriesContent(vault.entries);

    await adapter.save(bytes, {
      maxBackups: opts?.maxBackups ?? 5,
      contentHash,
    });
  }

  // ---------------------------------------------------------------------------
  // CRUD-through-session (P3-02)
  //
  // Each method:
  //   1. Calls the core verb (mutates vault.entries in place).
  //   2. REASSIGNS #vault to a new top-level reference (shallow copy of the
  //      UnlockedVault object) so Svelte's $state.raw reactivity fires.
  //      Deep $state is deliberately NOT used — Pitfall 7 defense.
  // ---------------------------------------------------------------------------

  async addEntry(input: EntryInput): Promise<import('@cryptiq/core').Entry> {
    const vault = this._requireVault();
    const entry = await addEntry(vault, input);
    // Reassign reference to trigger $state.raw reactivity (P3-02).
    this.#vault = { ...vault };
    return entry;
  }

  updateEntry(id: string, update: EntryUpdate): import('@cryptiq/core').Entry {
    const vault = this._requireVault();
    const entry = updateEntry(vault, id, update);
    this.#vault = { ...vault };
    return entry;
  }

  softDeleteEntry(id: string): void {
    const vault = this._requireVault();
    softDeleteEntry(vault, id);
    this.#vault = { ...vault };
  }

  purgeEntry(id: string): void {
    const vault = this._requireVault();
    purgeEntry(vault, id);
    this.#vault = { ...vault };
  }

  async regenerateFromPreset(id: string): Promise<import('@cryptiq/core').Entry> {
    const vault = this._requireVault();
    const entry = await regenerateFromPreset(vault, id);
    this.#vault = { ...vault };
    return entry;
  }

  // ---------------------------------------------------------------------------
  // @internal — crypto layer only
  // ---------------------------------------------------------------------------

  /**
   * For the crypto layer ONLY (e.g. changeMasterPassword, saveVault): hand back the live key
   * buffer. NEVER expose this to UI code. Throws if the session is locked.
   * @internal
   */
  unsafeGetKey(): Uint8Array {
    if (this.#vaultKey !== null) return this.#vaultKey;
    throw new Error('VaultSession.unsafeGetKey: session is locked (no key mounted).');
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /**
   * Acquire the advisory lock via vault_lock_acquire. Handles P3-09 (same-host
   * fresh lock → error) and P3-10 (cross-host fresh lock → warn + allow).
   */
  private async _acquireLock(vaultPath: string): Promise<LockWarning | null> {
    const startedAt = new Date().toISOString();
    try {
      await invoke('vault_lock_acquire', { vaultPath, startedAt });
      return null; // No warning — lock acquired cleanly.
    } catch (e) {
      const msg = String(e);
      if (msg.startsWith('VAULT_LOCK_WARN:')) {
        // "VAULT_LOCK_WARN:<pid>:<hostname>" — cross-host fresh lock, warn but allow (P3-10).
        const parts = msg.split(':');
        const hostname = parts[2] ?? 'unknown';
        return { hostname };
      }
      if (msg.startsWith('VAULT_LOCKED:')) {
        // "VAULT_LOCKED:<pid>:<hostname>" — same-host fresh live lock (P3-09).
        const parts = msg.split(':');
        const pid = parts[1] !== undefined ? Number(parts[1]) : undefined;
        throw new VaultLockedByOtherProcessError(
          pid !== undefined && !Number.isNaN(pid) ? pid : undefined,
        );
      }
      // Any other error from vault_lock_acquire — surface as IO error.
      throw new Error(`Failed to acquire vault lock: ${msg}`);
    }
  }

  /** Throw if the session is not unlocked (no vault mounted). */
  private _requireVault(): UnlockedVault {
    if (this.#vault !== null) return this.#vault;
    throw new Error('VaultSession: operation requires an unlocked vault.');
  }
}

// Module-level singleton — the only handle the rest of the app sees.
export const vaultSession = new VaultSession();
