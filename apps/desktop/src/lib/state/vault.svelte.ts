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
  changeMasterPassword,
  addEntry,
  updateEntry,
  restoreEntry,
  softDeleteEntry,
  purgeEntry,
  regenerateFromPreset,
  VaultLockedByOtherProcessError,
} from '@cryptiq/core';
import type { KdfParams } from '@cryptiq/core/internal';
import type { TauriVaultStorageAdapter } from '../adapters/TauriVaultStorageAdapter';
import { hashEntriesContent } from '../adapters/contentHash';
// P5-08 / LOCK-02: tear down the module-level clipboard auto-clear guard timer on
// lock so it can NOT fire after the vault is unlocked again. Static import is safe:
// clipboardGuard.svelte does NOT import vault.svelte (it only imports invoke), so
// there is no circular dependency — unlike idle.svelte (lazy-imported below) which
// DOES import vaultSession.
import { cancelClipboardClear } from './clipboardGuard.svelte';
// P5-07: cancelIdleTimer is imported lazily inside lock() to avoid a circular
// module dependency at initialization time (idle.svelte imports vaultSession;
// vault.svelte imports cancelIdleTimer). A module-level lazy ref breaks the
// cycle: the import() resolves on first lock() call (after both modules are
// fully initialized), and subsequent calls use the cached ref.
let _cancelIdleTimer: (() => void) | null = null;
async function _getCancelIdleTimer(): Promise<() => void> {
  if (_cancelIdleTimer !== null) return _cancelIdleTimer;
  const mod = await import('./idle.svelte');
  _cancelIdleTimer = mod.cancelIdleTimer;
  return _cancelIdleTimer;
}

// LOCK-05 / HMR seam: The hot reference for clearing import.meta.hot.data on
// lock. In production (Vite dev server), this is import.meta.hot (the real
// Vite HMR module context). In tests, Vitest node environment does not share
// import.meta across modules, so the test seam below allows injection of a
// mock hot reference without relying on import.meta identity.
//
// `_setHotForTesting` is consumed by hotData.test.ts to wire the HMR mock.
// It is ONLY available in non-production builds (import.meta.env.PROD check).
let _hotRef: { data: Record<string, unknown> } | null | undefined =
  (import.meta.hot as { data: Record<string, unknown> } | undefined) ?? undefined;

/**
 * @internal TEST SEAM (LOCK-05): Inject a mock HMR hot reference so lock()
 * can be tested in Vitest node environment where import.meta is not shared
 * across modules. Call with `null` to clear the override.
 *
 * Plan 05-03 ONLY — not exported from the public API.
 */
export function _setHotForTesting(hot: { data: Record<string, unknown> } | null): void {
  _hotRef = hot ?? undefined;
}

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

  // P5-07 (LOCK-04 / Pitfall 1): critical-op tracking for EVERY key-reading
  // operation that runs OUTSIDE the adapter save-mutex under the live #vaultKey —
  // changeMasterPassword, resetMasterPasswordAfterRecovery (each a ~2s Argon2id
  // derive), AND the saveVault() encryption phase inside save() (a few-ms AEAD seal
  // that reads the key before the mutex-guarded byte-write). All route through
  // #withCriticalOp below. Two consumers read this state:
  //   1. The idle controller's fast isCriticalOpInProgress check avoids even
  //      STARTING a lock during a derive.
  //   2. The EVENT-DRIVEN lock() callers (App.svelte sleep/blur/close) bypass the
  //      idle guard, so lock() awaits #criticalOpDone BEFORE secureWipe — the key
  //      buffer is never zeroed while a ~2s Argon2id derive is still reading/
  //      wrapping it (which would seal an all-zero key → corrupt wrappedKeys.master
  //      → permanent lockout).
  //
  // REF-COUNT design (re-entrancy safe): #criticalOpCount tracks how many critical
  // ops are concurrently in flight. #criticalOpDone is created on the 0→1 edge and
  // resolved (never rejected) ONLY on the last 1→0 edge, so two overlapping ops
  // share ONE promise that a deferring lock() awaits until the LAST op finishes.
  // #criticalOpDone is non-null whenever ANY critical op is in flight, and null
  // when none are. #resolveCriticalOp holds the resolver for the shared promise.
  #criticalOpCount = 0;
  #criticalOpDone: Promise<void> | null = null;
  #resolveCriticalOp: (() => void) | null = null;

  /**
   * True while ANY key-reading critical op (changeMasterPassword,
   * resetMasterPasswordAfterRecovery, the save() encryption phase, or any future
   * op routed through #withCriticalOp) is in flight (P5-07). Count-based: true iff
   * the in-flight count is > 0. Phase-5 LOCK-04 reads isCriticalOpInProgress
   * alongside isSaving to defer auto-lock.
   */
  get isCriticalOpInProgress(): boolean {
    return this.#criticalOpCount > 0;
  }

  /**
   * Run `fn` as a tracked critical op (P5-07 / LOCK-04 / Pitfall 1).
   *
   * Guarantees, for the duration of `fn`:
   *   - isCriticalOpInProgress === true (count > 0).
   *   - #criticalOpDone is a non-null promise that lock() can await before
   *     secureWipe so the live #vaultKey is never zeroed mid-derive.
   *
   * Re-entrancy safe: the shared #criticalOpDone is created on the 0→1 transition
   * and resolved on the last 1→0 transition only. Overlapping ops therefore share
   * ONE promise that resolves when the LAST in-flight op completes — a lock()
   * awaiting it can never proceed to wipe while any critical op is still running.
   *
   * The promise ALWAYS resolves (never rejects) so a rejecting `fn` (e.g. a failed
   * change-master) can never block lock() — `fn`'s own rejection still propagates
   * to its caller via the returned promise.
   */
  async #withCriticalOp<T>(fn: () => Promise<T>): Promise<T> {
    if (this.#criticalOpCount === 0) {
      this.#criticalOpDone = new Promise<void>((resolve) => {
        this.#resolveCriticalOp = resolve;
      });
    }
    this.#criticalOpCount += 1;
    try {
      return await fn();
    } finally {
      this.#criticalOpCount -= 1;
      if (this.#criticalOpCount === 0) {
        const resolve = this.#resolveCriticalOp;
        this.#criticalOpDone = null;
        this.#resolveCriticalOp = null;
        resolve?.();
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Public critical-op wrapper (Fix-forward: import-auto-lock regression)
  // ---------------------------------------------------------------------------

  /**
   * Run `fn` as a tracked critical op, exposed for callers outside VaultSession
   * (e.g. the ImportView commit loop) that need the LOCK-04 / Pitfall-1 protections
   * without owning the private #withCriticalOp method directly.
   *
   * Guarantees (inherited from #withCriticalOp):
   *   - isCriticalOpInProgress === true for the entire duration of `fn`.
   *   - The idle controller defers its lock check while this is in flight
   *     (SECURITY_INVARIANT 1 / LOCK-04).
   *   - lock() awaits #criticalOpDone before secureWipe, so the live #vaultKey
   *     is NEVER zeroed mid-operation (Pitfall-1 backstop).
   *   - try/finally is enforced INTERNALLY — the counter can NEVER leak even if
   *     `fn` throws (SECURITY_INVARIANT 5).
   *
   * @param fn  The async work to run as a critical op.
   * @returns   The resolved value of `fn`.
   * @throws    Re-throws any rejection from `fn`.
   */
  async runCriticalOp<T>(fn: () => Promise<T>): Promise<T> {
    return this.#withCriticalOp(fn);
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

    // D-09: sweep any orphaned .tmp file from a prior killed sync (best-effort, non-fatal).
    try {
      await invoke('vault_sweep_tmp', { vaultPath: adapter.vaultPath });
    } catch {
      // Non-fatal: .tmp may not exist or Rust command may be unavailable in test env.
    }

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

    // Now that the lock exists, write the newly-created vault to disk. If ANY step here
    // throws (write failure, etc.), roll back: release the advisory lock we just acquired
    // and wipe the vault key. Otherwise a failed create leaks the lock — which later
    // wedges unlock with a spurious "locked by another process" (UAT T5).
    try {
      const bytes = await saveVault(vault, vaultKey);
      await adapter.save(bytes, { contentHash: hashEntriesContent(vault.entries) });

      // Seed the content-hash dedup marker.
      adapter.initLastSavedHash(hashEntriesContent(vault.entries));
    } catch (e) {
      try {
        await invoke('vault_lock_release', { vaultPath: adapter.vaultPath });
      } catch {
        // Lock file already gone — acceptable.
      }
      await secureWipe(vaultKey);
      throw e;
    }

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
   * Lock the session: cancel idle timer, clear pending clipboard, await any
   * in-flight save (Pitfall 4), zero the vault key buffer in place (SEC-09),
   * drop all references, release the advisory lock, and clear HMR data in dev.
   *
   * Idempotent: locking an already-locked session is a no-op.
   *
   * PITFALL 4 DEFENSE: `await adapter.awaitSaveMutex()` BEFORE zeroing #vaultKey
   * to guarantee that no concurrent save() is using the key when we wipe it.
   *
   * PITFALL 1 DEFENSE (P5-07 backstop): `await #criticalOpDone` BEFORE zeroing
   * #vaultKey to guarantee that no in-flight critical op (any key-reading op routed
   * through #withCriticalOp — changeMasterPassword AND resetMasterPasswordAfterRecovery,
   * each a ~2s Argon2id derive, AND the save() saveVault encryption phase, a few-ms
   * AEAD seal that runs outside the adapter save-mutex) is still reading/wrapping the
   * key when we wipe it. The count-based #criticalOpDone
   * stays non-null until the LAST in-flight critical op finishes, so this single
   * await guards EVERY such op at one choke point — including the event-driven
   * App.svelte handlers (sleep/blur/close) that bypass the idle controller's
   * fast guard.
   *
   * NOTE: lock() does NOT call go('unlock') — the caller (idle controller,
   * App.svelte listeners) owns the view transition (separation of concerns).
   *
   * ORDERING (P5-07):
   *   1. Synchronously clear all references (isUnlocked → false immediately).
   *   2. Cancel idle timer (lazy import — resolves after module init).
   *   3. Clear pending clipboard (non-fatal invoke, before key zero).
   *   4. await save-mutex (Pitfall 4 ordering — BEFORE secureWipe).
   *   4b. await in-flight critical op (Pitfall 1 backstop — BEFORE secureWipe).
   *   5. secureWipe the key (SEC-09).
   *   6. Clear HMR data in dev (LOCK-05).
   *   7. Release advisory lock (P3-08).
   */
  async lock(): Promise<void> {
    const adapter = this.#adapter;
    const vaultPath = this.#vaultPath;
    const key = this.#vaultKey;
    // Capture the in-flight critical-op promise BEFORE we clear references in
    // step 1. We await it in step 4b (after the save-mutex, before secureWipe).
    const criticalOpDone = this.#criticalOpDone;

    // Step 1: Clear all references FIRST so the session is visually locked
    // immediately (isUnlocked → false before any await). This is the
    // synchronous half of lock() — callers observing isUnlocked right after
    // calling lock() (without awaiting) see false immediately.
    this.#vault = null;
    this.#vaultKey = null;
    this.#adapter = null;
    this.#vaultPath = null;
    this.#lockWarning = null;

    // Step 2 (P5-07 / LOCK-01): Cancel the idle timer so it doesn't
    // double-fire after lock() is called from a non-idle path (sleep/close/
    // explicit user lock). Lazy import via cached ref breaks the vault ↔ idle
    // circular dependency at initialization time.
    const cancelIdleTimer = await _getCancelIdleTimer();
    cancelIdleTimer();

    // Step 3 (LOCK-02/03): Tear down the module-level clipboard auto-clear guard
    // timer FIRST so its authoritative setTimeout can NOT fire after this lock (and
    // after a possible re-unlock). cancelClipboardClear does NOT itself invoke the
    // Rust clear — we do that immediately below, which is the real clipboard wipe.
    cancelClipboardClear();

    // Step 3b (LOCK-03): Clear any pending clipboard password before zeroing
    // the key. Non-fatal: the Rust command no-ops if nothing is stashed.
    try {
      await invoke('clipboard_clear_if_ours');
    } catch {
      // Non-fatal: clipboard state missing or Tauri command unavailable (e.g.
      // in unit tests where invoke is mocked to no-op). Continue locking.
    }

    // Step 4 (Pitfall 4): Wait for any in-flight save to finish BEFORE zeroing
    // the key. This ordering is locked — MUST NOT move secureWipe before this.
    if (adapter !== null) {
      await adapter.awaitSaveMutex();
    }

    // Step 4b (P5-07 / Pitfall 1 backstop): Wait for any in-flight critical op
    // (changeMasterPassword OR resetMasterPasswordAfterRecovery — each a ~2s
    // Argon2id derive — OR the save() encryption phase, all routed through
    // #withCriticalOp) to finish BEFORE zeroing the key. Without this, an
    // event-driven lock() (App.svelte sleep/blur/close) could secureWipe #vaultKey
    // while the derive is still reading/wrapping it (sealing an all-zero key →
    // corrupt wrappedKeys.master → permanent lockout) or while saveVault's AEAD seal
    // is still reading it (a torn read → corrupt data-blob ciphertext that may not
    // decrypt). The count-based #criticalOpDone always resolves (never
    // rejects) when the LAST in-flight op finishes, but we wrap in try/catch as a
    // belt-and-suspenders so a rejecting/aborted op can NEVER block locking — a
    // failed critical op must still let the vault lock and wipe its key.
    if (criticalOpDone !== null) {
      try {
        await criticalOpDone;
      } catch {
        // A rejected critical op must not block the lock — proceed to secureWipe.
      }
    }

    // Step 5 (SEC-09): Zero the key buffer. secureWipe calls sodium.memzero —
    // the desktop layer never touches raw libsodium. Best-effort defense
    // (JS GC may have already copied bytes).
    if (key !== null) {
      await secureWipe(key);
    }

    // Step 6 (LOCK-05 / Pitfall 4): Clear HMR module data in dev so a
    // hot-reload does not re-surface the just-zeroed key via
    // import.meta.hot.data. The guard handles production, where
    // import.meta.hot is undefined.
    //
    // Uses _hotRef (seam-injectable for tests) with fallback to import.meta.hot
    // (the real Vite HMR context in dev-server mode).
    //
    // IMPORTANT: import.meta.hot.data is a GETTER-ONLY property on Vite's real
    // HMRContext — reassigning it (`hot.data = {}`) throws "Cannot set property
    // data of #<HMRContext> which has only a getter" and aborts lock(), breaking
    // every lock path in `tauri dev`. Clear the object IN PLACE (delete its keys)
    // so persisted state is wiped without reassigning the read-only reference.
    // (The unit-test seam injects a plain writable object, so the old reassignment
    // passed tests but failed against the live HMRContext — see hotData.test.ts (c).)
    const hot = _hotRef ?? (import.meta.hot as { data: Record<string, unknown> } | undefined);
    if (hot?.data) {
      for (const k of Object.keys(hot.data)) {
        delete hot.data[k];
      }
    }

    // Step 7 (P3-08): Release the advisory lock. Fire-and-forget any error —
    // if the lock file is already gone (e.g. OS cleaned it), that is acceptable.
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
    // P5-07 (LOCK-04 / Pitfall 1): the encryption reads the LIVE #vaultKey inside
    // crypto_aead_xchacha20poly1305_ietf_encrypt (saveVault → encryptInner → sealData),
    // and runs OUTSIDE the adapter's save-mutex (the mutex wraps ONLY the vault_write_atomic
    // byte-write inside adapter.save() below). Without this guard, an event-driven lock()
    // (App.svelte sleep/blur/close) firing during the encryption phase would secureWipe
    // #vaultKey mid-encrypt — a torn read sealing a partially-zeroed key → corrupt data-blob
    // ciphertext that may not decrypt. Route ONLY the key-reading encryption through
    // #withCriticalOp so lock() defers its secureWipe until the encryption completes (the
    // adapter.save() write below stays under the save-mutex, which lock() already awaits via
    // awaitSaveMutex()). #withCriticalOp is ref-counted, so overlapping saves share the
    // promise; save() never calls lock() and lock() never calls save(), so there is no
    // deadlock/recursion.
    const bytes = await this.#withCriticalOp(() => saveVault(vault, key));

    // Compute the content hash for P3-11 dedup AFTER saveVault (which may have mutated
    // vault.doc.data and vault.doc.meta.modifiedAt). The entries object itself is unchanged
    // by saveVault, so the hash reflects the current entry state.
    const contentHash = hashEntriesContent(vault.entries);

    await adapter.save(bytes, {
      maxBackups: opts?.maxBackups ?? 5,
      contentHash,
    });
  }

  /**
   * Persist in-place settings mutations and surface them to $state.raw consumers.
   *
   * SettingsShell mutates `getVaultSettings(vault).lock` IN PLACE (the
   * lock-on-minimize toggle, the auto-lock timeout), then calls this. Because
   * #vault is `$state.raw`, an in-place NESTED mutation does NOT fire reactivity,
   * so the Settings toggles (`$derived`) and App.svelte's idle `$effect` never
   * see the change — the toggle looks frozen and a timeout change does not apply
   * live. Reassign #vault (shallow — the same P3-02 pattern the entry-CRUD
   * methods use) BEFORE persisting so reactivity fires, then save.
   *
   * Scoped to settings edits so the hot, IO-critical save() path keeps its exact
   * contract (no extra reassign on every autosave).
   */
  async saveSettingsChange(opts?: { maxBackups?: number }): Promise<void> {
    const vault = this._requireVault();
    // P3-02: surface the in-place settings mutation to $state.raw consumers.
    this.#vault = { ...vault };
    await this.save(opts);
  }

  // ---------------------------------------------------------------------------
  // Phase-11: B-side raw-blob save (sync path, SAFE-02, D-10)
  // ---------------------------------------------------------------------------

  /**
   * Save pre-sealed vault bytes directly through the adapter.
   *
   * Used by the B-side sync handler after `resealInnerDoc` produces a sealed blob.
   * Bypasses the re-encryption step of `save()` because the bytes are already sealed
   * by `resealInnerDoc`. Runs through the adapter's save-mutex + backup rotation
   * exactly like `save()` does — no vault_write_atomic invoke (Pitfall 5 / SAFE-02).
   *
   * SECURITY: `sealedBytes` MUST be ciphertext produced by `resealInnerDoc` (never
   * plaintext). The caller owns wiping any plaintext that produced these bytes (SAFE-04).
   *
   * @internal — sync orchestration only; do NOT call from UI code.
   * @param sealedBytes Pre-sealed vault document bytes (output of resealInnerDoc).
   * @param opts        Optional save options (maxBackups defaults to 5).
   */
  async saveRawBlob(sealedBytes: Uint8Array, opts?: { maxBackups?: number }): Promise<void> {
    const adapter = this.#adapter;
    if (adapter === null) {
      throw new Error('VaultSession.saveRawBlob: session is locked — no adapter mounted.');
    }
    await adapter.save(sealedBytes, {
      maxBackups: opts?.maxBackups ?? 5,
    });
  }

  // ---------------------------------------------------------------------------
  // Phase-11: B-side session reload after sync (D-07)
  // ---------------------------------------------------------------------------

  /**
   * Reload the in-memory vault session from a freshly-merged InnerDoc.
   *
   * Called by the B-side `sync-merged-blob-received` event handler in
   * syncOrchestration.ts AFTER B has re-merged, re-sealed, and adapter-saved the
   * merged blob. Takes the ALREADY-DECRYPTED InnerDoc (not ciphertext — all crypto
   * runs in WASM). Uses the P3-02 whole-value reassignment pattern so $state.raw
   * reactivity fires and open list/detail views re-render from the merged data.
   * A tombstoned open entry falls back to the list automatically (D-07).
   *
   * D-06 lock-wins: if the vault locked mid-sync (#vault is null), returns early
   * WITHOUT throwing. The lock takes precedence; the caller confirms failure with
   * `syncConfirmSave(false)`.
   *
   * SAFE-04: `mergedEntries` is the plaintext — the caller MUST secureWipe the
   * source JSON bytes (the entriesBytes Uint8Array from TextEncoder) immediately
   * after this returns, before any await. This method stores `mergedEntries` by
   * reference in #vault; the caller should null-out the source reference after wipe.
   *
   * @param mergedEntries  The merged InnerDoc (already decrypted + re-merged by
   *                       the B-side handler — NOT ciphertext).
   */
  async reloadFromMergedInner(mergedEntries: object): Promise<void> {
    const vault = this.#vault;
    if (vault === null) return; // D-06 lock-wins: session locked mid-sync — no-op
    // P3-02: whole-value reassignment fires $state.raw reactivity.
    // Preserve the existing outer doc (wrappedKeys, modifiedAt already updated by
    // resealInnerDoc in the handler) and replace only the in-memory entries reference.
    this.#vault = { doc: vault.doc, entries: mergedEntries };
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

  /**
   * Restore a soft-deleted entry (ENTRY-05). Clears the tombstone via the core
   * `restoreEntry` verb, then reassigns #vault for $state.raw reactivity (P3-02).
   * Distinct from updateEntry because updateEntry refuses tombstones by design.
   *
   * @throws EntryNotFoundError if `id` is unknown or the entry is not soft-deleted.
   */
  restoreEntry(id: string): import('@cryptiq/core').Entry {
    const vault = this._requireVault();
    const entry = restoreEntry(vault, id);
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
  // Master-password change (AUTH-08 / AUTH-10)
  // ---------------------------------------------------------------------------

  /**
   * Change the master password for the currently unlocked vault.
   *
   * Wraps `changeMasterPassword` from @cryptiq/core so the UI never needs to call
   * unsafeGetKey() directly. The vault doc is mutated in place; the caller MUST call
   * save() after this to persist the new master wrap to disk.
   *
   * @param currentPassword  The current master password bytes (verifies ownership).
   * @param newPassword      The new master password bytes.
   * @throws WrongPasswordError if currentPassword is incorrect.
   * @throws Error if the session is not unlocked.
   */
  async changeMasterPassword(
    currentPassword: Uint8Array,
    newPassword: Uint8Array,
  ): Promise<void> {
    const vault = this._requireVault();
    const key = this.#vaultKey;
    if (key === null) {
      throw new Error('VaultSession.changeMasterPassword: session is locked.');
    }
    // P5-07 (LOCK-04 / Pitfall 1): run the ~2s Argon2id derive as a tracked
    // critical op so (1) the idle controller defers auto-lock while it runs and
    // (2) the event-driven lock() callers (App.svelte sleep/blur/close), which
    // bypass the idle guard, defer their secureWipe until #criticalOpDone
    // resolves — the live #vaultKey is NEVER zeroed mid-derive (which would seal
    // an all-zero key → corrupt wrappedKeys.master → permanent lockout).
    await this.#withCriticalOp(() =>
      changeMasterPassword(vault, key, { currentPassword, newPassword }),
    );
  }

  /**
   * AUTH-08: Re-wrap the master key after a recovery-key unlock, where the old
   * master password is UNKNOWN (and therefore cannot be passed to changeMasterPassword).
   *
   * This method is ONLY valid immediately after a recovery-key unlock, before the user
   * has set any new master password. It uses the internal @cryptiq/core/internal crypto
   * to directly derive + replace the master wrap using the live vault key.
   *
   * After calling this method, call save() to persist the new master wrap to disk.
   *
   * @param newPassword  The new master password bytes.
   */
  async resetMasterPasswordAfterRecovery(newPassword: Uint8Array): Promise<void> {
    const vault = this._requireVault();
    const key = this.#vaultKey;
    if (key === null) {
      throw new Error('VaultSession.resetMasterPasswordAfterRecovery: session is locked.');
    }
    // P5-07 (LOCK-04 / Pitfall 1): like changeMasterPassword, this performs a
    // long, key-reading derive — wrapKey(key, …) seals the LIVE #vaultKey under
    // the newly-derived key inside crypto_aead_xchacha20poly1305_ietf_encrypt.
    // If lock() zeroed #vaultKey mid-derive, wrapKey would seal an all-zero key
    // and the subsequent save() (UnlockScreen.handleSetNewMaster) would persist a
    // corrupt wrappedKeys.master → permanent lockout. Route the ENTIRE derive+wrap
    // through #withCriticalOp so lock() defers its secureWipe of #vaultKey until
    // this completes. (The derivedKey wiped in the inner finally is a DISTINCT
    // buffer from the live #vaultKey, which must NOT be wiped while this runs.)
    await this.#withCriticalOp(async () => {
      // Use the internal crypto path to set a new master wrap without needing to verify
      // the old password (AUTH-08: after recovery unlock, old master password is unknown).
      // Import the internal crypto verbs from @cryptiq/core/internal (internal.ts exports them).
      const { calibrateArgon2id, deriveKey, wrapKey } = await import('@cryptiq/core/internal');
      const { params } = await calibrateArgon2id();
      const derivedKey = await deriveKey(newPassword, params);
      try {
        const newWrap = await wrapKey(key, derivedKey, params);
        vault.doc.wrappedKeys.master = newWrap;
        vault.doc.meta.modifiedAt = new Date().toISOString();
      } finally {
        await secureWipe(derivedKey);
      }
    });
  }

  // ---------------------------------------------------------------------------
  // Export support (Phase 6 — EXPORT-01 / P6-09 / P6-10)
  // ---------------------------------------------------------------------------

  /**
   * Phase 6 (P6-10): the filesystem path to the current vault file, or null when
   * the session is locked. Exposed so SettingsShell can pass it to the
   * vault_export_copy Rust command without touching the private adapter reference.
   *
   * Non-secret: this is a filesystem path, not a key or plaintext data.
   */
  get vaultPath(): string | null {
    return this.#vaultPath;
  }

  /**
   * Phase 6 (P6-10 / Pitfall 3 defense): await the adapter's save-mutex so the
   * export pre-flight can guarantee that any in-flight save has completed BEFORE
   * the vault bytes are copied to the user-chosen destination.
   *
   * Why: auto-save-on-blur (P4-11) may be writing the vault when the user clicks
   * Export. Flushing the mutex guarantees the exported file includes the latest edits
   * rather than an earlier committed state. The Rust command only copies the canonical
   * `.cryptiq` (never `.cryptiq.tmp`), so even a racing copy lands on a valid vault —
   * but the mutex flush eliminates the ambiguity entirely.
   *
   * No-op (resolves immediately) when the session is locked or the adapter is null.
   */
  async awaitSaveMutex(): Promise<void> {
    await this.#adapter?.awaitSaveMutex();
  }

  /**
   * Phase 6 (P6-09 / AUTH-11 / T-06-15): verify the master password by
   * ALWAYS re-deriving Argon2id from `passwordBytes` and attempting to unwrap the
   * master key. Returns `true` if the password is correct, `false` if not.
   *
   * Security invariants:
   *   - ALWAYS re-derives (no cached check) — AUTH-11 / P6-09 always-re-derive contract.
   *   - The Poly1305 MAC inside `tryUnwrap` IS the correctness proof: a non-null return
   *     means the password decrypted the master wrap successfully (MAC-authenticated).
   *   - NEVER compares against the live `#vaultKey` buffer (no memcmp, no key exposure).
   *   - Derived key and the throwaway unwrapped key are both wiped in `finally`.
   *   - `#vaultKey` is never rebound — the session continues using its existing key.
   *   - Never logs the password (T-06-19).
   *
   * Runs inside `#withCriticalOp` so the idle controller defers auto-lock for the
   * ~1s Argon2id re-derive (same protection as changeMasterPassword).
   *
   * Returns `false` (not throws) when the password is wrong or the session is locked.
   *
   * @param passwordBytes  UTF-8 encoded password bytes. Caller MUST zero in `finally`.
   */
  async verifyMasterPassword(passwordBytes: Uint8Array): Promise<boolean> {
    const vault = this.#vault;
    if (vault === null) return false;

    return this.#withCriticalOp(async () => {
      const { deriveKey, tryUnwrap, secureWipe: wipe, getSodium } = await import('@cryptiq/core/internal');
      const sodium = await getSodium();
      const masterWrap = vault.doc.wrappedKeys.master;

      // The stored kdf.salt is a base64 string (per WrappedKey wire format, decision 27).
      // Convert to Uint8Array before passing to deriveKey (which expects KdfParams.salt: Uint8Array).
      const kdfParams = {
        algorithm: 2 as const,
        opsLimit: masterWrap.kdf.opsLimit,
        memLimit: masterWrap.kdf.memLimit,
        salt: sodium.from_base64(masterWrap.kdf.salt, sodium.base64_variants.ORIGINAL),
      };

      const derivedKey = await deriveKey(passwordBytes, kdfParams);
      let unwrapped: Uint8Array | null = null;
      try {
        unwrapped = await tryUnwrap(masterWrap, derivedKey);
        return unwrapped !== null;
      } finally {
        // Zero BOTH throwaway buffers — the live #vaultKey is NEVER touched.
        await wipe(derivedKey);
        if (unwrapped !== null) {
          await wipe(unwrapped);
        }
      }
    });
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
