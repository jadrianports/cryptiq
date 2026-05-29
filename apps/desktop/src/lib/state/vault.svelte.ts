// apps/desktop/src/lib/state/vault.svelte.ts
//
// The in-memory unlocked-vault session singleton. Phase 1 scaffolded the shape; Phase 2
// (Plan 02-04) fills the method bodies against the @cryptiq/core verb-first API.
//
// Why this shape:
//  - Module-scoped singleton: only one unlocked vault at a time, anywhere in the app.
//  - $state.raw (NOT $state): avoid Svelte's deep reactive proxy on the decrypted vault
//    data (defends Pitfall 7 — a deep proxy could surface decrypted secrets through
//    DevTools / the reactivity graph). $state.raw stores the value by reference and only
//    reacts to WHOLE-OBJECT reassignment. This MUST NOT become `$state` (locked decision).
//  - The vault KEY is a NON-reactive private field (#vaultKey): the UI never needs to react
//    to raw key bytes, and keeping it out of the reactive graph is part of the Pitfall-7
//    defense. lock() zeroes it via @cryptiq/core's secureWipe (SEC-09) so the desktop layer
//    never imports raw libsodium (the ESLint no-restricted-imports ban stays intact).

import type { UnlockedVault } from '@cryptiq/core';
import { secureWipe } from '@cryptiq/core';

class VaultSession {
  // $state.raw — Svelte 5 runes pattern for "whole-object reassignment without deep proxying."
  #vault = $state.raw<UnlockedVault | null>(null);
  #vaultKey: Uint8Array | null = null;

  get vault(): UnlockedVault | null {
    return this.#vault;
  }
  get isUnlocked(): boolean {
    return this.#vault !== null;
  }

  /**
   * Mount a freshly unlocked vault + its 32-byte key after a successful
   * createVault()/unlockVault() call. The caller hands ownership of `vaultKey` to the
   * session; from here only lock() may zero it.
   */
  mount(vault: UnlockedVault, vaultKey: Uint8Array): void {
    this.#vault = vault;
    this.#vaultKey = vaultKey;
  }

  /**
   * Lock the session: zero the vault key buffer in place (SEC-09) and drop all references.
   * secureWipe (from @cryptiq/core) calls sodium.memzero under the hood — the desktop layer
   * never touches raw libsodium. Idempotent: locking an already-locked session is a no-op.
   *
   * Note: memzero is a best-effort defense (JS GC may have copied bytes); it is the
   * documented mitigation, not a guarantee (see 02-security-design.md).
   */
  lock(): void {
    const key = this.#vaultKey;
    this.#vault = null;
    this.#vaultKey = null;
    if (key !== null) {
      // Fire-and-forget: secureWipe awaits getSodium() (already resolved by unlock time).
      void secureWipe(key);
    }
  }

  /**
   * For the crypto layer ONLY (e.g. changeMasterPassword, saveVault): hand back the live key
   * buffer. NEVER expose this to UI code. Throws if the session is locked.
   * @internal
   */
  unsafeGetKey(): Uint8Array {
    if (this.#vaultKey !== null) return this.#vaultKey;
    throw new Error('VaultSession.unsafeGetKey: session is locked (no key mounted).');
  }
}

// Module-level singleton — the only handle the rest of the app sees.
export const vaultSession = new VaultSession();
