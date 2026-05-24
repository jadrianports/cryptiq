// apps/desktop/src/lib/state/vault.svelte.ts
//
// Phase 1: D-stub skeleton. All methods throw "Phase 2 will implement".
// The class shape (per ARCHITECTURE.md §5.2) is correct so Phase 2 just fills in bodies.
//
// Why this shape:
//  - Module-scoped singleton: only one unlocked vault at a time, anywhere in the app.
//  - $state.raw (not $state): avoid Svelte's deep proxy on entry data
//    (defends Pitfall 7 — proxied passwords could leak through DevTools).
//  - vault key is a NON-reactive private field (no UI reactivity needed on bytes).
//  - lock() is the ONLY way to clear; sodium.memzero is called on every key buffer
//    (Phase 2 wires the real sodium import).

// Phase 1 stub — Phase 2 imports the real type from @cryptiq/core
type UnlockedVault = unknown;

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
   * Phase 2 will populate after a successful unlockVault() call.
   * Phase 1: throws so any accidental call surfaces loudly.
   */
  mount(_vault: UnlockedVault, _vaultKey: Uint8Array): void {
    throw new Error('VaultSession.mount: Phase 2 will implement.');
  }

  /**
   * Phase 2 will call sodium.memzero on #vaultKey and drop references.
   * Phase 1: throws (no key to zero yet).
   */
  lock(): void {
    throw new Error('VaultSession.lock: Phase 2 will implement.');
  }

  /**
   * For the crypto layer: hand back the key buffer (e.g., master-password change).
   * Never expose to UI code. In Phase 1 the key is always null (mount() throws),
   * so the throw path is the only reachable one; Phase 2 wires mount() to assign
   * #vaultKey and this method then returns it.
   * @internal
   */
  unsafeGetKey(): Uint8Array {
    if (this.#vaultKey !== null) return this.#vaultKey;
    throw new Error('VaultSession.unsafeGetKey: Phase 2 will implement.');
  }
}

// Module-level singleton — the only handle the rest of the app sees.
export const vaultSession = new VaultSession();
