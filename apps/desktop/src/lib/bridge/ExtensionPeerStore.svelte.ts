// apps/desktop/src/lib/bridge/ExtensionPeerStore.svelte.ts
//
// Reactive browser-extension association store (Phase 15, BRIDGE-09).
//
// ARCHITECTURE DECISIONS:
//
//   $state.raw (NOT $state):
//     Association records are secret-adjacent (they contain client public keys, a
//     pairing-token hash, and labels). A deep Svelte `$state` proxy could expose
//     these through DevTools / the reactivity graph. `$state.raw` stores by
//     reference and only reacts to WHOLE-OBJECT reassignment — same discipline as
//     PairingStore.svelte.ts (sync) and vaultSession's #vaultKey. This MUST NOT
//     become `$state(`. (CLAUDE.md frontend/security, T-15-10.)
//
//   Whole-array reassignment on mutation:
//     Every mutating method (revoke, renameLabel) reassigns `#associations` to a
//     fresh array so that $state.raw reactivity fires (consumers see the new
//     reference).
//
//   Fail-open init:
//     init() never throws into the UI — a read error yields an empty list, mirroring
//     PairingStore.init()'s fail-open peersJsonRead handling.
//
//   Module-level singleton:
//     `export const extensionPeerStore = new ExtensionPeerStore()` — mirrors
//     `pairingStore` / `vaultSession`. Import the singleton, not the class.
//
// USAGE:
//   1. Call `await extensionPeerStore.init(configDir)` after settings mount.
//   2. Read `extensionPeerStore.associations` reactively in ExtensionSettingsSection.
//   3. Call `extensionPeerStore.revoke(configDir, clientId)` to remove an association.
//   4. Call `extensionPeerStore.renameLabel(configDir, clientId, label)` to rename
//      (persists via rename_extension_association, unlike sync's local-only rename).
//   5. Call `extensionPeerStore.reset()` on vault lock (T-15-10).
//
// Source: 15-05-PLAN.md Task 1; 15-PATTERNS.md "ExtensionPeerStore.svelte.ts" section.

import type { ExtensionAssociation } from './bridgeCommands';
import {
  extensionPeersList,
  renameExtensionAssociation,
  revokeExtensionAssociation,
} from './bridgeCommands';

class ExtensionPeerStore {
  // $state.raw: association list reassigned on add/remove/update — no deep proxy.
  // MUST use $state.raw, NEVER $state( for secret-adjacent association records.
  #associations = $state.raw<ExtensionAssociation[]>([]);

  // ---------------------------------------------------------------------------
  // Readable state (reactive via $state.raw)
  // ---------------------------------------------------------------------------

  /**
   * The current list of browser-extension associations.
   *
   * Reactive via $state.raw — consumers see a new array reference on every mutation.
   * Returns a snapshot; do NOT mutate the returned array in-place.
   */
  get associations(): ExtensionAssociation[] {
    return this.#associations;
  }

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  /**
   * Load the association list from extension-peers.json.
   *
   * Call after settings mount / vault unlock. Defaults to an empty list when the
   * sidecar does not yet exist (extensionPeersList returns [] in that case).
   *
   * Error handling: fail open — a read error (corrupt file, IO error) yields an
   * empty list rather than throwing into the UI.
   *
   * @param configDir Tauri app config directory (passed to Rust commands).
   */
  async init(configDir: string): Promise<void> {
    try {
      const associations = await extensionPeersList(configDir);
      // Whole-array assignment (fires $state.raw reactivity).
      this.#associations = [...associations];
    } catch {
      // Fail open: if extension-peers.json is corrupt or unreadable, show empty list.
      this.#associations = [];
    }
  }

  // ---------------------------------------------------------------------------
  // Mutations (whole-array reassignment for $state.raw reactivity)
  // ---------------------------------------------------------------------------

  /**
   * Revoke an association by clientId (D-04 confirm-before-revoke flow calls this
   * on confirm). Removes the persisted record AND evicts the live peer-lookup
   * cache Rust-side, so the cut takes effect immediately.
   *
   * @param configDir Tauri app config directory.
   * @param clientId  The association's stable opaque identifier.
   */
  async revoke(configDir: string, clientId: string): Promise<void> {
    await revokeExtensionAssociation(configDir, clientId);
    // Whole-array reassignment fires $state.raw reactivity.
    this.#associations = this.#associations.filter((a) => a.clientId !== clientId);
  }

  /**
   * Rename an association's label. Unlike sync's PairingStore.renameDevice (which
   * is local-only), this PERSISTS via rename_extension_association — the app owns
   * both sides of this record (no peer device to stay out of sync with).
   *
   * @param configDir Tauri app config directory.
   * @param clientId  The association's stable opaque identifier.
   * @param label     The new friendly label.
   */
  async renameLabel(configDir: string, clientId: string, label: string): Promise<void> {
    await renameExtensionAssociation(configDir, clientId, label);
    // Map returns a new array; reassignment fires $state.raw reactivity.
    this.#associations = this.#associations.map((a) =>
      a.clientId === clientId ? { ...a, label } : a,
    );
  }

  /**
   * Reset store to initial state (e.g., on vault lock — T-15-10).
   * Clears the association list so secret-adjacent data does not outlive the
   * unlocked session.
   */
  reset(): void {
    this.#associations = [];
  }
}

// ---------------------------------------------------------------------------
// Module-level singleton (mirrors `export const pairingStore = new PairingStore()`)
// ---------------------------------------------------------------------------

/**
 * The module-level ExtensionPeerStore singleton.
 *
 * Import this, not the class:
 *   import { extensionPeerStore } from '$lib/bridge/ExtensionPeerStore.svelte';
 */
export const extensionPeerStore = new ExtensionPeerStore();
