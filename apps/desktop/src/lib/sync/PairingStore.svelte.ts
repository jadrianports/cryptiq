// apps/desktop/src/lib/sync/PairingStore.svelte.ts
//
// Reactive device-list store for the pairing subsystem (Phase 9).
//
// ARCHITECTURE DECISIONS:
//
//   $state.raw (NOT $state):
//     Peer records are secret-adjacent (they contain device IDs, public keys, pairing
//     timestamps). A deep Svelte `$state` proxy could expose these through DevTools /
//     the reactivity graph. `$state.raw` stores by reference and only reacts to
//     WHOLE-OBJECT reassignment — same discipline as the vault state in vault.svelte.ts.
//     This MUST NOT become `$state(`. (CLAUDE.md frontend/security, Pitfall 7 defense.)
//
//   Non-reactive #localDeviceId:
//     The local device's stable UUID and identity info are read once on init and never
//     need reactivity — they don't change during a session. Kept as plain private fields.
//
//   No #vaultKey:
//     The store MUST NOT hold or copy vaultSession's #vaultKey. The D-18 unlock guard
//     (assertVaultUnlockedForPairing in syncBridge.ts) enforces that the vault is
//     unlocked BEFORE any pairing invoke fires. The store itself never retains key bytes.
//
//   Whole-array reassignment on mutation:
//     Every mutating method (unpair, renameDevice) reassigns `#peers` to a fresh array
//     so that $state.raw reactivity fires (consumers see the new reference).
//
//   D-14 cap (list-shaped):
//     `peers.json` is list-shaped (cap 1 for v2.0) but the store holds a full array
//     so the cap can be lifted for mesh/Autopilot without API changes.
//
//   Module-level singleton:
//     `export const pairingStore = new PairingStore()` — mirrors vaultSession export
//     at the bottom of vault.svelte.ts. Import the singleton, not the class.
//
// USAGE:
//   1. Call `await pairingStore.init(configDir)` after vault unlock.
//   2. Read `pairingStore.peers` reactively in Svelte components (Phase 12).
//   3. Call `pairingStore.unpair(configDir, deviceId)` to remove a peer.
//   4. Call `pairingStore.renameDevice(deviceId, name)` for a local rename (D-12).
//
// Phase 12 delivers PairingScreen / DeviceListPanel — this file is DATA ONLY.

import type { PeerRecord, LocalDeviceInfo } from './syncBridge';
import { getLocalDeviceInfo, peersJsonRead, unpairDevice } from './syncBridge';

class PairingStore {
  // $state.raw: peer list reassigned on add/remove/update — no deep proxy (Pitfall 7).
  // MUST use $state.raw, NEVER $state( for secret-adjacent peer records.
  #peers = $state.raw<PeerRecord[]>([]);

  // NON-reactive: read once on init, never changes during a session.
  #localDeviceId: string | null = null;

  // Optional: full local device info (public key + name) loaded on init.
  // Non-reactive — not needed in the reactive graph.
  #localDeviceInfo: LocalDeviceInfo | null = null;

  // ---------------------------------------------------------------------------
  // Readable state (reactive via $state.raw)
  // ---------------------------------------------------------------------------

  /**
   * The current list of paired peers.
   *
   * Reactive via $state.raw — consumers see a new array reference on every mutation.
   * Returns a snapshot; do NOT mutate the returned array in-place.
   */
  get peers(): PeerRecord[] {
    return this.#peers;
  }

  /**
   * The stable UUID of this device, loaded on init.
   * null before init() completes.
   */
  get localDeviceId(): string | null {
    return this.#localDeviceId;
  }

  /**
   * Full local device info (public key + name + ID), loaded on init.
   * null before init() completes.
   */
  get localDeviceInfo(): LocalDeviceInfo | null {
    return this.#localDeviceInfo;
  }

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  /**
   * Load local device info and peers list from peers.json.
   *
   * Call after vault unlock. Defaults to an empty peers list when peers.json
   * does not yet exist (peersJsonRead returns [] in that case).
   *
   * Error handling: if getLocalDeviceInfo fails (first-launch CredManager race),
   * #localDeviceId stays null — non-fatal, pairing UI shows a spinner.
   * If peersJsonRead fails, #peers stays [] — fail open (empty list, no crash).
   *
   * @param configDir Tauri app config directory (passed to Rust commands).
   */
  async init(configDir: string): Promise<void> {
    // Load local device info (public key + stable UUID + hostname name).
    try {
      const info = await getLocalDeviceInfo(configDir);
      this.#localDeviceInfo = info;
      this.#localDeviceId = info.deviceId;
    } catch {
      // Non-fatal: CredManager may not be initialized on first launch.
      // #localDeviceId remains null; UI should handle the uninitialized state.
      this.#localDeviceInfo = null;
      this.#localDeviceId = null;
    }

    // Load peers from peers.json (defaults to [] when file absent).
    try {
      const peers = await peersJsonRead(configDir);
      // Whole-array assignment (fires $state.raw reactivity).
      this.#peers = [...peers];
    } catch {
      // Fail open: if peers.json is corrupt or unreadable, show empty list.
      this.#peers = [];
    }
  }

  // ---------------------------------------------------------------------------
  // Mutations (whole-array reassignment for $state.raw reactivity)
  // ---------------------------------------------------------------------------

  /**
   * Remove a peer by deviceId from peers.json and the local list.
   *
   * Calls unpairDevice (syncBridge) to write the updated peers.json, then
   * reassigns #peers so consumers see the removal immediately (optimistic UI).
   * On Tauri invoke error the local list is NOT rolled back — caller handles errors.
   *
   * D-17: own device identity keypair is NOT removed (enforced in Rust).
   *
   * @param configDir Tauri app config directory.
   * @param deviceId  UUID of the peer to remove.
   */
  async unpair(configDir: string, deviceId: string): Promise<void> {
    await unpairDevice(configDir, deviceId);
    // Whole-array reassignment fires $state.raw reactivity.
    this.#peers = this.#peers.filter((p) => p.deviceId !== deviceId);
  }

  /**
   * Rename a peer locally (D-12: locally editable, does NOT propagate to peer).
   *
   * This is a LOCAL-ONLY operation in v2.0 — peers.json is not synced, so the
   * peer's copy of our name will remain whatever was set during pairing. No
   * network call is made.
   *
   * Reassigns the whole #peers array with the updated record so $state.raw
   * reactivity fires.
   *
   * @param deviceId The UUID of the peer to rename.
   * @param name     The new friendly name.
   */
  renameDevice(deviceId: string, name: string): void {
    // Map returns a new array; reassignment fires $state.raw reactivity.
    this.#peers = this.#peers.map((p) =>
      p.deviceId === deviceId ? { ...p, deviceName: name } : p,
    );
  }

  /**
   * Reset store to initial state (e.g., on vault lock).
   * Clears peers list and local device info.
   */
  reset(): void {
    this.#peers = [];
    this.#localDeviceId = null;
    this.#localDeviceInfo = null;
  }
}

// ---------------------------------------------------------------------------
// Module-level singleton (mirrors `export const vaultSession = new VaultSession()`)
// ---------------------------------------------------------------------------

/**
 * The module-level PairingStore singleton.
 *
 * Import this, not the class:
 *   import { pairingStore } from '$lib/sync/PairingStore.svelte';
 */
export const pairingStore = new PairingStore();
