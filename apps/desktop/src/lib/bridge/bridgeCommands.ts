// apps/desktop/src/lib/bridge/bridgeCommands.ts
//
// Typed `invoke` wrappers for every registered browser-extension-bridge Rust command
// (Plan 15-04's Tauri commands in extension_bridge.rs). Mirrors syncBridge.ts's
// wrapper-per-command convention — components/stores call these, never raw invoke().
//
// ARCHITECTURE:
//   - This file is `apps/desktop` (NOT packages/core): importing @tauri-apps/* is allowed.
//   - Each wrapper calls `invoke('<snake_case_command>', { <camelCaseArgs> })`. Tauri v2
//     maps camelCase JS object keys -> snake_case Rust params automatically.
//   - ExtensionAssociation mirrors extension_peers.rs's ExtensionPeerRecord
//     (#[serde(rename_all = "camelCase")]).
//
// SECRET DISCIPLINE:
//   ExtensionAssociation NEVER contains a raw pairing token or private key — only
//   public keys + metadata + a one-way hash (pairingTokenHash). See extension_peers.rs.
//
// REGISTERED COMMANDS (lib.rs / extension_bridge.rs Plan 15-04):
//   bridge_approve, bridge_deny, extension_peers_list,
//   rename_extension_association, revoke_extension_association_cmd

import { invoke } from '@tauri-apps/api/core';

/**
 * One browser-extension association record (mirrors Rust's ExtensionPeerRecord).
 *
 * NEVER contains a raw pairing token or private key — only public keys + metadata
 * plus a one-way hash of the pairing token.
 */
export interface ExtensionAssociation {
  /** Stable opaque identifier for this association (minted at approval). */
  clientId: string;
  /** Hex-encoded 32-byte Curve25519 public key of the extension's association keypair. */
  clientPublicKey: string;
  /** Human-editable label (auto-named from the detected browser at approval, D-02). */
  label: string;
  /** ISO 8601 timestamp of when this association was approved. */
  pairedAt: string;
  /** ISO 8601 timestamp of the most recent authenticated RPC from this association. */
  lastUsedAt: string | null;
  /** Hex-encoded 32-byte BLAKE2b-256 digest of the pairing token — a HASH, never the raw token. */
  pairingTokenHash: string;
}

/**
 * Resolve a pending TOFU association with Approve.
 *
 * @param sessionId The pending-association session id from the
 *                   `bridge://associate-request` event payload.
 */
export async function bridgeApprove(sessionId: string): Promise<void> {
  return invoke<void>('bridge_approve', { sessionId });
}

/**
 * Resolve a pending TOFU association with Deny.
 *
 * @param sessionId The pending-association session id from the
 *                   `bridge://associate-request` event payload.
 */
export async function bridgeDeny(sessionId: string): Promise<void> {
  return invoke<void>('bridge_deny', { sessionId });
}

/**
 * List every persisted browser-extension association.
 *
 * @param configDir Tauri app config directory.
 */
export async function extensionPeersList(configDir: string): Promise<ExtensionAssociation[]> {
  return invoke<ExtensionAssociation[]>('extension_peers_list', { configDir });
}

/**
 * Rename an association's local label (persists to extension-peers.json).
 *
 * @param configDir Tauri app config directory.
 * @param clientId  The association's stable opaque identifier.
 * @param label     The new friendly label.
 */
export async function renameExtensionAssociation(
  configDir: string,
  clientId: string,
  label: string,
): Promise<void> {
  return invoke<void>('rename_extension_association', { configDir, clientId, label });
}

/**
 * Revoke one association. Cuts exactly that extension's access — its very next
 * `rpc` fails `NotAssociated`; it must re-approve (TOFU) to reconnect.
 *
 * @param configDir Tauri app config directory.
 * @param clientId  The association's stable opaque identifier.
 */
export async function revokeExtensionAssociation(
  configDir: string,
  clientId: string,
): Promise<void> {
  return invoke<void>('revoke_extension_association_cmd', { configDir, clientId });
}

/**
 * Start the extension-bridge named-pipe listener (UX-05 kill-switch ON). Idempotent —
 * a redundant call while the listener is already running is a no-op. Takes no args: the
 * Rust command receives only the injected `app` handle (the bridge toggle is not a vault
 * operation, so there is no configDir/vaultPath param and no vault-unlock guard).
 */
export async function startExtensionBridgeListener(): Promise<void> {
  return invoke<void>('start_extension_bridge_listener');
}

/**
 * Stop the extension-bridge listener (UX-05 kill-switch OFF). Fires the Rust `cancel_tx`
 * to break the accept loop and drop the pending pipe instance so the extension observes a
 * plain disconnect (D-01). Idempotent — safe to call when no listener is running.
 */
export async function stopExtensionBridgeListener(): Promise<void> {
  return invoke<void>('stop_extension_bridge_listener');
}
