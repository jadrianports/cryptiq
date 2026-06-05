// apps/desktop/src/lib/sync/syncBridge.ts
//
// Typed `invoke` wrappers for every registered pairing Rust command.
//
// ARCHITECTURE:
//   - This file is `apps/desktop` (NOT packages/core): importing @tauri-apps/* and the
//     Svelte vaultSession singleton is ALLOWED here.
//   - Each wrapper calls `invoke('<snake_case_command>', { <camelCaseArgs> })`. Tauri v2
//     maps camelCase JS object keys → snake_case Rust params automatically.
//   - LocalDeviceInfo / PeerRecord / PairingInitResponse mirror the Rust serde structs
//     in pairing.rs (PeerRecord uses `#[serde(rename_all = "camelCase")]`).
//
// D-18 UNLOCK GUARD:
//   `assertVaultUnlockedForPairing(vaultSession.isUnlocked)` is called BEFORE every
//   pairing-INITIATING invoke (pairingInitiate, pairingConnect, pairingConfirm).
//   A locked vault throws PairingRequiresUnlockError locally — no IPC/network is touched.
//
// D-11 CODE VALIDATION:
//   `validatePairingCode(code)` is called BEFORE `pairingConnect`'s invoke so a mistyped
//   code throws PairingCodeInvalidError locally — no handshake is attempted for a typo.
//
// PRIVATE KEY INVARIANT:
//   No wrapper returns or accepts a private key. `getLocalDeviceInfo` returns only the
//   public key + IDs. The private key is generated and stored exclusively in Rust.
//
// REGISTERED COMMANDS (from lib.rs / pairing.rs Plan 09-05):
//   get_local_device_info, device_key_write, device_key_read, device_key_delete,
//   generate_qr_svg, get_lan_ip,
//   pairing_initiate, pairing_connect, pairing_confirm, pairing_finalize,
//   unpair_device, peers_json_read
//
// Source: 09-PATTERNS.md §syncBridge.ts, CLAUDE.md locked decisions.

import { invoke } from '@tauri-apps/api/core';
import {
  validatePairingCode,
  assertVaultUnlockedForPairing,
} from '@cryptiq/core';
import { vaultSession } from '../state/vault.svelte';

// ---------------------------------------------------------------------------
// TypeScript interfaces — camelCase mirrors of Rust serde structs (pairing.rs)
// ---------------------------------------------------------------------------

/**
 * This device's identity info returned by `get_local_device_info`.
 * NEVER includes the private key — the private key stays in Rust/CredManager (D-13).
 *
 * Rust struct: LocalDeviceInfo { device_id, static_public_key, device_name }
 * Serde:       explicit #[serde(rename = "camelCase")] per field
 */
export interface LocalDeviceInfo {
  /** Stable opaque UUID v4 — NOT derived from the key (D-13). */
  deviceId: string;
  /** Hex-encoded 32-byte Curve25519 static PUBLIC key. Private key stays in Rust. */
  staticPublicKey: string;
  /** Hostname-seeded friendly name (locally editable, D-12). */
  deviceName: string;
}

/**
 * One paired peer record from peers.json.
 * NEVER contains a private key or the pairing PSK.
 *
 * Rust struct: PeerRecord — #[serde(rename_all = "camelCase")]
 */
export interface PeerRecord {
  deviceId: string;
  deviceName: string;
  /** Hex-encoded 32-byte Curve25519 static PUBLIC key of the peer. */
  staticPublicKey: string;
  vaultPairId: string;
  /** ISO 8601 timestamp of when this pairing was established. */
  pairedAt: string;
  lastSyncedAt: string | null;
}

/**
 * Returned by pairing_initiate (Device A) and pairing_connect (Device B).
 *
 * Rust struct: PairingInitResponse — #[serde(rename_all = "camelCase")]
 */
export interface PairingInitResponse {
  /** SVG string for the QR code. Empty string on Device B side. */
  qrSvg: string;
  /** Full pairing code string (IP:PORT:BASE32+CHECKCHAR). Empty on Device B. */
  base32Code: string;
  /** Unique session identifier used by pairingConfirm / pairingFinalize. */
  sessionId: string;
}

// ---------------------------------------------------------------------------
// Pairing-initiating commands — D-18 unlock guard runs BEFORE every invoke
// ---------------------------------------------------------------------------

/**
 * Device A: initiate a pairing session.
 *
 * D-18: assertVaultUnlockedForPairing called before invoke — a locked vault
 * throws PairingRequiresUnlockError locally, no IPC is sent.
 *
 * Returns PairingInitResponse containing the QR SVG, base32Code bundle, and sessionId.
 */
export async function pairingInitiate(configDir: string): Promise<PairingInitResponse> {
  assertVaultUnlockedForPairing(vaultSession.isUnlocked); // D-18
  return invoke<PairingInitResponse>('pairing_initiate', { configDir });
}

/**
 * Device B (INITIATOR): connect to an existing pairing session using the typed code.
 *
 * D-18: assertVaultUnlockedForPairing called before invoke.
 * D-11: validatePairingCode(code) called before invoke — a typo throws
 *       PairingCodeInvalidError locally, no handshake attempt is made.
 *
 * Returns PairingInitResponse with empty qrSvg/base32Code but a valid sessionId.
 */
export async function pairingConnect(
  configDir: string,
  code: string,
): Promise<PairingInitResponse> {
  assertVaultUnlockedForPairing(vaultSession.isUnlocked); // D-18
  validatePairingCode(code); // D-11: typo detected before any connect
  return invoke<PairingInitResponse>('pairing_connect', { configDir, code });
}

/**
 * Record that the local user has approved the SAS for this session.
 *
 * D-18: assertVaultUnlockedForPairing called before invoke.
 * This does NOT write peers.json — that is pairing_finalize's job (D-06).
 */
export async function pairingConfirm(sessionId: string): Promise<void> {
  assertVaultUnlockedForPairing(vaultSession.isUnlocked); // D-18
  return invoke<void>('pairing_confirm', { sessionId });
}

/**
 * The all-or-nothing commit point for a pairing session.
 *
 * Writes peers.json + CredManager ONLY after both sides confirm (D-06).
 * Enforces 60 s timeout (D-02) and re-pair guard (D-16).
 *
 * No D-18 guard here: if the session was created (unlock was confirmed then),
 * pairing_finalize is completing an already-initiated flow. The Rust side owns
 * session state integrity.
 */
export async function pairingFinalize(
  configDir: string,
  sessionId: string,
): Promise<void> {
  return invoke<void>('pairing_finalize', { configDir, sessionId });
}

// ---------------------------------------------------------------------------
// Device info + peers
// ---------------------------------------------------------------------------

/**
 * Return this device's identity info (public key + IDs).
 *
 * NEVER returns the private key. The private key stays in Rust/CredManager.
 */
export async function getLocalDeviceInfo(configDir: string): Promise<LocalDeviceInfo> {
  return invoke<LocalDeviceInfo>('get_local_device_info', { configDir });
}

/**
 * Return the current peers list from peers.json.
 *
 * Returns an empty array if peers.json does not yet exist.
 */
export async function peersJsonRead(configDir: string): Promise<PeerRecord[]> {
  return invoke<PeerRecord[]>('peers_json_read', { configDir });
}

/**
 * Remove a peer from peers.json AND its CredManager entry.
 *
 * Does NOT touch the own device identity key (D-17).
 */
export async function unpairDevice(configDir: string, deviceId: string): Promise<void> {
  return invoke<void>('unpair_device', { configDir, deviceId });
}

// ---------------------------------------------------------------------------
// QR + LAN IP utilities
// ---------------------------------------------------------------------------

/**
 * Generate a QR code SVG from a payload string.
 *
 * Returns a complete SVG XML string (pass to Svelte with {@html}).
 */
export async function generateQrSvg(payload: string): Promise<string> {
  return invoke<string>('generate_qr_svg', { payload });
}

/**
 * Return the best private IPv4 address for this device (UDP-connect trick).
 *
 * Returns an error string if no private IPv4 is found; caller shows manual-IP UI.
 */
export async function getLanIp(): Promise<string> {
  return invoke<string>('get_lan_ip');
}

// ---------------------------------------------------------------------------
// Credential Manager pass-through commands (low-level — for advanced use only)
// ---------------------------------------------------------------------------

/**
 * Write key bytes under a Credential Manager target.
 *
 * NEVER write the device identity private key from JS — it is generated in Rust.
 * This wrapper exists for completeness of the registered command surface.
 */
export async function deviceKeyWrite(target: string, keyBytes: number[]): Promise<void> {
  return invoke<void>('device_key_write', { target, keyBytes });
}

/**
 * Read key bytes from a Credential Manager target.
 *
 * Returns raw bytes as a number array (Tauri Vec<u8> serialization).
 */
export async function deviceKeyRead(target: string): Promise<number[]> {
  return invoke<number[]>('device_key_read', { target });
}

/**
 * Delete a Credential Manager entry by target name.
 *
 * Will refuse to delete the own device identity key (D-17 enforced in Rust).
 */
export async function deviceKeyDelete(target: string): Promise<void> {
  return invoke<void>('device_key_delete', { target });
}
