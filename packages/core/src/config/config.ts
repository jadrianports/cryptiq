import type { CryptiqConfig } from './types';
import { DEFAULT_CONFIG } from './types';

export class ConfigCorruptError extends Error {
  readonly code = 'CONFIG_CORRUPT';
}

/**
 * Parse bytes (UTF-8 JSON) into a CryptiqConfig.
 * Throws ConfigCorruptError on invalid JSON, non-object root, wrong field
 * types, or unsupported schemaVersion. Pure function — no fs, no Tauri,
 * testable.
 */
export function parseConfig(bytes: Uint8Array): CryptiqConfig {
  const text = new TextDecoder('utf-8').decode(bytes);
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (e) {
    throw new ConfigCorruptError(`config.json is not valid JSON: ${(e as Error).message}`);
  }
  if (raw === null || typeof raw !== 'object') {
    throw new ConfigCorruptError('config.json must be a JSON object.');
  }
  const obj = raw as Record<string, unknown>;

  const vaultPath = obj.vaultPath;
  if (vaultPath !== null && typeof vaultPath !== 'string') {
    throw new ConfigCorruptError('config.json: vaultPath must be string | null.');
  }

  const schemaVersion = obj.schemaVersion;
  if (schemaVersion !== 1) {
    // Future schema versions handled by migration logic; v1 refuses unknown.
    throw new ConfigCorruptError(`config.json: unsupported schemaVersion ${String(schemaVersion)}.`);
  }

  // listenerEnabled: optional boolean, default true (D-03 / Phase 13).
  // Old builds write config.json without this field; new builds read it as true if absent.
  const listenerEnabled = obj.listenerEnabled;
  if (listenerEnabled !== undefined && typeof listenerEnabled !== 'boolean') {
    throw new ConfigCorruptError('config.json: listenerEnabled must be boolean or absent.');
  }

  // extensionBridgeEnabled: optional boolean, default true (UX-05 / D-04 / Phase 20).
  // Device-local kill-switch for browser-extension bridge connections. Mirrors
  // listenerEnabled — old builds omit it; new builds read it as true if absent. This MUST
  // round-trip through parseConfig (not just serializeConfig) so the OFF state the Rust
  // boot-gate honors is also reflected by the Settings toggle after a reload (D-04).
  const extensionBridgeEnabled = obj.extensionBridgeEnabled;
  if (extensionBridgeEnabled !== undefined && typeof extensionBridgeEnabled !== 'boolean') {
    throw new ConfigCorruptError('config.json: extensionBridgeEnabled must be boolean or absent.');
  }

  // hibpEntryScanEnabled: optional boolean, default FALSE (HIBP-01 / D-02 / Phase 31).
  // Device-local consent to scan stored entry passwords via the HaveIBeenPwned
  // k-anonymity range API. UNLIKE listenerEnabled/extensionBridgeEnabled, absence MUST
  // resolve to false — a `?? true` here would silently authorize this app's first-ever
  // network egress for every pre-Phase-31 install. This is the load-bearing deviation.
  const hibpEntryScanEnabled = obj.hibpEntryScanEnabled;
  if (hibpEntryScanEnabled !== undefined && typeof hibpEntryScanEnabled !== 'boolean') {
    throw new ConfigCorruptError('config.json: hibpEntryScanEnabled must be boolean or absent.');
  }

  // hibpMasterCheckEnabled: optional boolean, default FALSE (HIBP-06 / D-16 / Phase 31).
  // Device-local consent to check the master password via the same HIBP range API at
  // set/change time. Same default-OFF rule as hibpEntryScanEnabled — `?? false`, never
  // `?? true`.
  const hibpMasterCheckEnabled = obj.hibpMasterCheckEnabled;
  if (hibpMasterCheckEnabled !== undefined && typeof hibpMasterCheckEnabled !== 'boolean') {
    throw new ConfigCorruptError('config.json: hibpMasterCheckEnabled must be boolean or absent.');
  }

  return {
    vaultPath,
    schemaVersion,
    listenerEnabled: (listenerEnabled as boolean | undefined) ?? true,
    extensionBridgeEnabled: (extensionBridgeEnabled as boolean | undefined) ?? true,
    hibpEntryScanEnabled: (hibpEntryScanEnabled as boolean | undefined) ?? false,
    hibpMasterCheckEnabled: (hibpMasterCheckEnabled as boolean | undefined) ?? false,
  };
}

/** Serialize a CryptiqConfig to UTF-8 JSON bytes. */
export function serializeConfig(cfg: CryptiqConfig): Uint8Array {
  const text = JSON.stringify(cfg, null, 2) + '\n';
  return new TextEncoder().encode(text);
}

export { DEFAULT_CONFIG };
