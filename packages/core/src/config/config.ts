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

  return {
    vaultPath,
    schemaVersion,
    listenerEnabled: (listenerEnabled as boolean | undefined) ?? true,
    extensionBridgeEnabled: (extensionBridgeEnabled as boolean | undefined) ?? true,
  };
}

/** Serialize a CryptiqConfig to UTF-8 JSON bytes. */
export function serializeConfig(cfg: CryptiqConfig): Uint8Array {
  const text = JSON.stringify(cfg, null, 2) + '\n';
  return new TextEncoder().encode(text);
}

export { DEFAULT_CONFIG };
