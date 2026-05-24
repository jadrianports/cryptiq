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

  return { vaultPath, schemaVersion };
}

/** Serialize a CryptiqConfig to UTF-8 JSON bytes. */
export function serializeConfig(cfg: CryptiqConfig): Uint8Array {
  const text = JSON.stringify(cfg, null, 2) + '\n';
  return new TextEncoder().encode(text);
}

export { DEFAULT_CONFIG };
