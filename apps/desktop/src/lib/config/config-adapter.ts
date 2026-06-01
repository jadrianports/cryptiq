// apps/desktop/src/lib/config/config-adapter.ts
// Thin Tauri-side wrapper. core/config does the parsing; this just bridges the fs plugin.

import { readFile, writeFile, exists, mkdir, BaseDirectory } from '@tauri-apps/plugin-fs';
import { appConfigDir, join } from '@tauri-apps/api/path';
import { parseConfig, serializeConfig, DEFAULT_CONFIG } from '@cryptiq/core';
import type { CryptiqConfig } from '@cryptiq/core';

const CONFIG_DIR = 'cryptiq';
const CONFIG_FILE = 'cryptiq/config.json';
const VAULT_SUBDIR = 'cryptiq/vaults';

/**
 * Absolute path to the single app-managed vault file
 * ($APPCONFIG/cryptiq/vaults/vault.cryptiq). v1 stores the vault at this FIXED location —
 * it is the only path the capability fs scopes allow for read/write/exists, so reads
 * (unlock), writes, lock, and backups all work without per-path scope grants. The vault is
 * not user-relocatable in v1 (a freeform location picker is deferred to v1.5 with proper
 * dialog→persisted-scope plumbing). [UAT T4 decision — fixed app-managed location.]
 */
export async function defaultVaultPath(): Promise<string> {
  return join(await appConfigDir(), 'cryptiq', 'vaults', 'vault.cryptiq');
}

/**
 * Ensure $APPCONFIG/cryptiq/vaults exists before the first vault write — the Rust
 * vault_write_atomic command requires the target's parent directory to already exist.
 * mkdir(recursive) is idempotent; a benign "already exists" is ignored.
 */
export async function ensureVaultDir(): Promise<void> {
  try {
    await mkdir(VAULT_SUBDIR, { baseDir: BaseDirectory.AppConfig, recursive: true });
  } catch {
    // Directory already exists (or a benign race) — safe to ignore for an idempotent ensure.
  }
}

export async function loadConfig(): Promise<CryptiqConfig> {
  if (!(await exists(CONFIG_FILE, { baseDir: BaseDirectory.AppConfig }))) {
    return DEFAULT_CONFIG;
  }
  const bytes = await readFile(CONFIG_FILE, { baseDir: BaseDirectory.AppConfig });
  return parseConfig(bytes);
}

export async function saveConfig(cfg: CryptiqConfig): Promise<void> {
  // Ensure $APPCONFIG/cryptiq exists.
  if (!(await exists(CONFIG_DIR, { baseDir: BaseDirectory.AppConfig }))) {
    await mkdir(CONFIG_DIR, { baseDir: BaseDirectory.AppConfig, recursive: true });
  }
  const bytes = serializeConfig(cfg);
  await writeFile(CONFIG_FILE, bytes, { baseDir: BaseDirectory.AppConfig });
}
