// apps/desktop/src/lib/config/config-adapter.ts
// Thin Tauri-side wrapper. core/config does the parsing; this just bridges the fs plugin.

import { readFile, writeFile, exists, mkdir, BaseDirectory } from '@tauri-apps/plugin-fs';
import { parseConfig, serializeConfig, DEFAULT_CONFIG } from '@cryptiq/core';
import type { CryptiqConfig } from '@cryptiq/core';

const CONFIG_DIR = 'cryptiq';
const CONFIG_FILE = 'cryptiq/config.json';

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
