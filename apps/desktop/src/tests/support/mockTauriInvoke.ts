// apps/desktop/src/tests/support/mockTauriInvoke.ts
//
// In-memory mock for Tauri's `invoke` IPC function, used in Playwright component
// tests (TEST-09). This module is aliased over `@tauri-apps/api/core` by the
// playwright.config.ts ctViteConfig so no real Tauri backend is needed.
//
// Handled commands:
//   vault_lock_*                           — advisory lock lifecycle (vault.svelte.ts)
//   plugin:fs|exists                       — file/dir presence check
//   plugin:fs|read_file                    — file read (config-adapter + TauriVaultStorageAdapter)
//   plugin:fs|write_file                   — file write (config-adapter — no-op)
//   plugin:fs|mkdir                        — dir creation (config-adapter — no-op)
//   plugin:fs|stat                         — file stat (no-op → throws VaultNotFoundError path)
//   plugin:dialog|save                     — vault-path picker (FirstRunWizard — no-op)
//   plugin:clipboard-manager|write_text    — per-field copy (copyField.ts — no-op)
//   plugin:opener|open_url                 — URL launch (openUrl.ts — no-op)
//
// Any unrecognized command rejects with a clear error message so component tests
// fail loudly if an unexpected invoke is triggered.
//
// CONFIGURABLE STATE — controlled by test helpers exported below:
//   setMockVaultPath(path | null)    controls what loadConfig() returns
//   setMockVaultBytes(bytes | null)  raw vault bytes for TauriVaultStorageAdapter.load()
//   resetMockState()                 restore defaults between tests

type InvokeArgs = Record<string, unknown>;

// ---------------------------------------------------------------------------
// Configurable mock state
// ---------------------------------------------------------------------------

/**
 * The vault path returned by config reads.
 * null → no config on disk → loadConfig() returns DEFAULT_CONFIG (vaultPath: null).
 */
let _mockVaultPath: string | null = '/fake/vault.cryptiq';

/**
 * Raw vault bytes returned when TauriVaultStorageAdapter calls readFile().
 * null → no vault bytes on disk → load() triggers VaultNotFoundError.
 */
let _mockVaultBytes: Uint8Array | null = null;

/**
 * Set the vault path the mocked config layer will return.
 * Pass null to simulate "no vault configured" (first-run scenario).
 */
export function setMockVaultPath(path: string | null): void {
  _mockVaultPath = path;
}

/**
 * Seed raw vault bytes for TauriVaultStorageAdapter.load() to return.
 * Call this with bytes from FakeVaultStorageAdapter.lastSavedBytes after
 * using mountVaultSession() + vaultSession.lock() to set up an unlock test.
 */
export function setMockVaultBytes(bytes: Uint8Array | null): void {
  _mockVaultBytes = bytes;
}

/** Read the currently configured mock vault path (for assertions). */
export function getMockVaultPath(): string | null {
  return _mockVaultPath;
}

/** Reset all configurable mock state to harness defaults. */
export function resetMockState(): void {
  _mockVaultPath = '/fake/vault.cryptiq';
  _mockVaultBytes = null;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function configBytes(vaultPath: string): number[] {
  const json = JSON.stringify({ schemaVersion: 1, vaultPath });
  return Array.from(new TextEncoder().encode(json));
}

// ---------------------------------------------------------------------------
// The mock invoke — aliased over @tauri-apps/api/core
// ---------------------------------------------------------------------------

export async function invoke(command: string, args?: InvokeArgs): Promise<unknown> {
  // ── Advisory lock lifecycle ────────────────────────────────────────────────
  if (
    command === 'vault_lock_acquire' ||
    command === 'vault_lock_release' ||
    command === 'vault_lock_check'
  ) {
    return undefined;
  }

  // ── plugin:fs|exists ──────────────────────────────────────────────────────
  // config-adapter uses this to check CONFIG_FILE; also TauriVaultStorageAdapter.exists()
  if (command === 'plugin:fs|exists') {
    const path = (args as Record<string, string> | undefined)?.path ?? '';
    // Vault file existence: match when vault path is configured AND bytes are seeded
    if (_mockVaultPath !== null && path === _mockVaultPath && _mockVaultBytes !== null) {
      return true;
    }
    // Config file existence: return true when a vault path is configured
    if (_mockVaultPath !== null) {
      return true;
    }
    return false;
  }

  // ── plugin:fs|read_file ───────────────────────────────────────────────────
  // Two callers:
  //   1. config-adapter's loadConfig() — returns serialised CryptiqConfig JSON
  //   2. TauriVaultStorageAdapter.load() — returns raw vault bytes
  if (command === 'plugin:fs|read_file') {
    const path = (args as Record<string, string> | undefined)?.path ?? '';

    // Vault bytes request: path matches _mockVaultPath exactly
    if (_mockVaultPath !== null && path === _mockVaultPath && _mockVaultBytes !== null) {
      return Array.from(_mockVaultBytes);
    }

    // Config file request: return config JSON bytes when vault path is configured
    if (_mockVaultPath !== null) {
      return configBytes(_mockVaultPath);
    }

    // No config → return empty bytes (parseConfig → DEFAULT_CONFIG)
    return [];
  }

  // ── plugin:fs|write_file ──────────────────────────────────────────────────
  // config-adapter's saveConfig() — no-op in tests
  if (command === 'plugin:fs|write_file') {
    return undefined;
  }

  // ── plugin:fs|mkdir ───────────────────────────────────────────────────────
  // config-adapter's mkdir — no-op in tests
  if (command === 'plugin:fs|mkdir') {
    return undefined;
  }

  // ── plugin:fs|stat ────────────────────────────────────────────────────────
  // TauriVaultStorageAdapter.exists() via the exists() helper in plugin-fs
  // also stat. Return a minimal stat object.
  if (command === 'plugin:fs|stat') {
    return { isFile: true, isDir: false, isSymlink: false, size: 0, mtime: null, atime: null, ctime: null };
  }

  // ── plugin:dialog|save ───────────────────────────────────────────────────
  // FirstRunWizard's vault-location picker — no-op (cancel)
  if (command === 'plugin:dialog|save') {
    return null;
  }

  // ── plugin:clipboard-manager|write_text ──────────────────────────────────
  // copyField.ts — no-op (tests don't assert clipboard content)
  if (command === 'plugin:clipboard-manager|write_text') {
    return undefined;
  }

  // ── plugin:opener|open_url ───────────────────────────────────────────────
  // openUrl.ts — no-op (tests don't test external URL launching)
  if (command === 'plugin:opener|open_url') {
    return undefined;
  }

  // ── Fail loudly for anything unrecognised ────────────────────────────────
  throw new Error(
    `[test] Unexpected invoke("${command}") in component test context. ` +
      `Add it to mockTauriInvoke.ts if this command is needed for a new test.`,
  );
}

// Resource is exported as a dummy to satisfy any destructure imports
// from @tauri-apps/api/core that expect it (e.g. plugin-fs barrel).
export class Resource {
  constructor(public readonly rid: number) {}
  async close(): Promise<void> {}
}

// Channel is a no-op placeholder for streaming commands.
export class Channel<T = unknown> {
  onmessage: ((msg: T) => void) | null = null;
}
