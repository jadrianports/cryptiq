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
//   plugin:fs|write_file                   — file write (config-adapter — captured, see below)
//   plugin:fs|mkdir                        — dir creation (config-adapter — no-op)
//   plugin:fs|stat                         — file stat (no-op → throws VaultNotFoundError path)
//   plugin:dialog|save                     — vault-path picker (FirstRunWizard — no-op)
//   plugin:clipboard-manager|write_text    — per-field copy (copyField.ts — no-op)
//   plugin:opener|open_url                 — URL launch (openUrl.ts — no-op)
//   hibp_range_lookup                      — HIBP k-anonymity range lookup (Phase 31)
//
// Any unrecognized command rejects with a clear error message so component tests
// fail loudly if an unexpected invoke is triggered.
//
// CONFIGURABLE STATE — controlled by test helpers exported below:
//   setMockVaultPath(path | null)    controls what loadConfig() returns
//   setMockVaultBytes(bytes | null)  raw vault bytes for TauriVaultStorageAdapter.load()
//   setMockConfigFlags(flags)        seeds hibpEntryScanEnabled/hibpMasterCheckEnabled on
//                                    the config.json a spec's loadConfig() will read back
//   setMockHibpResponse(mode, pw?)   controls hibp_range_lookup's response (match/no-match/fail)
//   getLastSavedConfig()             the last CryptiqConfig object written via saveConfig()
//   resetMockState()                 restore defaults between tests
//
// NOTE (Phase 31, Plan 31-02): this file is the Wave-1 shared owner of the three HIBP
// test-infra additions below (hibp_range_lookup mock, config consent-flag seeding,
// saveConfig write-capture). Downstream Plans 03/04/05 CONSUME these helpers and must
// NOT edit this file themselves — keeps same-wave plans conflict-free.

import { sha1Hex } from '@cryptiq/core';

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
 * In-memory browser-extension association list, seeded by tests via
 * setMockExtensionAssociations(). Backs extension_peers_list / rename_extension_association /
 * revoke_extension_association_cmd so ExtensionSettingsSection.spec.ts can exercise the
 * real store + component without a live Tauri backend.
 */
interface MockExtensionAssociation {
  clientId: string;
  clientPublicKey: string;
  label: string;
  pairedAt: string;
  lastUsedAt: string | null;
  pairingTokenHash: string;
}
let _mockExtensionAssociations: MockExtensionAssociation[] = [];

/** Seed the association list extension_peers_list will return. */
export function setMockExtensionAssociations(associations: MockExtensionAssociation[]): void {
  _mockExtensionAssociations = associations;
}

/**
 * Consent-flag overlay merged into the config.json a spec's loadConfig() will read
 * back via plugin:fs|read_file (Phase 31). Absent (both undefined, the default) means
 * a spec exercises the real parseConfig() `?? false` default-OFF path — mirrors a
 * pre-Phase-31 config.json missing both fields.
 */
let _mockConfigFlags: { hibpEntryScanEnabled?: boolean; hibpMasterCheckEnabled?: boolean } = {};

/** Seed hibpEntryScanEnabled/hibpMasterCheckEnabled on the mocked config.json. */
export function setMockConfigFlags(flags: {
  hibpEntryScanEnabled?: boolean;
  hibpMasterCheckEnabled?: boolean;
}): void {
  _mockConfigFlags = { ...flags };
}

/**
 * The last CryptiqConfig object written via saveConfig() (plugin:fs|write_file to the
 * config path), captured so specs can assert a persisted flag (e.g.
 * `hibpEntryScanEnabled: true`) occurred only after a confirm — never on toggle alone.
 */
let _lastSavedConfig: unknown = null;

/** Read the last config object persisted via saveConfig(), or null if none yet. */
export function getLastSavedConfig(): unknown {
  return _lastSavedConfig;
}

/**
 * hibp_range_lookup response mode (Phase 31):
 *   'no-match' (default) — empty range body, lookupHibpRange resolves false.
 *   'match'              — body includes the TRUE SHA-1 suffix of `_mockHibpMatchPassword`
 *                           (only for the matching prefix), so the real matchesSuffix logic
 *                           genuinely matches — lookupHibpRange resolves true.
 *   'fail'                — invoke rejects, lookupHibpRange throws HibpLookupError.
 */
type MockHibpResponseMode = 'no-match' | 'match' | 'fail';

let _mockHibpMode: MockHibpResponseMode = 'no-match';
let _mockHibpMatchPassword: string | null = null;

/**
 * Configure hibp_range_lookup's mocked response.
 * @param mode     'no-match' (default), 'match', or 'fail'.
 * @param password Required when mode === 'match' — the password whose TRUE SHA-1 suffix
 *                 the mock will return a match for (via the real sha1Hex/matchesSuffix
 *                 logic, never a fabricated suffix).
 */
export function setMockHibpResponse(mode: MockHibpResponseMode, password?: string): void {
  _mockHibpMode = mode;
  _mockHibpMatchPassword = password ?? null;
}

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
  _mockExtensionAssociations = [];
  _mockConfigFlags = {};
  _lastSavedConfig = null;
  _mockHibpMode = 'no-match';
  _mockHibpMatchPassword = null;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function configBytes(vaultPath: string): number[] {
  const json = JSON.stringify({ schemaVersion: 1, vaultPath, ..._mockConfigFlags });
  return Array.from(new TextEncoder().encode(json));
}

// ---------------------------------------------------------------------------
// The mock invoke — aliased over @tauri-apps/api/core
// ---------------------------------------------------------------------------

export async function invoke(
  command: string,
  args?: unknown,
  _options?: { headers?: Record<string, string> },
): Promise<unknown> {
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
  // config-adapter's saveConfig() is the only writeFile() caller in this codebase
  // (vault writes go through custom Rust commands, not plugin:fs). Unlike every
  // other command, @tauri-apps/plugin-fs's writeFile() sends the path via the raw
  // invoke() `options.headers.path` (URI-encoded), NOT the `args` object — `args`
  // here IS the raw byte payload. Captured into _lastSavedConfig (Phase 31) so
  // specs can assert a persisted consent flag occurred only after an explicit
  // confirm, never on toggle alone.
  if (command === 'plugin:fs|write_file') {
    try {
      const bytes = args instanceof Uint8Array ? args : Uint8Array.from(args as number[]);
      const text = new TextDecoder('utf-8').decode(bytes);
      _lastSavedConfig = JSON.parse(text);
    } catch {
      // Non-config binary write (none exist today) or malformed payload — ignore.
    }
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

  // ── hibp_range_lookup ─────────────────────────────────────────────────────
  // The ONLY egress path lookupHibpRange() calls (Phase 31). The real
  // sha1Hex/matchesSuffix k-anonymity logic in @cryptiq/core is NEVER mocked —
  // this handler returns a raw range-response body (or throws), exactly like the
  // real Rust hibp_range_lookup command would, and lets the real core logic parse it.
  if (command === 'hibp_range_lookup') {
    if (_mockHibpMode === 'fail') {
      throw new Error('[test] mock hibp_range_lookup failure (setMockHibpResponse fail mode)');
    }
    if (_mockHibpMode === 'match' && _mockHibpMatchPassword !== null) {
      const hex = sha1Hex(_mockHibpMatchPassword);
      const truePrefix = hex.slice(0, 5);
      const trueSuffix = hex.slice(5);
      const requestedPrefix = (args as Record<string, string> | undefined)?.prefix ?? '';
      if (requestedPrefix === truePrefix) {
        return `${trueSuffix}:1\r\n`;
      }
    }
    // 'no-match' (default) — empty range body, or a 'match' request for a
    // different prefix than the configured password's — never matches.
    return '';
  }

  // ── extension_peers_list ──────────────────────────────────────────────────
  // ExtensionPeerStore.init() — returns the seeded association list.
  if (command === 'extension_peers_list') {
    return _mockExtensionAssociations;
  }

  // ── rename_extension_association ─────────────────────────────────────────
  // ExtensionPeerStore.renameLabel() — updates the seeded label in place.
  if (command === 'rename_extension_association') {
    const { clientId, label } = (args ?? {}) as { clientId: string; label: string };
    _mockExtensionAssociations = _mockExtensionAssociations.map((a) =>
      a.clientId === clientId ? { ...a, label } : a,
    );
    return undefined;
  }

  // ── revoke_extension_association_cmd ─────────────────────────────────────
  // ExtensionPeerStore.revoke() — removes the seeded association.
  if (command === 'revoke_extension_association_cmd') {
    const { clientId } = (args ?? {}) as { clientId: string };
    _mockExtensionAssociations = _mockExtensionAssociations.filter((a) => a.clientId !== clientId);
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
