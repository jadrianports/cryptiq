export interface CryptiqConfig {
  /** Absolute path to the user's vault file. null until Phase 4 first-run. */
  vaultPath: string | null;
  /** Schema version for forward-compat migrations of config.json itself. */
  schemaVersion: 1;
  /**
   * Whether this device's inbound sync listener is enabled (D-01/D-03).
   * Device-local — stored in config.json, NEVER in InnerDoc.settings (which syncs).
   * Default: true (existing behavior preserved on upgrade). Outbound Sync Now unaffected.
   */
  listenerEnabled?: boolean;
  /**
   * Whether this device accepts browser-extension bridge connections (UX-05).
   * Device-local — config.json only, NEVER InnerDoc.settings. Default: true
   * (existing installs keep working on upgrade). Mirrors listenerEnabled (D-04).
   */
  extensionBridgeEnabled?: boolean;
}

export const DEFAULT_CONFIG: CryptiqConfig = {
  vaultPath: null,
  schemaVersion: 1,
  listenerEnabled: true,
  extensionBridgeEnabled: true,
};
