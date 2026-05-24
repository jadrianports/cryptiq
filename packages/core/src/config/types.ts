export interface CryptiqConfig {
  /** Absolute path to the user's vault file. null until Phase 4 first-run. */
  vaultPath: string | null;
  /** Schema version for forward-compat migrations of config.json itself. */
  schemaVersion: 1;
}

export const DEFAULT_CONFIG: CryptiqConfig = {
  vaultPath: null,
  schemaVersion: 1,
};
