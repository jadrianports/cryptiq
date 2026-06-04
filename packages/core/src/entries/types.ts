// packages/core/src/entries/types.ts
//
// The ENTRY-01 full field set + the P3-01 versioned inner document shape.
// GeneratorOptions is imported from the generator module — a single type for both
// live generator input and per-entry preset storage (P3-07).
// EntrySnapshot is imported from sync/types for the Phase 8 additive lostVersions
// field on Entry (D-01/D-02). The import is type-only — no runtime circular dep.
//
// Source: CONTEXT.md P3-01/P3-02/P3-07 + 03-RESEARCH §Entry Model

import type { GeneratorOptions } from '../generator/types';
import type { EntrySnapshot } from '../sync/types';

/** One entry in `passwordHistory` (newest-first, capped at 10 — ENTRY-07). */
export interface PasswordHistoryItem {
  /** The password value that was replaced. */
  password: string;
  /** ISO 8601 timestamp of the change. */
  changedAt: string;
}

/**
 * A single vault entry.
 *
 * Field invariants (ENTRY-01):
 *   - `id`   — UUIDv4 derived from `sodium.randombytes_buf(16)` (P3-03; never Math.random)
 *   - `type` — `'login'` in v1; field exists for v2 expansion (card, identity, secure-note)
 *   - `deletedAt` — `null` when active; ISO 8601 when soft-deleted (ENTRY-04 tombstone)
 *   - `passwordHistory` — newest-first; cap 10 (ENTRY-07); pushed on any password change
 *   - `generatorPreset` — mirrors GeneratorOptions union exactly (P3-07); `null` = no preset
 *   - `tags` — first-class string array (ENTRY-02)
 *   - `lostVersions` — Phase 8 (D-01/D-02/D-10): full-entry snapshots of losing sync versions;
 *     optional — absent on pre-Phase-8 entries; `asInnerDoc()` fills with `[]`; cap 5 newest.
 */
export interface Entry {
  // -- Identity (immutable after creation) --
  /** UUIDv4 (CSPRNG-backed; P3-03). */
  id: string;
  /** Entry type discriminator. `'login'` in v1. */
  type: 'login';

  // -- Content --
  /** Display name. Required. */
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  /** First-class tag list (ENTRY-02). Empty array when no tags. */
  tags: string[];

  // -- Metadata --
  /** Pinned / starred by the user. */
  favorite: boolean;
  /**
   * User-set flag: this entry's site changed its password requirements and needs
   * a new password generated. Phase 4 surfaces a "Needs update" filter list.
   */
  needsSiteUpdate: boolean;
  /**
   * Saved generator configuration for this entry (P3-07).
   * Same discriminated union the generator itself consumes.
   * `null` = user never set a preset for this entry.
   */
  generatorPreset: GeneratorOptions | null;
  /**
   * Password history (ENTRY-07). Newest first. Capped at 10.
   * Pushed automatically by `updateEntry` + `regenerateFromPreset` whenever
   * the `password` field changes.
   */
  passwordHistory: PasswordHistoryItem[];
  /**
   * Full-entry snapshots of losing versions overwritten during sync (D-01/D-02).
   * Capped at 5 newest (T-03-04 plaintext-surface discipline). Filled by `asInnerDoc()`
   * on any unlock/save after the Phase 8 app update (D-10).
   * Optional — absent on pre-Phase-8 entries; `asInnerDoc()` fills with `[]`.
   */
  lostVersions?: EntrySnapshot[];

  // -- Timestamps --
  /** ISO 8601 creation time. Set once on `addEntry`; never updated. */
  createdAt: string;
  /** ISO 8601 last-modified time. Updated on any field change (including soft-delete). */
  modifiedAt: string;
  /**
   * ISO 8601 soft-delete timestamp, or `null` when active (ENTRY-04 tombstone).
   * `softDeleteEntry` sets this; `purgeEntry` removes the record entirely.
   */
  deletedAt: string | null;
}

/**
 * P3-01 versioned inner document.
 *
 * This is the JSON blob that `encryptInner`/`decryptInner` seal/open. The
 * `schemaVersion` is SEPARATE from the outer file-format `version` (= 1) that
 * is bound into AEAD associated data. Inner schema migrations can be done
 * lightly (no heavy back-up→migrate→verify-by-cold-decrypt pipeline) when only
 * entry-field additions/renames are needed.
 *
 * `settings.generator` stores the vault-level generator defaults (GEN-04).
 * `settings.lock` stores the auto-lock preferences (P5-12). Optional — absent on
 * pre-Phase-5 vaults; `asInnerDoc()` fills defaults idempotently.
 * `settings.clipboard` stores the clipboard auto-clear preference (P5-12). Optional.
 */
export interface InnerDoc {
  /** Inner schema version. 1 in v1; 2 after the Phase 8 additive bump (D-02/D-10). */
  schemaVersion: 1 | 2;
  /** All entries (active + tombstones). */
  entries: Entry[];
  /** Vault-level settings. */
  settings: {
    /** Default generator options for this vault (GEN-04). */
    generator: GeneratorOptions;
    /**
     * Auto-lock preferences (P5-12, P5-03/P5-05).
     * Optional — absent on pre-Phase-5 vaults; `asInnerDoc()` fills:
     *   `{ idleMinutes: 5, lockOnMinimize: false }`.
     */
    lock?: {
      /** Idle minutes before auto-lock. `'never'` disables idle timeout. */
      idleMinutes: number | 'never';
      /** Lock when the Cryptiq window loses focus / is minimized. Default: false. */
      lockOnMinimize: boolean;
    };
    /**
     * Clipboard auto-clear preferences (P5-12, P5-08).
     * Optional — absent on pre-Phase-5 vaults; `asInnerDoc()` fills:
     *   `{ clearSeconds: 25 }`.
     */
    clipboard?: {
      /** Seconds after which a copied password is automatically cleared. Default: 25. */
      clearSeconds: number;
    };
    /**
     * Health-audit preferences (Phase 6, AUDIT-04).
     * Optional — absent on pre-Phase-6 vaults; `asInnerDoc()` fills:
     *   `{ staleThresholdDays: 365 }`.
     */
    audit?: {
      /**
       * Days before a password is considered stale. Default: 365.
       * Configurable in Settings (AUDIT-04). Stored in encrypted InnerDoc.settings.
       */
      staleThresholdDays: number;
    };
  };
}

/**
 * Input type for `addEntry`. Only `title` is required; all other fields have
 * sensible defaults and are optional.
 *
 * Omits auto-managed fields: `id`, `type`, `createdAt`, `modifiedAt`,
 * `deletedAt`, and `passwordHistory`.
 */
export type EntryInput = Pick<Entry, 'title'> &
  Partial<Omit<Entry, 'id' | 'type' | 'createdAt' | 'modifiedAt' | 'deletedAt' | 'passwordHistory'>>;

/**
 * Update type for `updateEntry`. Any subset of mutable entry fields.
 *
 * Omits immutable fields: `id`, `type`, `createdAt`.
 */
export type EntryUpdate = Partial<Omit<Entry, 'id' | 'type' | 'createdAt'>>;
