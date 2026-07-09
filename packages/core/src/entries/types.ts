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
 * Payment-card sub-shape (Phase 21, D-07). All fields are `string` — `number` and
 * `cvv` are NEVER a JS number (leading zeros, spacing, 16+ digit precision).
 * Expiry is stored as separate `expiryMonth`/`expiryYear` strings (e.g. `'03'`/`'2027'`)
 * rather than a combined `'MM/YY'` string, so it maps 1:1 onto the WHATWG
 * `cc-exp-month`/`cc-exp-year` `<select>` fill target with no parse-at-fill-time.
 */
export interface EntryCard {
  cardholderName: string;
  number: string;
  expiryMonth: string;
  expiryYear: string;
  cvv: string;
  brand?: string;
  nickname?: string;
}

/**
 * Identity sub-shape (Phase 21, D-08). `address` is a single free-text (multi-line)
 * field, not structured sub-parts. `email` here is distinct from a login entry's
 * top-level `Entry.email`.
 */
export interface EntryIdentity {
  name: string;
  email: string;
  phone: string;
  address: string;
}

/**
 * TOTP (time-based one-time password) sub-shape (Phase 28, TOTP-07). A flat all-scalar
 * sub-shape mirroring EntryCard/EntryIdentity.
 *
 * `secret` is stored VERBATIM as a raw RFC 4648 Base32 string (the standard TOTP
 * alphabet, which INCLUDES I/L/O/U) — NEVER Cryptiq's Crockford recovery alphabet
 * (`crypto/recovery.ts`, which deliberately EXCLUDES I/L/O/U). This phase treats
 * `secret` as OPAQUE: no Base32 decode, no HMAC, no code generation, no alphabet
 * validation. Phase 29 generates codes from it via `otpauth`'s own `Secret.fromBase32`.
 *
 * `algorithm` is the HMAC hash name (e.g. `'SHA1'`/`'SHA256'`/`'SHA512'`) stored as a
 * free string this phase; `digits` (e.g. 6 or 8) and `period` (seconds, e.g. 30 or 60)
 * are numbers. `label`/`issuer` are optional display metadata from the otpauth URI.
 *
 * Loss-sensitivity: `totp` is deliberately EXCLUDED from the merge engine's
 * `meaningfulContentDiffers`/`snapshotOf` (documented at those call sites in
 * `sync/merge.ts`) — see TOTP-07/SC-4.
 */
export interface EntryTotp {
  /** RFC 4648 Base32 secret, stored verbatim + opaque this phase (never Crockford). */
  secret: string;
  /** HMAC hash name (e.g. `'SHA1'`/`'SHA256'`/`'SHA512'`). */
  algorithm: string;
  /** Number of digits in the generated code (e.g. 6 or 8). */
  digits: number;
  /** Time-step period in seconds (e.g. 30 or 60). */
  period: number;
  /** Optional account label from the otpauth URI. */
  label?: string;
  /** Optional issuer name from the otpauth URI. */
  issuer?: string;
}

/**
 * A single vault entry.
 *
 * Field invariants (ENTRY-01):
 *   - `id`   — UUIDv4 derived from `sodium.randombytes_buf(16)` (P3-03; never Math.random)
 *   - `type` — `'login'` in v1; widened in Phase 21 (D-04) to `'login' | 'card' |
 *     'identity' | 'secure-note'`. Immutable after creation — `EntryUpdate` omits it.
 *   - `deletedAt` — `null` when active; ISO 8601 when soft-deleted (ENTRY-04 tombstone)
 *   - `passwordHistory` — newest-first; cap 10 (ENTRY-07); pushed on any password change
 *   - `generatorPreset` — mirrors GeneratorOptions union exactly (P3-07); `null` = no preset
 *   - `tags` — first-class string array (ENTRY-02)
 *   - `lostVersions` — Phase 8 (D-01/D-02/D-10): full-entry snapshots of losing sync versions;
 *     optional — absent on pre-Phase-8 entries; `asInnerDoc()` fills with `[]`; cap 5 newest.
 *   - `email` — Phase 21 (D-05): optional, independent of `username` (never derived from
 *     it); absent on pre-Phase-21 entries and never backfilled by the 2→3 migration.
 *   - `equivalentUrls` — Phase 21 (D-06): optional raw user-entered alternate URLs (same
 *     shape as `url`), reduced to eTLD+1 only at match time (`matchByOrigin`); no cap.
 *   - `card` / `identity` — Phase 21 (D-07/D-08): optional sub-shapes for the widened
 *     `type` union; absent on pre-Phase-21 entries and on every `'login'` entry.
 */
export interface Entry {
  // -- Identity (immutable after creation) --
  /** UUIDv4 (CSPRNG-backed; P3-03). */
  id: string;
  /** Entry type discriminator. Widened in Phase 21 (D-04) beyond `'login'`. */
  type: 'login' | 'card' | 'identity' | 'secure-note';

  // -- Content --
  /** Display name. Required. */
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  /** First-class tag list (ENTRY-02). Empty array when no tags. */
  tags: string[];
  /**
   * Independent optional email identifier (Phase 21, D-05). Orthogonal to `username` —
   * never derived/split from it (IDENT-03). Optional — absent until the user sets it;
   * the 2→3 migration never backfills this field.
   */
  email?: string;
  /**
   * Alternate URLs for origin matching (Phase 21, D-06). Raw user-entered strings, same
   * shape as `url`; reduced to eTLD+1 only at match time via `registrableHost()`. No cap.
   * Optional — absent until the user sets it; the 2→3 migration never backfills this field.
   */
  equivalentUrls?: string[];
  /**
   * Payment-card details (Phase 21, D-07). Present only on `type: 'card'` entries in
   * practice; optional at the type level since the 2→3 migration never backfills it.
   */
  card?: EntryCard;
  /**
   * Identity details (Phase 21, D-08). Present only on `type: 'identity'` entries in
   * practice; optional at the type level since the 2→3 migration never backfills it.
   */
  identity?: EntryIdentity;
  /**
   * TOTP 2FA seed + parameters (Phase 28, TOTP-07). Optional — absent on pre-Phase-28
   * entries; the 3→4 migration never backfills it (the key stays OMITTED until the user
   * adds a TOTP, per `exactOptionalPropertyTypes`). `secret` is a verbatim opaque RFC
   * 4648 Base32 string this phase. Loss-sensitivity is documented at the merge.ts call
   * sites (excluded from `meaningfulContentDiffers`/`snapshotOf` — SC-4).
   */
  totp?: EntryTotp;

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
 *
 * Phase 21 (D-01/D-03): `schemaVersion` widens 2→3 via a PURE version bump in
 * `asInnerDoc()` — no field backfill. This is the same additive `asInnerDoc()` idiom as
 * the 1→2 bump, NOT the outer `loadAndMigrate` back-up→migrate→cold-decrypt-verify→swap
 * pipeline (which guards the AEAD-bound LOCKED wire format and stays untouched).
 */
export interface InnerDoc {
  /**
   * Inner schema version. 1 in v1; 2 after the Phase 8 additive bump (D-02/D-10);
   * 3 after the Phase 21 additive bump (D-01/D-03); 4 after the Phase 28 additive bump
   * (TOTP-07, `Entry.totp`) — each a pure version-number flip, no new field is
   * backfilled onto existing entries.
   */
  schemaVersion: 1 | 2 | 3 | 4;
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
 * Phase 23 (D-03): `type` is now accepted at create time — `addEntry` honors
 * `input.type` and defaults to `'login'` when absent. `type` is immutable
 * thereafter — only `EntryInput` accepts it; `EntryUpdate` continues to omit it.
 *
 * Omits auto-managed fields: `id`, `createdAt`, `modifiedAt`,
 * `deletedAt`, and `passwordHistory`.
 */
export type EntryInput = Pick<Entry, 'title'> &
  Partial<Omit<Entry, 'id' | 'createdAt' | 'modifiedAt' | 'deletedAt' | 'passwordHistory'>>;

/**
 * Update type for `updateEntry`. Any subset of mutable entry fields.
 *
 * Omits immutable fields: `id`, `type`, `createdAt`.
 *
 * `totp` is widened beyond a plain `Partial` to also accept `null` as an explicit
 * REMOVE sentinel (Phase 29 Plan 05, D-11 "remove the seed"). A bare `Partial<Entry>`
 * cannot express deletion under `exactOptionalPropertyTypes` (assigning `undefined`
 * to an already-optional key is a type error, and is indistinguishable at runtime
 * from simply omitting the key). `updateEntry` treats `totp: null` as "delete the
 * key" and `totp: EntryTotp` as "wholesale-replace it" — omitting `totp` entirely
 * leaves it untouched, matching every other field's semantics.
 */
export type EntryUpdate = Partial<Omit<Entry, 'id' | 'type' | 'createdAt' | 'totp'>> & {
  totp?: EntryTotp | null;
};
