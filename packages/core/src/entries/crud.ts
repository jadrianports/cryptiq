// packages/core/src/entries/crud.ts
//
// Entry CRUD verbs — Plan 03-01 ships SIGNATURE STUBS with locked contracts.
// Plan 02 fills the implementations. Do NOT change these signatures without
// updating the parallel plan.
//
// DC-8 / P3-02 PATTERN: verbs mutate `vault.entries` (the InnerDoc) IN PLACE
// and return the affected Entry (or void for delete/purge). The caller
// (VaultSession, $state.raw) reassigns its vault reference after mutation to
// trigger Svelte reactivity — no deep $state proxying (Pitfall 7).
//
// CSPRNG discipline: addEntry uses `sodium.randombytes_buf(16)` for the ID
// (P3-03). No Math.random anywhere (ESLint enforced).
//
// Source: CONTEXT.md P3-02/P3-03/P3-07 + 03-RESEARCH Pattern 1 + §Password Age

import type { UnlockedVault } from '../vault/vault';
import type { Entry, EntryInput, EntryUpdate, InnerDoc } from './types';
import { EntryNotFoundError, GeneratorError } from '../errors';
import { getSodium } from '../crypto/sodium';
import { uuidV4FromBytes } from './uuid';
import { generateRandom } from '../generator/random';
import { generatePassphrase } from '../generator/passphrase';
import { DEFAULT_RANDOM_OPTIONS } from '../generator/types';

// -- Type re-exports for callers that import from entries/crud --
export type { Entry, EntryInput, EntryUpdate, InnerDoc };

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Return the current time as an ISO 8601 string. */
function nowIso(): string {
  return new Date().toISOString();
}

/**
 * Pitfall-3 defensive inner-doc cast.
 *
 * Phase-2 vaults start with `{ entries: [] }` (no `schemaVersion`). Upgrade
 * them in place to the P3-01 versioned shape so every CRUD verb operates on a
 * well-formed `InnerDoc`. The upgrade is idempotent — calling it on an already-
 * versioned doc is a no-op.
 *
 * This is the ONLY place `vault.entries` is cast — single audit point.
 *
 * Phase 8 (D-02/D-10): this function is also the v1→v2 upgrade site. It bumps
 * `schemaVersion` 1→2 and fills `lostVersions: []` on any entry that lacks it.
 * Idempotent — never downgrades, never overwrites an existing lostVersions array.
 *
 * Phase 21 (D-01/D-03): this function is ALSO the v2→v3 upgrade site (inner schema
 * widening for `email`/`equivalentUrls`/`card`/`identity` — SCHEMA-01/02, IDENT-03).
 * Unlike the 1→2 bump, the 2→3 bump is a PURE version-number flip with NO per-entry
 * backfill loop — the new optional fields stay absent until the user sets them. This
 * is NOT the outer `loadAndMigrate` back-up→migrate→cold-decrypt-verify→swap pipeline,
 * which guards the AEAD-bound LOCKED wire format and is untouched by this bump.
 */
function asInnerDoc(vault: UnlockedVault): InnerDoc {
  const raw = vault.entries as Record<string, unknown>;

  // Upgrade Phase-2 dev vaults (missing schemaVersion) in place.
  if (raw['schemaVersion'] === undefined || raw['schemaVersion'] === 0) {
    raw['schemaVersion'] = 1;
  }
  if (!Array.isArray(raw['entries'])) {
    raw['entries'] = [];
  }
  if (raw['settings'] === undefined || typeof raw['settings'] !== 'object' || raw['settings'] === null) {
    raw['settings'] = { generator: DEFAULT_RANDOM_OPTIONS };
  }
  const settings = raw['settings'] as Record<string, unknown>;
  if (settings['generator'] === undefined) {
    settings['generator'] = DEFAULT_RANDOM_OPTIONS;
  }
  // P5-12: additive lock/clipboard defaults — idempotent; never overwrites a user value.
  if (settings['lock'] === undefined) {
    settings['lock'] = { idleMinutes: 5, lockOnMinimize: false };
  }
  if (settings['clipboard'] === undefined) {
    settings['clipboard'] = { clearSeconds: 25 };
  }
  // Phase 6 (AUDIT-04): additive audit default — idempotent; single upgrade site (P5-12 pattern).
  if (settings['audit'] === undefined) {
    settings['audit'] = { staleThresholdDays: 365 };
  }
  // Phase 8 (D-02/D-10): additive schemaVersion 1→2 bump + lostVersions default.
  // idempotent — never downgrades; never overwrites existing lostVersions arrays.
  if (raw['schemaVersion'] === 1) {
    raw['schemaVersion'] = 2;
  }
  if (Array.isArray(raw['entries'])) {
    for (const entry of raw['entries'] as Array<Record<string, unknown>>) {
      if (entry['lostVersions'] === undefined) {
        entry['lostVersions'] = [];
      }
    }
  }
  // Phase 21 (D-01): additive schemaVersion 2→3 bump — a PURE version-number flip,
  // strictly narrower than the 1→2 block above. NO per-entry backfill: `email`,
  // `equivalentUrls`, `card`, `identity` stay absent on every pre-existing entry
  // until the user sets them (SCHEMA-01/02, IDENT-03 — never rewrites an existing
  // field, never splits `username` into `email`).
  //
  // PHASE-22 BREADCRUMB (do not fix here — read-only this phase). This bump makes every
  // opened vault schemaVersion 3 on the next CRUD call, but the LOCKED sync path only
  // knows versions 1|2. Phase 22 (SYNCP-01 GATE) MUST update ALL of the following before
  // any sync path exercises a v3 vault, or sync either fails closed or silently drops the
  // new fields:
  //   1. `apps/desktop/src/lib/sync/syncOrchestration.ts:96`
  //      `KNOWN_INNER_DOC_SCHEMA_VERSIONS = new Set([1, 2])` — the fail-closed HARDEN-02
  //      allowlist (enforced at :470 A-side and :834 B-side). A v3 vault currently throws
  //      `MergeSchemaMismatchError` here. Widen to include 3 — but ONLY together with the
  //      merge-field-parity fixes below, else a v3↔v3 merge PROCEEDS and silently strips
  //      the new fields (fail-safe loud error → silent data loss). Do not widen alone.
  //   2. `sync/merge.ts:361` exact-equality gate (`local.schemaVersion !== remote.schemaVersion`)
  //      — decide mixed 2/3-peer semantics (a v2 device syncing with a migrated v3 device).
  //   3. `sync/merge.ts` `deepCopyEntry` (object-literal return, `merge.ts:240-275`) silently
  //      strips any new `Entry` field (it is not a spread — only named fields are copied), and
  //      `contentEqual`/`canonicalEntry`/`meaningfulContentDiffers` hand-enumerate fields and
  //      don't know about `email`/`equivalentUrls`/`card`/`identity` either.
  //   4. Add a sync regression test whose fixtures carry `schemaVersion: 3` (or route through
  //      `asInnerDoc()`) — the existing sync tests build InnerDoc directly from `createVault`
  //      (schemaVersion 1) and never exercise the v3 path, so they stay green while sync is broken.
  if (raw['schemaVersion'] === 2) {
    raw['schemaVersion'] = 3;
  }

  return vault.entries as InnerDoc;
}

/**
 * Return a guaranteed-defaulted settings object without mutating any entry.
 *
 * This is the canonical accessor for lock/clipboard settings in the desktop idle
 * controller, clipboard clear timer, and Settings UI (RESEARCH Pitfall 7 / Open Q3).
 * Calling `asInnerDoc()` ensures the P5-12 defaults (`lock`, `clipboard`) are filled
 * before any CRUD verb has been invoked — safe to call immediately after unlock.
 *
 * Pure function — no Tauri/Svelte/node imports (Core purity rule).
 */
export function getVaultSettings(vault: UnlockedVault): InnerDoc['settings'] {
  return asInnerDoc(vault).settings;
}

/**
 * Push the old password to `passwordHistory` (newest-first) and cap at 10.
 *
 * Single shared implementation for both `updateEntry` (manual password change)
 * and `regenerateFromPreset` (ENTRY-07/ENTRY-09 single source of truth).
 * T-03-04: the hard cap keeps plaintext surface inside the sealed `data` blob bounded.
 */
function pushHistory(entry: Entry, oldPassword: string): void {
  entry.passwordHistory.unshift({ password: oldPassword, changedAt: nowIso() });
  entry.passwordHistory = entry.passwordHistory.slice(0, 10);
}

// ---------------------------------------------------------------------------
// Public CRUD verbs
// ---------------------------------------------------------------------------

/**
 * Add a new entry to the vault (ENTRY-01/ENTRY-02).
 *
 * - Generates a CSPRNG-backed UUIDv4 for `id` (P3-03).
 * - Sets `type` from `input.type` (default `'login'`), `createdAt`, `modifiedAt` to now.
 *   `type` is immutable after creation (Phase 23 D-03) — `EntryUpdate` continues to omit it.
 * - `deletedAt` is `null`; `passwordHistory` is `[]`.
 * - Maps the Phase-21 optional fields (`email`/`equivalentUrls`/`card`/`identity`) from
 *   `input` onto the created entry via conditional spread — an absent input field stays
 *   OMITTED on the entry (never set to `undefined`, per `exactOptionalPropertyTypes`).
 * - Mutates `vault.entries` in place and returns the new Entry.
 *
 * @throws GeneratorError if entry input is structurally invalid (future validation).
 */
export async function addEntry(vault: UnlockedVault, input: EntryInput): Promise<Entry> {
  const sodium = await getSodium();
  const inner = asInnerDoc(vault);

  const id = uuidV4FromBytes(sodium.randombytes_buf(16));
  const now = nowIso();

  const entry: Entry = {
    id,
    type: input.type ?? 'login',
    title: input.title,
    username: input.username ?? '',
    password: input.password ?? '',
    url: input.url ?? '',
    notes: input.notes ?? '',
    tags: input.tags ?? [],
    ...(input.email !== undefined ? { email: input.email } : {}),
    ...(input.equivalentUrls !== undefined ? { equivalentUrls: input.equivalentUrls } : {}),
    ...(input.card !== undefined ? { card: input.card } : {}),
    ...(input.identity !== undefined ? { identity: input.identity } : {}),
    favorite: input.favorite ?? false,
    needsSiteUpdate: input.needsSiteUpdate ?? false,
    generatorPreset: input.generatorPreset ?? null,
    passwordHistory: [],
    createdAt: now,
    modifiedAt: now,
    deletedAt: null,
  };

  inner.entries.push(entry);
  return entry;
}

/**
 * Update mutable fields on an existing active entry (ENTRY-03/ENTRY-07).
 *
 * - If `update.password` differs from the current value, the OLD password is
 *   pushed onto `passwordHistory` (newest-first, cap 10) before the update.
 * - `modifiedAt` is always updated to now.
 * - Mutates the entry in place and returns the updated Entry.
 *
 * @throws EntryNotFoundError if `id` is not found or is soft-deleted.
 */
export function updateEntry(vault: UnlockedVault, id: string, update: EntryUpdate): Entry {
  const inner = asInnerDoc(vault);
  const entry = inner.entries.find((e) => e.id === id && e.deletedAt === null);
  if (entry === undefined) {
    throw new EntryNotFoundError(
      `Entry not found or is soft-deleted: ${id}`,
    );
  }

  // Push old password to history only when password actually changes (ENTRY-07).
  if (update.password !== undefined && update.password !== entry.password) {
    pushHistory(entry, entry.password);
  }

  // Apply mutable fields from the update (omit immutable fields — id, type, createdAt).
  if (update.title !== undefined) entry.title = update.title;
  if (update.username !== undefined) entry.username = update.username;
  if (update.password !== undefined) entry.password = update.password;
  if (update.url !== undefined) entry.url = update.url;
  if (update.notes !== undefined) entry.notes = update.notes;
  if (update.tags !== undefined) entry.tags = update.tags;
  if (update.favorite !== undefined) entry.favorite = update.favorite;
  if (update.needsSiteUpdate !== undefined) entry.needsSiteUpdate = update.needsSiteUpdate;
  if (update.generatorPreset !== undefined) entry.generatorPreset = update.generatorPreset;
  if (update.passwordHistory !== undefined) entry.passwordHistory = update.passwordHistory;
  if (update.modifiedAt !== undefined) {
    entry.modifiedAt = update.modifiedAt;
  } else {
    entry.modifiedAt = nowIso();
  }
  if (update.deletedAt !== undefined) entry.deletedAt = update.deletedAt;

  return entry;
}

/**
 * Restore a soft-deleted entry by clearing its `deletedAt` tombstone (ENTRY-05).
 *
 * The inverse of `softDeleteEntry`: it targets ONLY tombstones (`deletedAt !== null`)
 * — the exact rows the Recently Deleted view shows. This is a SEPARATE verb from
 * `updateEntry` because `updateEntry` deliberately refuses soft-deleted entries
 * (it finds by `deletedAt === null`), so it can never un-tombstone a row.
 *
 * - Finds the entry by `id` AND `deletedAt !== null` (a tombstone).
 * - Sets `deletedAt = null` and updates `modifiedAt` to now (matches the
 *   updateEntry/softDeleteEntry convention of touching modifiedAt on a state change).
 * - Mutates the entry in place and returns the restored Entry.
 *
 * @throws EntryNotFoundError if `id` is not found OR the entry is NOT soft-deleted
 *         (an already-active entry is not a tombstone — fail closed, the safe choice).
 */
export function restoreEntry(vault: UnlockedVault, id: string): Entry {
  const inner = asInnerDoc(vault);
  const entry = inner.entries.find((e) => e.id === id && e.deletedAt !== null);
  if (entry === undefined) {
    throw new EntryNotFoundError(
      `Entry not found or is not soft-deleted: ${id}`,
    );
  }
  entry.deletedAt = null;
  entry.modifiedAt = nowIso();
  return entry;
}

/**
 * Soft-delete an entry by setting `deletedAt` (ENTRY-03/ENTRY-04 tombstone).
 *
 * The entry remains in `vault.entries` for sync + Recently Deleted UI.
 * `modifiedAt` is updated to the same timestamp as `deletedAt`.
 *
 * @throws EntryNotFoundError if `id` is not found.
 */
export function softDeleteEntry(vault: UnlockedVault, id: string): void {
  const inner = asInnerDoc(vault);
  const entry = inner.entries.find((e) => e.id === id);
  if (entry === undefined) {
    throw new EntryNotFoundError(`Entry not found: ${id}`);
  }
  const now = nowIso();
  entry.deletedAt = now;
  entry.modifiedAt = now;
}

/**
 * Permanently remove an entry from `vault.entries` (ENTRY-03).
 *
 * Hard-deletes the record — the user confirmed in the UI (Phase 4 explicit confirm
 * gate; this function does NOT prompt). If `id` is not found, silently no-ops.
 */
export function purgeEntry(vault: UnlockedVault, id: string): void {
  const inner = asInnerDoc(vault);
  const idx = inner.entries.findIndex((e) => e.id === id);
  if (idx !== -1) {
    inner.entries.splice(idx, 1);
  }
}

/**
 * List entries (ENTRY-03).
 *
 * @param includeDeleted When false (default), filters out tombstones (`deletedAt !== null`).
 *                       Pass `true` for the Recently Deleted view.
 */
export function listEntries(vault: UnlockedVault, includeDeleted?: boolean): Entry[] {
  const inner = asInnerDoc(vault);
  if (includeDeleted === true) {
    return [...inner.entries];
  }
  return inner.entries.filter((e) => e.deletedAt === null);
}

/**
 * Retrieve a single entry by ID regardless of deleted status.
 *
 * Returns `undefined` if not found (caller handles missing case).
 */
export function getEntry(vault: UnlockedVault, id: string): Entry | undefined {
  const inner = asInnerDoc(vault);
  return inner.entries.find((e) => e.id === id);
}

/**
 * Derive the age of the current password in milliseconds (AUDIT-04 precursor, TEST-04).
 *
 * Age is measured from the most recent `passwordHistory[0].changedAt` timestamp,
 * or from `entry.createdAt` if history is empty (password has never been changed).
 *
 * @param nowMs Optional current time in ms for testability. Defaults to `Date.now()`.
 */
export function derivePasswordAge(entry: Entry, nowMs?: number): number {
  const now = nowMs ?? Date.now();
  const referenceTs =
    entry.passwordHistory.length > 0
      ? entry.passwordHistory[0]!.changedAt
      : entry.createdAt;
  return now - new Date(referenceTs).getTime();
}

/**
 * Regenerate the entry password from its saved `generatorPreset` (ENTRY-09 / P3-07).
 *
 * 1. Generates a new password using the stored preset options.
 * 2. Pushes the OLD `password` + a `changedAt` timestamp to `passwordHistory` (cap 10).
 * 3. Updates `password` and `modifiedAt` on the entry.
 * 4. Mutates `vault.entries` in place and returns the updated Entry.
 *
 * @throws EntryNotFoundError if `id` is not found or is soft-deleted.
 * @throws GeneratorError if `generatorPreset` is null (no preset saved).
 */
export async function regenerateFromPreset(vault: UnlockedVault, id: string): Promise<Entry> {
  const inner = asInnerDoc(vault);
  const entry = inner.entries.find((e) => e.id === id && e.deletedAt === null);
  if (entry === undefined) {
    throw new EntryNotFoundError(
      `Entry not found or is soft-deleted: ${id}`,
    );
  }
  if (entry.generatorPreset === null) {
    throw new GeneratorError(
      `Entry has no saved generatorPreset: ${id}`,
    );
  }

  let newPassword: string;
  if (entry.generatorPreset.mode === 'random') {
    const result = await generateRandom(entry.generatorPreset);
    newPassword = result.password;
  } else {
    const result = await generatePassphrase(entry.generatorPreset);
    newPassword = result.phrase;
  }

  // Push old password to history (same logic as updateEntry — single source of truth).
  pushHistory(entry, entry.password);
  entry.password = newPassword;
  entry.modifiedAt = nowIso();

  return entry;
}
