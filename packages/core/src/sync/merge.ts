// packages/core/src/sync/merge.ts
//
// Pure, IO-free merge engine for Phase 8 (MERGE-01).
//
// Contract:
//   - Zero IO: no Tauri, no Svelte, no node:fs, no node:path, no libsodium imports.
//   - Clock and device identities are ALWAYS injected via MergeContext (D-12/D-14).
//     The engine never calls Date.now() internally.
//   - Caller (Phase 11) owns the merged plaintext lifecycle — MergeResult is
//     plaintext; the caller MUST secureWipe after re-encryption (D-11).
//   - Fail closed: any invalid input throws MergeInvalidInputError before any
//     records are merged; schema version mismatch throws MergeSchemaMismatchError;
//     clock skew >30s throws MergeClockSkewError (both abort before any records
//     are processed — D-09/D-12/D-17).
//
// Merge rules implemented here:
//   - D-01: Loser's full content preserved as EntrySnapshot in lostVersions.
//   - D-03: passwordHistory union — union both lists, sort newest-first by changedAt,
//     dedup exact items (changedAt::password key), apply cap 10.
//   - D-04: merged.settings = local.settings; settings-local.
//   - D-05: Soft delete preserves — soft tombstone wins; concurrent peer edit's
//     full snapshot preserved into tombstone lostVersions.
//   - D-07: Permanent delete is final — content-wiped tombstone wins everywhere;
//     peer still-live content NOT preserved (single sanctioned exception to D-01).
//   - D-08: Entry only on one side (no tombstone) → kept.
//   - D-09: schemaVersion mismatch → MergeSchemaMismatchError before any records merge.
//   - D-12: Clock skew |Δ| > 30s → MergeClockSkewError before any records merge.
//   - D-13: Tiebreak on identical modifiedAt — lexicographically-greater deviceId wins;
//     loser preserved as full snapshot (same as any LWW loser — D-01). On EQUAL deviceIds,
//     greater canonical content wins (deterministic), loser still preserved.
//   - D-14: identical content on both sides → unchanged regardless of deviceIds (idempotency).
//     ALL ties (both-soft equal-deletedAt, both-permanent, equal-deviceId differing content)
//     resolve by a deterministic, argument-order-independent rule — never positional `local`
//     — so both PCs converge to byte-identical content (D-18); no loser is silently dropped.
//   - D-16: Per-device counts (added/updated/deleted/unchanged).
//   - D-17: Per-entry input validation (valid id, parseable modifiedAt, required shape);
//     whole merge refused on any violation — never partial.
//   - D-18: Property-based convergence — commutativity + idempotency enforced via
//     deterministic ordering and identical-content shortcut.
//
// Source: CONTEXT.md D-01..D-19; PATTERNS.md merge.ts section

import type {
  Entry,
  EntryCard,
  EntryIdentity,
  InnerDoc,
  PasswordHistoryItem,
} from '../entries/types';
import {
  MergeClockSkewError,
  MergeSchemaMismatchError,
  MergeInvalidInputError,
} from '../errors';
import type {
  MergeContext,
  MergeResult,
  ConflictRecord,
  EntrySnapshot,
  MergeCounts,
} from './types';
import { isPermanentTombstone } from './types';

// ---------------------------------------------------------------------------
// Phase 22 (SYNCP-02/D-03): set of InnerDoc.schemaVersion values this build
// understands. Fails closed (MergeSchemaMismatchError) on anything outside
// this set BEFORE any record is processed — see GUARD 0 in mergeInnerDocs.
//
// MUST be kept in exact lockstep with apps/desktop/src/lib/sync/
// syncOrchestration.ts:96's KNOWN_INNER_DOC_SCHEMA_VERSIONS (HARDEN-02). The
// two are independent literals (core has no import path to desktop — core
// purity) so this is a discipline point, not an enforceable-by-import
// invariant. Widen ONLY together with that constant (Pitfall 1 — widen-alone
// converts a loud fail-safe into a silent field-strip).
// ---------------------------------------------------------------------------
const KNOWN_SCHEMA_VERSIONS = new Set([1, 2, 3]);

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/**
 * Parse a modifiedAt ISO 8601 string to epoch-ms.
 * Throws MergeInvalidInputError on NaN (RESEARCH Pattern 1 / D-17).
 */
function parseModifiedAt(ts: string, entryId: string): number {
  const ms = Date.parse(ts);
  if (Number.isNaN(ms)) {
    throw new MergeInvalidInputError(
      `Entry ${entryId}: unparseable modifiedAt: ${ts}`,
    );
  }
  return ms;
}

/**
 * Union two passwordHistory lists, dedup, sort newest-first with a stable secondary
 * key, and slice to cap (RESEARCH Pattern 2 / D-03).
 *
 * Dedup key: `${changedAt}::${item.password}` — exact match.
 * Secondary sort key: lexicographic on password — REQUIRED for commutativity (D-18).
 */
function unionHistory(
  a: PasswordHistoryItem[],
  b: PasswordHistoryItem[],
  cap = 10,
): PasswordHistoryItem[] {
  const seen = new Set<string>();
  const merged: PasswordHistoryItem[] = [];
  for (const item of [...a, ...b]) {
    const key = `${item.changedAt}::${item.password}`;
    if (!seen.has(key)) {
      seen.add(key);
      merged.push(item);
    }
  }
  // Sort newest-first by changedAt epoch-ms; secondary stable key: lexicographic on
  // password to break equal-changedAt ties deterministically (D-18 commutativity).
  merged.sort((x, y) => {
    const diff = Date.parse(y.changedAt) - Date.parse(x.changedAt);
    if (diff !== 0) return diff;
    return y.password < x.password ? -1 : y.password > x.password ? 1 : 0;
  });
  return merged.slice(0, cap);
}

/**
 * Build an EntrySnapshot from an entry + the deviceId that produced it (D-01/D-15).
 */
function snapshotOf(entry: Entry, deviceId: string): EntrySnapshot {
  return {
    password: entry.password,
    username: entry.username,
    url: entry.url,
    notes: entry.notes,
    tags: [...entry.tags],
    modifiedAt: entry.modifiedAt,
    deviceId,
  };
}

/**
 * Append a snapshot to lostVersions, dedup, and keep the 5 NEWEST by modifiedAt
 * (D-02/T-03-04 plaintext-surface discipline).
 *
 * Deep-copies the incoming list so callers do not share references.
 */
function capLostVersions(
  existing: EntrySnapshot[],
  newSnapshot: EntrySnapshot,
): EntrySnapshot[] {
  // Dedup by (modifiedAt, deviceId, password)
  const combined = [...existing];
  const key = `${newSnapshot.modifiedAt}::${newSnapshot.deviceId}::${newSnapshot.password}`;
  const alreadyPresent = combined.some(
    (s) => `${s.modifiedAt}::${s.deviceId}::${s.password}` === key,
  );
  if (!alreadyPresent) {
    combined.push(newSnapshot);
  }
  // Sort newest-first by modifiedAt, with deterministic secondary on deviceId
  combined.sort((x, y) => {
    const diff = Date.parse(y.modifiedAt) - Date.parse(x.modifiedAt);
    if (diff !== 0) return diff;
    return y.deviceId < x.deviceId ? -1 : y.deviceId > x.deviceId ? 1 : 0;
  });
  return combined.slice(0, 5);
}

/**
 * Validate a single entry for required shape (D-17).
 * Throws MergeInvalidInputError if invalid.
 * Returns the parsed modifiedAt epoch-ms for reuse.
 */
function validateEntry(entry: Entry): number {
  if (typeof entry.id !== 'string' || entry.id.trim() === '') {
    throw new MergeInvalidInputError(
      `Entry has missing or empty id: ${JSON.stringify(entry.id)}`,
    );
  }
  // D-17: required shape — fail closed on any malformed field BEFORE any merge work
  // (the remote InnerDoc is attacker-influenceable per the threat model; T-08-11).
  for (const field of ['title', 'username', 'password', 'url', 'notes'] as const) {
    if (typeof entry[field] !== 'string') {
      throw new MergeInvalidInputError(
        `Entry ${entry.id}: field '${field}' must be a string`,
      );
    }
  }
  if (!Array.isArray(entry.tags) || entry.tags.some((t) => typeof t !== 'string')) {
    throw new MergeInvalidInputError(`Entry ${entry.id}: tags must be a string[]`);
  }
  if (
    !Array.isArray(entry.passwordHistory) ||
    entry.passwordHistory.some(
      (h) =>
        h === null ||
        typeof h !== 'object' ||
        typeof h.password !== 'string' ||
        typeof h.changedAt !== 'string' ||
        Number.isNaN(Date.parse(h.changedAt)),
    )
  ) {
    throw new MergeInvalidInputError(
      `Entry ${entry.id}: passwordHistory must be {password,changedAt}[] with parseable changedAt`,
    );
  }
  if (entry.lostVersions !== undefined && !Array.isArray(entry.lostVersions)) {
    throw new MergeInvalidInputError(
      `Entry ${entry.id}: lostVersions must be an array when present`,
    );
  }
  if (
    entry.deletedAt !== null &&
    (typeof entry.deletedAt !== 'string' || Number.isNaN(Date.parse(entry.deletedAt)))
  ) {
    throw new MergeInvalidInputError(
      `Entry ${entry.id}: deletedAt must be null or a parseable ISO string`,
    );
  }
  // Phase 22 (SYNCP-01/T-08-11): the remote InnerDoc is attacker-influenceable —
  // strictly type-check the four Phase-21 v3 fields when present. Whole objects
  // stay optional (undefined is always valid, matching every pre-Phase-21 entry
  // and every non-card/identity `type`).
  if (entry.email !== undefined && typeof entry.email !== 'string') {
    throw new MergeInvalidInputError(`Entry ${entry.id}: email must be a string when present`);
  }
  if (
    entry.equivalentUrls !== undefined &&
    (!Array.isArray(entry.equivalentUrls) ||
      entry.equivalentUrls.some((u) => typeof u !== 'string'))
  ) {
    throw new MergeInvalidInputError(
      `Entry ${entry.id}: equivalentUrls must be a string[] when present`,
    );
  }
  if (entry.card !== undefined) {
    if (entry.card === null || typeof entry.card !== 'object' || Array.isArray(entry.card)) {
      throw new MergeInvalidInputError(`Entry ${entry.id}: card must be an object when present`);
    }
    const card = entry.card as unknown as Record<string, unknown>;
    for (const key of [
      'cardholderName',
      'number',
      'expiryMonth',
      'expiryYear',
      'cvv',
      'brand',
      'nickname',
    ] as const) {
      if (card[key] !== undefined && typeof card[key] !== 'string') {
        throw new MergeInvalidInputError(
          `Entry ${entry.id}: card.${key} must be a string when present`,
        );
      }
    }
  }
  if (entry.identity !== undefined) {
    if (
      entry.identity === null ||
      typeof entry.identity !== 'object' ||
      Array.isArray(entry.identity)
    ) {
      throw new MergeInvalidInputError(
        `Entry ${entry.id}: identity must be an object when present`,
      );
    }
    const identity = entry.identity as unknown as Record<string, unknown>;
    for (const key of ['name', 'email', 'phone', 'address'] as const) {
      if (identity[key] !== undefined && typeof identity[key] !== 'string') {
        throw new MergeInvalidInputError(
          `Entry ${entry.id}: identity.${key} must be a string when present`,
        );
      }
    }
  }
  return parseModifiedAt(entry.modifiedAt, entry.id);
}

/**
 * Compare two optional `equivalentUrls` arrays. `undefined` vs `undefined` is
 * equal; `undefined` vs `[]` is NOT (a real semantic distinction between
 * "never set" and "explicitly cleared" — Phase 22 RESEARCH Code Examples).
 */
function equivalentUrlsEqual(a: string[] | undefined, b: string[] | undefined): boolean {
  if (a === undefined || b === undefined) return a === b;
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/** Field-by-field EntryCard comparison (house style — no deep-equal library). */
function cardEqual(a: EntryCard | undefined, b: EntryCard | undefined): boolean {
  if (a === undefined || b === undefined) return a === b;
  return (
    a.cardholderName === b.cardholderName &&
    a.number === b.number &&
    a.expiryMonth === b.expiryMonth &&
    a.expiryYear === b.expiryYear &&
    a.cvv === b.cvv &&
    a.brand === b.brand &&
    a.nickname === b.nickname
  );
}

/** Field-by-field EntryIdentity comparison (house style — no deep-equal library). */
function identityEqual(a: EntryIdentity | undefined, b: EntryIdentity | undefined): boolean {
  if (a === undefined || b === undefined) return a === b;
  return (
    a.name === b.name && a.email === b.email && a.phone === b.phone && a.address === b.address
  );
}

/**
 * Check if two active entries have identical content on all meaningful fields.
 *
 * Used to implement the D-14 / D-18 idempotency shortcut: when both sides are
 * content-identical (regardless of which deviceId produced them), the merge is
 * a no-op — unchanged count, no snapshot, no conflict.
 *
 * Required for `merge(A, A, ctx)` to be a no-op even when localDeviceId ≠ remoteDeviceId.
 */
function contentEqual(a: Entry, b: Entry): boolean {
  if (a.password !== b.password) return false;
  if (a.username !== b.username) return false;
  if (a.url !== b.url) return false;
  if (a.notes !== b.notes) return false;
  if (a.title !== b.title) return false;
  // Phase 22 (SYNCP-01/D-02a): contentEqual DOES gain the new fields — required
  // so merge(A,A) stays a true no-op when v3 entries carry email/equivalentUrls/
  // card/identity, and so two entries differing ONLY in a new field are never
  // false-equalled by the D-14 idempotency shortcut.
  if (a.email !== b.email) return false;
  if (!equivalentUrlsEqual(a.equivalentUrls, b.equivalentUrls)) return false;
  if (!cardEqual(a.card, b.card)) return false;
  if (!identityEqual(a.identity, b.identity)) return false;
  if (a.modifiedAt !== b.modifiedAt) return false;
  if (a.deletedAt !== b.deletedAt) return false;
  if (a.favorite !== b.favorite) return false;
  if (a.needsSiteUpdate !== b.needsSiteUpdate) return false;
  if (a.tags.length !== b.tags.length) return false;
  for (let i = 0; i < a.tags.length; i++) {
    if (a.tags[i] !== b.tags[i]) return false;
  }
  if (a.passwordHistory.length !== b.passwordHistory.length) return false;
  for (let i = 0; i < a.passwordHistory.length; i++) {
    const ah = a.passwordHistory[i]!;
    const bh = b.passwordHistory[i]!;
    if (ah.password !== bh.password || ah.changedAt !== bh.changedAt) return false;
  }
  return true;
}

/**
 * Deep-copy an entry to prevent aliasing across multiple merges (D-18 idempotency).
 * Input mutation would corrupt idempotency and commutativity proofs.
 */
function deepCopyEntry(entry: Entry): Entry {
  return {
    id: entry.id,
    type: entry.type,
    title: entry.title,
    username: entry.username,
    password: entry.password,
    url: entry.url,
    notes: entry.notes,
    tags: [...entry.tags],
    // Phase 22 (SYNCP-01): the four Phase-21 v3 fields, each conditionally
    // spread so the key is OMITTED when absent (never assigned `undefined` —
    // exactOptionalPropertyTypes). `card`/`identity` are flat all-string
    // interfaces (entries/types.ts) so a shallow `{...}` IS a legitimate deep
    // copy here — no nested arrays/objects to alias.
    ...(entry.email !== undefined ? { email: entry.email } : {}),
    ...(entry.equivalentUrls !== undefined
      ? { equivalentUrls: [...entry.equivalentUrls] }
      : {}),
    ...(entry.card !== undefined ? { card: { ...entry.card } } : {}),
    ...(entry.identity !== undefined ? { identity: { ...entry.identity } } : {}),
    favorite: entry.favorite,
    needsSiteUpdate: entry.needsSiteUpdate,
    // Deep-copy the preset object so the merged result never aliases an input doc
    // (the deep-copy contract; a later in-place mutation must not touch the inputs).
    generatorPreset: entry.generatorPreset === null ? null : { ...entry.generatorPreset },
    passwordHistory: entry.passwordHistory.map((h) => ({
      password: h.password,
      changedAt: h.changedAt,
    })),
    lostVersions:
      entry.lostVersions !== undefined
        ? entry.lostVersions.map((s) => ({
            password: s.password,
            username: s.username,
            url: s.url,
            notes: s.notes,
            tags: [...s.tags],
            modifiedAt: s.modifiedAt,
            deviceId: s.deviceId,
          }))
        : [],
    createdAt: entry.createdAt,
    modifiedAt: entry.modifiedAt,
    deletedAt: entry.deletedAt,
  };
}

/**
 * True when two entries differ on any RECOVERABLE/meaningful content field per D-01
 * (password, username, url, notes, title, tags). Excludes timestamps and flags.
 *
 * Used to (a) gate the D-15 lww/tiebreak/delete-wins conflict record on a provably-lossy
 * overwrite, and (b) decide whether a tombstone tie needs loser preservation. Symmetric
 * (argument-order-independent), so it never breaks commutativity.
 */
// Phase 22 (D-02a, option (a) — DELIBERATE, do not "fix" by adding fields here):
// email/equivalentUrls/card/identity are NOT included in this function on purpose.
// snapshotOf (D-02) stays password-centric and never captures these four fields,
// so widening meaningfulContentDiffers to treat a new-field-only difference as
// "meaningful" would push a ConflictRecord/lostVersions entry whose loserSnapshot
// looks byte-identical to the winner on every field it actually stores — an
// honest-looking but empty "recovery" record that overclaims recoverability the
// snapshot cannot deliver. A loser that differs from the winner ONLY in a new
// field is therefore treated as "not meaningfully different": no conflict is
// recorded, and no false promise of snapshot-recoverable content is made.
function meaningfulContentDiffers(a: Entry, b: Entry): boolean {
  if (a.password !== b.password) return true;
  if (a.username !== b.username) return true;
  if (a.url !== b.url) return true;
  if (a.notes !== b.notes) return true;
  if (a.title !== b.title) return true;
  if (a.tags.length !== b.tags.length) return true;
  for (let i = 0; i < a.tags.length; i++) {
    if (a.tags[i] !== b.tags[i]) return true;
  }
  return false;
}

/**
 * Deterministic canonical serialization of an entry's content (D-18). The final,
 * argument-order-independent tiebreak when neither timestamp nor deviceId decides.
 */
function canonicalEntry(e: Entry): string {
  return JSON.stringify([
    e.password,
    e.username,
    e.url,
    e.notes,
    e.title,
    // Phase 22 (SYNCP-01/Pitfall 4): canonicalEntry DOES gain the new fields —
    // omitting them would make two entries differing ONLY in card/identity/
    // email/equivalentUrls compare canonically-equal-ish in the pathological
    // equal-deviceId + equal-modifiedAt tiebreak, breaking D-18 determinism
    // for v3 entries in that edge case.
    e.email ?? null,
    e.equivalentUrls ?? null,
    e.card ?? null,
    e.identity ?? null,
    e.modifiedAt,
    e.deletedAt,
    e.favorite,
    e.needsSiteUpdate,
    [...e.tags],
    e.passwordHistory.map((h) => [h.changedAt, h.password]),
  ]);
}

/**
 * Decide a deterministic, argument-order-independent winner between two versions of the
 * same id when the primary key (modifiedAt / deletedAt) is tied (D-13/D-18). Cascade:
 * lexicographically-greater deviceId wins; on equal deviceIds (the pathological
 * same-identity case) greater canonical content wins. Returns true when LOCAL should win.
 *
 * Symmetric: under (local,remote) swap with a swapped ctx, the SAME physical entry wins,
 * so `merge(A,B)` and `merge(B,A)` converge to identical content.
 */
function localWinsTiebreak(localEntry: Entry, remoteEntry: Entry, ctx: MergeContext): boolean {
  if (ctx.localDeviceId !== ctx.remoteDeviceId) {
    return ctx.localDeviceId > ctx.remoteDeviceId;
  }
  return canonicalEntry(localEntry) >= canonicalEntry(remoteEntry);
}

// ---------------------------------------------------------------------------
// Public export
// ---------------------------------------------------------------------------

/**
 * Merge two decrypted `InnerDoc`s into a single deterministic `MergeResult`.
 *
 * Pure, IO-free, argument-order-independent (both devices converge to the same
 * merged entry set — D-18 commutativity guarantee; proven by the 08-02 property
 * test suite).
 *
 * @param local  - This device's decrypted InnerDoc (binding already verified upstream).
 * @param remote - Remote device's decrypted InnerDoc.
 * @param ctx    - Injected wall-clock + device identities (D-12/D-14).
 *
 * @throws MergeSchemaMismatchError if `local.schemaVersion !== remote.schemaVersion` (D-09).
 * @throws MergeClockSkewError if `|ctx.localNowMs - ctx.remoteNowMs| > 30_000` (D-12).
 * @throws MergeInvalidInputError if any entry has an invalid shape (D-17).
 */
export function mergeInnerDocs(
  local: InnerDoc,
  remote: InnerDoc,
  ctx: MergeContext,
): MergeResult {
  // -------------------------------------------------------------------------
  // GUARD 0: schemaVersion ceiling (D-03/SYNCP-02) — fires BEFORE GUARD 1's
  // exact-equality check and before any entry validation. Additive to (never
  // a replacement of) D-01's exact-equality gate: two known-but-mismatched
  // versions (e.g. 2 vs 3) still fall through to GUARD 1 below and throw
  // there; this guard only catches a schemaVersion this build does not
  // understand at all (e.g. a future 4+, or a corrupt/attacker-influenced
  // value) — a case the exact-equality check alone cannot catch when BOTH
  // sides happen to carry the same unknown value.
  // -------------------------------------------------------------------------
  if (
    !KNOWN_SCHEMA_VERSIONS.has(local.schemaVersion) ||
    !KNOWN_SCHEMA_VERSIONS.has(remote.schemaVersion)
  ) {
    throw new MergeSchemaMismatchError(
      `Unknown InnerDoc schemaVersion: local=${local.schemaVersion}, remote=${remote.schemaVersion} (known: ${[...KNOWN_SCHEMA_VERSIONS].join(',')})`,
    );
  }

  // -------------------------------------------------------------------------
  // GUARD 1: Schema version equality (D-09) — must fire before any records merge.
  // -------------------------------------------------------------------------
  if (local.schemaVersion !== remote.schemaVersion) {
    throw new MergeSchemaMismatchError(
      `Cannot merge InnerDocs with different schemaVersions: local=${local.schemaVersion}, remote=${remote.schemaVersion}`,
    );
  }

  // -------------------------------------------------------------------------
  // GUARD 2: Clock-skew check (D-12) — strict > 30_000ms; exactly 30_000ms is OK.
  // -------------------------------------------------------------------------
  const clockDiff = Math.abs(ctx.localNowMs - ctx.remoteNowMs);
  if (clockDiff > 30_000) {
    throw new MergeClockSkewError(
      `Clock skew too large: |local=${ctx.localNowMs} - remote=${ctx.remoteNowMs}| = ${clockDiff}ms (max 30_000ms)`,
    );
  }

  // -------------------------------------------------------------------------
  // GUARD 3: Per-entry input validation (D-17) — validate BOTH sides before merge.
  // An empty entries array is valid (D-17 explicitly states zero entries is OK).
  // -------------------------------------------------------------------------
  const localModifiedMs = new Map<string, number>();
  const remoteModifiedMs = new Map<string, number>();

  for (const entry of local.entries) {
    const ms = validateEntry(entry);
    localModifiedMs.set(entry.id, ms);
  }
  for (const entry of remote.entries) {
    const ms = validateEntry(entry);
    remoteModifiedMs.set(entry.id, ms);
  }

  // -------------------------------------------------------------------------
  // BUILD the unified entry map: id → { local?: Entry, remote?: Entry }
  // Iterate the map (not raw arrays) for deterministic merge order (D-18 Pitfall 1).
  // -------------------------------------------------------------------------
  const entryMap = new Map<string, { local?: Entry; remote?: Entry }>();

  for (const entry of local.entries) {
    entryMap.set(entry.id, { local: entry });
  }
  for (const entry of remote.entries) {
    const existing = entryMap.get(entry.id);
    if (existing !== undefined) {
      existing.remote = entry;
    } else {
      entryMap.set(entry.id, { remote: entry });
    }
  }

  // -------------------------------------------------------------------------
  // MERGE each unique id
  // -------------------------------------------------------------------------
  const mergedEntries: Entry[] = [];
  const conflicts: ConflictRecord[] = [];
  const counts: MergeCounts = { added: 0, updated: 0, deleted: 0, unchanged: 0 };

  for (const [id, sides] of entryMap) {
    const { local: localEntry, remote: remoteEntry } = sides;

    // --- Case 1: Entry only on ONE side (no tombstone on the other) — keep it (D-08). ---
    // Normalize passwordHistory via unionHistory so EVERY merge output is canonical
    // (D-03: deduped, newest-first, cap-10). Without this, an input entry whose history
    // is non-canonical (e.g. duplicate items) passes through unchanged on the first merge
    // but is deduped on the second — breaking idempotency (D-18). A canonical history is
    // unaffected (unionHistory(h, []) === h).
    if (localEntry === undefined) {
      // Remote-only: new to this device → added (D-16)
      mergedEntries.push({
        ...deepCopyEntry(remoteEntry!),
        passwordHistory: unionHistory(remoteEntry!.passwordHistory, []),
      });
      counts.added++;
      continue;
    }
    if (remoteEntry === undefined) {
      // Local-only: already on this device → unchanged (D-16)
      mergedEntries.push({
        ...deepCopyEntry(localEntry),
        passwordHistory: unionHistory(localEntry.passwordHistory, []),
      });
      counts.unchanged++;
      continue;
    }

    // --- Case 2: Entry on BOTH sides — tombstone-first dispatch (RESEARCH Pitfall 6). ---
    // Never fall through to LWW when one side is a tombstone.

    const localIsPerm = isPermanentTombstone(localEntry);
    const remoteIsPerm = isPermanentTombstone(remoteEntry);
    const localIsSoft = localEntry.deletedAt !== null && !localIsPerm;
    const remoteIsSoft = remoteEntry.deletedAt !== null && !remoteIsPerm;
    const localIsActive = localEntry.deletedAt === null;
    const remoteIsActive = remoteEntry.deletedAt === null;

    // D-07: Permanent delete is final — wins everywhere; peer content NOT preserved.
    // NOT recorded in conflicts (permanent-delete-final is the sanctioned exception — D-15).
    if (localIsPerm || remoteIsPerm) {
      // D-07: permanent tombstone wins everywhere; peer content NOT preserved.
      let winner: Entry;
      if (localIsPerm && remoteIsPerm) {
        // Both permanent: deterministic, argument-order-independent winner so both
        // PCs converge (D-18) — earlier deletedAt (MERGE-04), then deviceId/content
        // tiebreak. NOT positional `local` (that diverges across devices).
        const lDel = Date.parse(localEntry.deletedAt!);
        const rDel = Date.parse(remoteEntry.deletedAt!);
        let localWins: boolean;
        if (lDel < rDel) localWins = true;
        else if (rDel < lDel) localWins = false;
        else localWins = localWinsTiebreak(localEntry, remoteEntry, ctx);
        winner = localWins ? localEntry : remoteEntry;
      } else {
        winner = localIsPerm ? localEntry : remoteEntry;
      }
      mergedEntries.push(deepCopyEntry(winner));
      // D-16 counts: remote permanent replacing a local ACTIVE entry = deleted; otherwise
      // (local permanent, both permanent, or local soft + remote permanent) = unchanged.
      if (remoteIsPerm && localIsActive) {
        counts.deleted++;
      } else {
        counts.unchanged++;
      }
      // D-07: peer content NOT preserved — no snapshot, no conflict record
      continue;
    }

    // Both soft-deleted: keep the EARLIER deletedAt (MERGE-04); on a deletedAt tie,
    // deterministic deviceId/content tiebreak (D-18 — never positional `local`).
    // Soft tombstones are restorable (D-05), so the LOSING tombstone's distinct content
    // is preserved (snapshot + password into history) — never silently lost.
    if (localIsSoft && remoteIsSoft) {
      const localDeletedMs = Date.parse(localEntry.deletedAt!);
      const remoteDeletedMs = Date.parse(remoteEntry.deletedAt!);
      let localWins: boolean;
      if (localDeletedMs < remoteDeletedMs) localWins = true;
      else if (remoteDeletedMs < localDeletedMs) localWins = false;
      else localWins = localWinsTiebreak(localEntry, remoteEntry, ctx);

      const winner = localWins ? localEntry : remoteEntry;
      const loser = localWins ? remoteEntry : localEntry;
      const winnerDeviceId = localWins ? ctx.localDeviceId : ctx.remoteDeviceId;
      const loserDeviceId = localWins ? ctx.remoteDeviceId : ctx.localDeviceId;

      if (meaningfulContentDiffers(winner, loser)) {
        const loserSnapshot = snapshotOf(loser, loserDeviceId);
        const loserHistoryItem: PasswordHistoryItem = {
          password: loser.password,
          changedAt: loser.modifiedAt,
        };
        const unitedHistory = unionHistory(winner.passwordHistory, [
          loserHistoryItem,
          ...loser.passwordHistory,
        ]);
        const updatedLost = capLostVersions(winner.lostVersions ?? [], loserSnapshot);
        mergedEntries.push({
          ...deepCopyEntry(winner),
          passwordHistory: unitedHistory,
          lostVersions: updatedLost,
        });
        conflicts.push({
          entryId: id,
          loserSnapshot,
          winnerSnapshot: snapshotOf(winner, winnerDeviceId),
          winnerModifiedAtMs: localWins ? localModifiedMs.get(id)! : remoteModifiedMs.get(id)!,
          loserModifiedAtMs: localWins ? remoteModifiedMs.get(id)! : localModifiedMs.get(id)!,
          winnerDeviceId,
          loserDeviceId,
          reason: 'delete-wins',
        });
      } else {
        // Identical meaningful content (or only timestamps differ): no loss, no conflict.
        const unitedHistory = unionHistory(winner.passwordHistory, loser.passwordHistory);
        mergedEntries.push({
          ...deepCopyEntry(winner),
          passwordHistory: unitedHistory,
        });
      }
      counts.unchanged++; // both sides already tombstoned — no new deletion on this device
      continue;
    }

    // One soft-deleted, one active: delete-wins (D-05).
    // The losing active entry's full content is preserved in the tombstone's lostVersions
    // AND its last password goes into passwordHistory. Recorded as 'delete-wins' conflict.
    if (localIsSoft && remoteIsActive) {
      // D-05: local soft tombstone wins; remote active content is the loser
      const loserSnapshot = snapshotOf(remoteEntry, ctx.remoteDeviceId);
      const loserHistoryItem: PasswordHistoryItem = {
        password: remoteEntry.password,
        changedAt: remoteEntry.modifiedAt,
      };
      const unitedHistory = unionHistory(
        localEntry.passwordHistory,
        [loserHistoryItem, ...remoteEntry.passwordHistory],
      );
      const existingLost = localEntry.lostVersions ?? [];
      const updatedLost = capLostVersions(existingLost, loserSnapshot);
      const mergedEntry: Entry = {
        ...deepCopyEntry(localEntry),
        passwordHistory: unitedHistory,
        lostVersions: updatedLost,
      };
      mergedEntries.push(mergedEntry);
      conflicts.push({
        entryId: id,
        loserSnapshot,
        winnerSnapshot: snapshotOf(localEntry, ctx.localDeviceId),
        winnerModifiedAtMs: localModifiedMs.get(id)!,
        loserModifiedAtMs: remoteModifiedMs.get(id)!,
        winnerDeviceId: ctx.localDeviceId,
        loserDeviceId: ctx.remoteDeviceId,
        reason: 'delete-wins',
      });
      counts.unchanged++; // local already had the tombstone; from local's view, no new deletion
      continue;
    }

    if (remoteIsSoft && localIsActive) {
      // D-05: remote soft tombstone wins; local active content is the loser
      const loserSnapshot = snapshotOf(localEntry, ctx.localDeviceId);
      const loserHistoryItem: PasswordHistoryItem = {
        password: localEntry.password,
        changedAt: localEntry.modifiedAt,
      };
      const unitedHistory = unionHistory(
        remoteEntry.passwordHistory,
        [loserHistoryItem, ...localEntry.passwordHistory],
      );
      const existingLost = remoteEntry.lostVersions ?? [];
      const updatedLost = capLostVersions(existingLost, loserSnapshot);
      const mergedEntry: Entry = {
        ...deepCopyEntry(remoteEntry),
        passwordHistory: unitedHistory,
        lostVersions: updatedLost,
      };
      mergedEntries.push(mergedEntry);
      conflicts.push({
        entryId: id,
        loserSnapshot,
        winnerSnapshot: snapshotOf(remoteEntry, ctx.remoteDeviceId),
        winnerModifiedAtMs: remoteModifiedMs.get(id)!,
        loserModifiedAtMs: localModifiedMs.get(id)!,
        winnerDeviceId: ctx.remoteDeviceId,
        loserDeviceId: ctx.localDeviceId,
        reason: 'delete-wins',
      });
      counts.deleted++; // this device's active entry is now tombstoned
      continue;
    }

    // --- Case 3: Both active — LWW on modifiedAt epoch-ms (D-01/MERGE-02). ---
    const localMs = localModifiedMs.get(id)!;
    const remoteMs = remoteModifiedMs.get(id)!;

    if (localMs > remoteMs) {
      // Local newer wins; remote is the loser (D-01).
      const loserSnapshot = snapshotOf(remoteEntry, ctx.remoteDeviceId);
      const loserHistoryItem: PasswordHistoryItem = {
        password: remoteEntry.password,
        changedAt: remoteEntry.modifiedAt,
      };
      const unitedHistory = unionHistory(
        localEntry.passwordHistory,
        [loserHistoryItem, ...remoteEntry.passwordHistory],
      );
      const existingLost = localEntry.lostVersions ?? [];
      const updatedLost = capLostVersions(existingLost, loserSnapshot);
      const mergedEntry: Entry = {
        ...deepCopyEntry(localEntry),
        passwordHistory: unitedHistory,
        lostVersions: updatedLost,
      };
      mergedEntries.push(mergedEntry);
      // D-15: record an lww-overwrite conflict whenever the loser held distinct
      // meaningful content (any of password/username/url/notes/title/tags) — the
      // conflicts[] seam must record every provably-lossy overwrite, not just creds.
      if (meaningfulContentDiffers(localEntry, remoteEntry)) {
        conflicts.push({
          entryId: id,
          loserSnapshot,
          winnerSnapshot: snapshotOf(localEntry, ctx.localDeviceId),
          winnerModifiedAtMs: localMs,
          loserModifiedAtMs: remoteMs,
          winnerDeviceId: ctx.localDeviceId,
          loserDeviceId: ctx.remoteDeviceId,
          reason: 'lww-overwrite',
        });
      }
      counts.unchanged++; // local version was kept
      continue;
    }

    if (remoteMs > localMs) {
      // Remote newer wins; local is the loser (D-01).
      const loserSnapshot = snapshotOf(localEntry, ctx.localDeviceId);
      const loserHistoryItem: PasswordHistoryItem = {
        password: localEntry.password,
        changedAt: localEntry.modifiedAt,
      };
      const unitedHistory = unionHistory(
        remoteEntry.passwordHistory,
        [loserHistoryItem, ...localEntry.passwordHistory],
      );
      const existingLost = remoteEntry.lostVersions ?? [];
      const updatedLost = capLostVersions(existingLost, loserSnapshot);
      const mergedEntry: Entry = {
        ...deepCopyEntry(remoteEntry),
        passwordHistory: unitedHistory,
        lostVersions: updatedLost,
      };
      mergedEntries.push(mergedEntry);
      // D-15: record an lww-overwrite conflict whenever the loser held distinct
      // meaningful content (any of password/username/url/notes/title/tags).
      if (meaningfulContentDiffers(localEntry, remoteEntry)) {
        conflicts.push({
          entryId: id,
          loserSnapshot,
          winnerSnapshot: snapshotOf(remoteEntry, ctx.remoteDeviceId),
          winnerModifiedAtMs: remoteMs,
          loserModifiedAtMs: localMs,
          winnerDeviceId: ctx.remoteDeviceId,
          loserDeviceId: ctx.localDeviceId,
          reason: 'lww-overwrite',
        });
      }
      counts.updated++; // local version was replaced by remote
      continue;
    }

    // --- modifiedAt equal: content-identity shortcut first (D-14 / D-18 idempotency). ---
    // If both sides have identical content (all fields), treat as unchanged regardless of
    // deviceIds. This is required for merge(A, A, ctx) to be a no-op (D-18 idempotency).
    if (contentEqual(localEntry, remoteEntry)) {
      // D-14: identical content → unchanged; union history as a no-op (dedup removes dups)
      const unitedHistory = unionHistory(
        localEntry.passwordHistory,
        remoteEntry.passwordHistory,
      );
      const mergedEntry: Entry = {
        ...deepCopyEntry(localEntry),
        passwordHistory: unitedHistory,
      };
      mergedEntries.push(mergedEntry);
      counts.unchanged++;
      continue;
    }

    // --- modifiedAt equal but content differs: deterministic tiebreak (D-13/D-14). ---
    // Lexicographically-greater deviceId wins; on EQUAL deviceIds, greater canonical
    // content wins (D-18 determinism — never positional `local`). The loser's full
    // content is preserved as a snapshot + its password into history (D-01) so no
    // credential is silently lost even in the equal-deviceId edge.
    {
      const localWins = localWinsTiebreak(localEntry, remoteEntry, ctx);
      const winner = localWins ? localEntry : remoteEntry;
      const loser = localWins ? remoteEntry : localEntry;
      const winnerDeviceId = localWins ? ctx.localDeviceId : ctx.remoteDeviceId;
      const loserDeviceId = localWins ? ctx.remoteDeviceId : ctx.localDeviceId;

      if (meaningfulContentDiffers(winner, loser)) {
        const loserSnapshot = snapshotOf(loser, loserDeviceId);
        const loserHistoryItem: PasswordHistoryItem = {
          password: loser.password,
          changedAt: loser.modifiedAt,
        };
        const unitedHistory = unionHistory(winner.passwordHistory, [
          loserHistoryItem,
          ...loser.passwordHistory,
        ]);
        const updatedLost = capLostVersions(winner.lostVersions ?? [], loserSnapshot);
        mergedEntries.push({
          ...deepCopyEntry(winner),
          passwordHistory: unitedHistory,
          lostVersions: updatedLost,
        });
        conflicts.push({
          entryId: id,
          loserSnapshot,
          winnerSnapshot: snapshotOf(winner, winnerDeviceId),
          winnerModifiedAtMs: localMs,
          loserModifiedAtMs: remoteMs, // equal to localMs in this branch
          winnerDeviceId,
          loserDeviceId,
          reason: 'tiebreak',
        });
      } else {
        // Differs only on non-meaningful fields (flags / history ordering) — pick the
        // deterministic winner and union history; nothing recoverable to preserve.
        const unitedHistory = unionHistory(winner.passwordHistory, loser.passwordHistory);
        mergedEntries.push({
          ...deepCopyEntry(winner),
          passwordHistory: unitedHistory,
        });
      }
      // D-16: if local won → unchanged; if remote won → updated.
      if (localWins) counts.unchanged++;
      else counts.updated++;
    }
  }

  // -------------------------------------------------------------------------
  // Deterministic output: sort entries by id, sort conflicts by entryId (D-18).
  // -------------------------------------------------------------------------
  mergedEntries.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  conflicts.sort((a, b) =>
    a.entryId < b.entryId ? -1 : a.entryId > b.entryId ? 1 : 0,
  );

  // -------------------------------------------------------------------------
  // Build merged InnerDoc: D-04 settings = local.settings; schemaVersion from local.
  // -------------------------------------------------------------------------
  const merged: InnerDoc = {
    schemaVersion: local.schemaVersion,
    entries: mergedEntries,
    settings: local.settings, // D-04: local settings win
  };

  return { merged, counts, conflicts };
}
