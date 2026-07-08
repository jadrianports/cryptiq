// packages/core/src/sync/types.ts
//
// All merge/duplicate type contracts for Phase 8 (D-01..D-19).
// Pure type definitions — no logic except the single `isPermanentTombstone` predicate (D-06).
//
// Core purity: zero Tauri/Svelte/node:fs/node:path/libsodium imports.
// Only import: Entry + InnerDoc from ../entries/types (relative path).
//
// Source: CONTEXT.md D-06/D-11/D-12/D-14/D-15/D-16/D-17/D-19

import type { Entry, InnerDoc } from '../entries/types';

// ---------------------------------------------------------------------------
// Entry snapshot — loser-version preservation (D-01)
// ---------------------------------------------------------------------------

/**
 * Full content snapshot of a losing version overwritten during sync (D-01).
 *
 * Contains ALL recoverable fields — not just the password. Carries entry-level
 * plaintext only: free of the vault key and the master password. Bounded by the
 * `lostVersions` cap on `Entry` (capped at 5 newest — T-03-04 plaintext-surface
 * discipline). Lives either in `ConflictRecord` (in-memory for Phase 11 secureWipe)
 * or in `Entry.lostVersions` (persisted, survives sessions/devices — D-01/D-02).
 */
export interface EntrySnapshot {
  /** The password value at the time this version was overwritten. */
  password: string;
  /** Username at the time this version was overwritten. */
  username: string;
  /** URL at the time this version was overwritten. */
  url: string;
  /** Notes at the time this version was overwritten. */
  notes: string;
  /** Tags at the time this version was overwritten. */
  tags: string[];
  /** ISO 8601 `modifiedAt` timestamp of the losing version. */
  modifiedAt: string;
  /** Device ID that produced the losing version (opaque comparable string — D-14). */
  deviceId: string;
}

// ---------------------------------------------------------------------------
// Merge engine context (D-12/D-14)
// ---------------------------------------------------------------------------

/**
 * Injected context for `mergeInnerDocs` — the engine is pure; it never reads the
 * clock or device identity itself. Caller (Phase 11) fills these. (D-12/D-14)
 */
export interface MergeContext {
  /** This device's ID (opaque comparable string; Phase 9 fills the real value — D-14). */
  localDeviceId: string;
  /** Remote device's ID (opaque comparable string — D-14). */
  remoteDeviceId: string;
  /** Local wall-clock at merge time, epoch-ms (injected — engine never calls Date.now()). */
  localNowMs: number;
  /** Remote wall-clock at merge time, epoch-ms (received from remote during transport). */
  remoteNowMs: number;
}

// ---------------------------------------------------------------------------
// Conflict record — provably-lossy decisions (D-15)
// ---------------------------------------------------------------------------

/**
 * Reason code for a `ConflictRecord` — why the losing version lost (D-15).
 * `'lww-overwrite'` — last-write-wins timestamp comparison.
 * `'delete-wins'`   — soft tombstone beat a concurrent edit (D-05).
 * `'tiebreak'`      — identical `modifiedAt`; lexicographically-greater deviceId won (D-13).
 * Permanent-delete-final (D-07) and create-vs-create (D-08) are NOT conflicts.
 */
export type ConflictReason = 'lww-overwrite' | 'delete-wins' | 'tiebreak';

/**
 * Frozen record of a provably-lossy merge decision (D-15).
 *
 * Populated but unused in v2.0; forward-compat seam for the Sync Autopilot resolver.
 * Never contains the vault key or the master password — only entry-level content.
 */
export interface ConflictRecord {
  /** ID of the entry that was the conflict site. */
  entryId: string;
  /** Full content of the LOSING version at merge time. */
  loserSnapshot: EntrySnapshot;
  /** Full content of the WINNING version at merge time. */
  winnerSnapshot: EntrySnapshot;
  /** `modifiedAt` of the winning version, epoch-ms. */
  winnerModifiedAtMs: number;
  /** `modifiedAt` of the losing version, epoch-ms. */
  loserModifiedAtMs: number;
  /** Device that produced the winning version. */
  winnerDeviceId: string;
  /** Device that produced the losing version. */
  loserDeviceId: string;
  /** Why this version was treated as a conflict (D-15 frozen reason set). */
  reason: ConflictReason;
}

// ---------------------------------------------------------------------------
// Merge counts — per-device (D-16)
// ---------------------------------------------------------------------------

/**
 * Per-device counts describing what this sync did to THIS device's vault (D-16).
 * The two peers may legitimately show different numbers. Consumed by Phase 12 UI-18.
 */
export interface MergeCounts {
  /** Entries present on remote but not local — new to this device. */
  added: number;
  /** Entries where this device's version was replaced by the remote's. */
  updated: number;
  /** Entries newly tombstoned on this device as a result of merge. */
  deleted: number;
  /** Entries unchanged on this device. */
  unchanged: number;
}

// ---------------------------------------------------------------------------
// Merge result — engine return value (D-11)
// ---------------------------------------------------------------------------

/**
 * Return value of `mergeInnerDocs` (D-11).
 *
 * `merged` is the plaintext merged `InnerDoc`; the caller (Phase 11) owns its
 * lifecycle and MUST `secureWipe` the key after re-encryption — mirrors the v1
 * `UnlockedVault` caller-owns contract. The pure engine never logs, persists,
 * or wipes the plaintext.
 */
export interface MergeResult {
  /**
   * The merged InnerDoc in plaintext.
   * Caller (Phase 11) must secureWipe after re-encryption (D-11).
   */
  merged: InnerDoc;
  /** Per-device counts for the UI counts summary (D-16). */
  counts: MergeCounts;
  /**
   * Provably-lossy conflict records (D-15).
   * Populated in v2.0 but not consumed until Sync Autopilot (forward-compat seam).
   */
  conflicts: ConflictRecord[];
}

// ---------------------------------------------------------------------------
// Possible duplicate hint (D-19)
// ---------------------------------------------------------------------------

/**
 * Advisory duplicate hint returned by `findPossibleDuplicates` (D-19).
 *
 * Groups active entries sharing a normalized (lowercased) `title` + `url`.
 * Advisory only — no auto-merge; keep-both (MERGE-03) remains the merge rule.
 * Phase 12 renders the hint; the engine never coalesces duplicates.
 */
export interface PossibleDuplicate {
  /** Normalized title shared by the group. */
  title: string;
  /** Normalized URL shared by the group. */
  url: string;
  /** Active entries in the group (length >= 2). */
  entries: Entry[];
}

// ---------------------------------------------------------------------------
// Permanent tombstone marker (D-06)
// ---------------------------------------------------------------------------

/**
 * Canonical shape of a permanently-deleted entry after content-wipe (D-06).
 *
 * Permanent Delete collapses an entry to this secret-free marker: secret content
 * (`password`, `username`, `notes`, `passwordHistory`, `lostVersions`) is wiped,
 * but the minimal marker is retained forever to prevent resurrection (D-07).
 *
 * Phase 8 RECOGNIZES this shape (see `isPermanentTombstone`); the actual wipe
 * (`purgeEntry` content-wipe instead of row-splice) lands in Phase 11/12.
 */
export interface PermanentTombstoneMarker {
  /** Entry ID (immutable, never erased). */
  id: string;
  /** Always `'login'` in v1. */
  type: 'login';
  /** ISO 8601 timestamp of the permanent deletion. */
  deletedAt: string;
  /** ISO 8601 last-modified time (set to the wipe time). */
  modifiedAt: string;
}

// ---------------------------------------------------------------------------
// isPermanentTombstone — D-06 recognition predicate
// ---------------------------------------------------------------------------

/**
 * Returns `true` when `entry` matches the D-06 permanent-tombstone heuristic:
 * `deletedAt` is set AND all secret content fields are empty/wiped.
 *
 * This is the SINGLE source of the D-06 recognition rule — used by `merge.ts` to
 * honour D-07 (permanent delete wins everywhere; peer content NOT preserved).
 * Pure function — no IO, no imports beyond the `Entry` type.
 *
 * Recognition (D-06): `deletedAt` is set AND the entry has collapsed to the
 * secret-free `PermanentTombstoneMarker` shape — EVERY content field is empty
 * (`password`/`username`/`notes`/`url`/`title` empty, `tags`/`passwordHistory`/
 * `lostVersions` empty, and the Phase-21 v3 fields `email`/`equivalentUrls`/`card`/
 * `identity` all absent-or-empty). This must be STRICT: a content-sparse SOFT delete
 * (e.g. a url-only bookmark a user soft-deletes, which has empty password/username/notes
 * but a non-empty title/url) must NOT be read as permanent — otherwise D-07's sanctioned
 * loss fires on an ordinary soft delete and silently destroys a peer's live edit.
 * Anything short of the full empty-marker shape is treated as SOFT (fail-safe: prefer
 * preserving the peer over destroying it). Phase 11/12 will replace this with an
 * explicit marker field once `purgeEntry` wipes in place.
 *
 * Phase 22 (D-06 field-parity): a `card`/`identity` entry is content-RICH in the new
 * v3 fields even when every login field is empty (a card's title/username/password/url
 * are all naturally blank). Without these clauses such an entry would misclassify as a
 * permanent marker and D-07 would silently destroy the peer's live copy — the exact
 * failure this predicate exists to prevent, reintroduced by the widened Entry shape.
 * Must move in lockstep with the merge.ts field-parity sites.
 *
 * Phase 28 (TOTP-07/T-28-02): a live `totp` seed is likewise content-RICH — a deleted
 * entry whose login fields are all empty BUT which still carries a 2FA seed must NOT be
 * read as permanent, or D-07's sanctioned "peer content NOT preserved" exception would
 * silently destroy a peer's still-live TOTP secret. `totp === undefined` joins the AND-chain.
 */
export function isPermanentTombstone(entry: Entry): boolean {
  return (
    entry.deletedAt !== null &&
    entry.password === '' &&
    entry.username === '' &&
    entry.notes === '' &&
    entry.url === '' &&
    entry.title === '' &&
    entry.tags.length === 0 &&
    entry.passwordHistory.length === 0 &&
    (entry.lostVersions === undefined || entry.lostVersions.length === 0) &&
    // Phase 21/22 v3 fields: absent-or-empty, else real content survives → SOFT.
    (entry.email === undefined || entry.email === '') &&
    (entry.equivalentUrls === undefined || entry.equivalentUrls.length === 0) &&
    entry.card === undefined &&
    entry.identity === undefined &&
    // Phase 28 (TOTP-07/T-28-02) v4 field: a live totp seed forces SOFT classification.
    entry.totp === undefined
  );
}
