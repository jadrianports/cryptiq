// packages/core/src/sync/__tests__/syncRemerge.test.ts
//
// D-05 B-side re-merge idempotency coverage (Plan 11-01, Task 2).
//
// Requirements covered:
//   D-05/D-18 — B's re-merge mergeInnerDocs(X, X, ctx) on an idle vault is a provable
//               no-op: counts.updated == 0, counts.conflicts == 0.
//   D-05 (B local edits survive) — when B's current doc has a newer edit than the
//               received merged doc, the re-merge keeps B's newer entry (no data loss).
//
// Context (from 11-CONTEXT.md D-05 and 11-RESEARCH.md Pattern 5):
//   B runs mergeInnerDocs(B_current, received_merged, ctx) before saving.
//   When B is idle: received_merged == B_current (same content) → no-op by Phase-8
//   idempotency (D-18). Both localNowMs and remoteNowMs are B's own clock (the received
//   doc was produced by A; B has no "A's clock" available at re-merge time). The skew
//   check |localNowMs - remoteNowMs| == 0 → always passes.
//
// No crypto in these tests — mergeInnerDocs is a pure TS function (no libsodium calls).
// Uses fixed epoch constants per CLAUDE.md convention (no Date.now() in test bodies).

import { describe, it, expect } from 'vitest';
import type { InnerDoc, Entry } from '../../entries/types';
import type { MergeContext } from '../types';
import { DEFAULT_RANDOM_OPTIONS } from '../../generator/types';
import { mergeInnerDocs } from '../merge';

// ---------------------------------------------------------------------------
// Fixed epoch constants (never Date.now() in test bodies — CLAUDE.md)
// ---------------------------------------------------------------------------

// A fixed reference epoch: 2026-01-01T00:00:00.000Z in ms
const EPOCH_BASE = 1_767_225_600_000;
// 1 hour later — used for "B has a newer local edit"
const EPOCH_PLUS_1H = EPOCH_BASE + 3_600_000;
// B's wall-clock for the re-merge (both local and remote timestamps come from B's clock)
const B_CLOCK_NOW = EPOCH_BASE + 7_200_000;

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

/** Build a valid InnerDoc (schemaVersion 2). */
function makeInnerDoc(overrides?: Partial<InnerDoc>): InnerDoc {
  return {
    schemaVersion: 2,
    entries: [],
    settings: { generator: DEFAULT_RANDOM_OPTIONS },
    ...overrides,
  };
}

/** Build a full valid active Entry with all required fields. */
function makeEntry(overrides?: Partial<Entry>): Entry {
  return {
    id: 'b-remerge-entry-001',
    type: 'login',
    title: 'B Re-Merge Test Entry',
    username: 'b@example.com',
    password: 'b-original-password',
    url: 'https://b-example.com',
    notes: '',
    tags: [],
    favorite: false,
    needsSiteUpdate: false,
    generatorPreset: null,
    passwordHistory: [],
    lostVersions: [],
    createdAt: new Date(EPOCH_BASE).toISOString(),
    modifiedAt: new Date(EPOCH_BASE).toISOString(),
    deletedAt: null,
    ...overrides,
  };
}

/**
 * B's re-merge MergeContext: both timestamps come from B's own clock (D-05/Pattern 5).
 * The skew check |localNowMs - remoteNowMs| == 0 — always a no-op.
 */
function makeBCtx(overrides?: Partial<MergeContext>): MergeContext {
  return {
    localDeviceId: 'B',
    remoteDeviceId: 'A',
    localNowMs: B_CLOCK_NOW,
    remoteNowMs: B_CLOCK_NOW,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// describe('B-side re-merge (D-05)')
// ---------------------------------------------------------------------------

describe('B-side re-merge (D-05)', () => {
  it('D-05/D-18 remerge-idempotent: mergeInnerDocs(X, X, ctx) is a no-op when B is idle', () => {
    // Arrange: B's current doc and the received merged doc are identical (B was idle)
    const bCurrentDoc = makeInnerDoc({
      entries: [
        makeEntry({
          id: 'idle-entry-001',
          title: 'Idle Vault Entry',
          password: 'idle-password',
          modifiedAt: new Date(EPOCH_BASE).toISOString(),
        }),
      ],
    });

    // Act: B re-merges with itself (received_merged == b_current → no-op case)
    const result = mergeInnerDocs(bCurrentDoc, bCurrentDoc, makeBCtx());

    // Assert: D-05/D-18 no-op on idle — zero updates, zero conflicts records
    expect(result.counts.updated).toBe(0);
    // The conflicts array must be empty (no lossy decisions)
    expect(result.conflicts).toHaveLength(0);
    // unchanged count covers the existing entry
    expect(result.counts.unchanged).toBeGreaterThanOrEqual(1);
    // No new entries added (B_current == received_merged → no new IDs)
    expect(result.counts.added).toBe(0);
    // No deletions (B_current == received_merged → no tombstones)
    expect(result.counts.deleted).toBe(0);

    // The merged doc has the same number of entries as the input
    expect(result.merged.entries).toHaveLength(bCurrentDoc.entries.length);
  });

  it('D-05/D-18 remerge-idempotent: empty vault re-merge is a no-op', () => {
    // Edge case: B and received doc both have zero entries
    const emptyDoc = makeInnerDoc({ entries: [] });

    const result = mergeInnerDocs(emptyDoc, emptyDoc, makeBCtx());

    expect(result.counts.updated).toBe(0);
    expect(result.conflicts).toHaveLength(0);
    expect(result.counts.added).toBe(0);
    expect(result.counts.deleted).toBe(0);
    expect(result.merged.entries).toHaveLength(0);
  });

  it('D-05 B local edits survive when they are newer (no data loss)', () => {
    // Arrange: A's merged doc has an entry at EPOCH_BASE.
    // B has the same entry but B updated it locally (EPOCH_PLUS_1H — newer).
    // B's version should WIN because it is more recent.
    const entryId = 'b-local-edit-entry-001';

    const receivedMergedDoc = makeInnerDoc({
      entries: [
        makeEntry({
          id: entryId,
          password: 'a-merged-password',
          modifiedAt: new Date(EPOCH_BASE).toISOString(),
        }),
      ],
    });

    const bCurrentDoc = makeInnerDoc({
      entries: [
        makeEntry({
          id: entryId,
          password: 'b-newer-local-password',
          modifiedAt: new Date(EPOCH_PLUS_1H).toISOString(), // B edited AFTER A's merge
        }),
      ],
    });

    // Act: B re-merges local (newer) vs received merged (older)
    const result = mergeInnerDocs(bCurrentDoc, receivedMergedDoc, makeBCtx());

    // Assert: B's newer entry survives (no data loss on B)
    const merged = result.merged.entries.find((e) => e.id === entryId);
    expect(merged).toBeDefined();
    expect(merged!.password).toBe('b-newer-local-password');

    // B's version won → from B's perspective this entry is "unchanged" (local won)
    // OR updated = 0 because the remote was older (LWW: B wins, remote=loser)
    // Either way: B's data is not lost
    expect(result.counts.updated).toBe(0); // B kept its own entry → no update from B's POV
  });

  it('D-05 convergence: B-idle + multiple entries all survive', () => {
    // Arrange: three entries, B and received_merged are identical
    const doc = makeInnerDoc({
      entries: [
        makeEntry({ id: 'multi-001', title: 'Entry 1' }),
        makeEntry({ id: 'multi-002', title: 'Entry 2', modifiedAt: new Date(EPOCH_PLUS_1H).toISOString() }),
        makeEntry({ id: 'multi-003', title: 'Entry 3', deletedAt: new Date(EPOCH_BASE).toISOString(), modifiedAt: new Date(EPOCH_BASE).toISOString() }),
      ],
    });

    const result = mergeInnerDocs(doc, doc, makeBCtx());

    // All entries preserved (including tombstone)
    expect(result.merged.entries).toHaveLength(3);
    expect(result.counts.updated).toBe(0);
    expect(result.conflicts).toHaveLength(0);
  });
});
