// packages/core/src/sync/__tests__/property.test.ts
//
// RED property-based test suite for Phase 8 (08-02).
// Proves COMMUTATIVITY and IDEMPOTENCY of mergeInnerDocs for arbitrary vault pairs.
//
// EXPECTED STATE: ALL properties in this file are RED. mergeInnerDocs throws
// new Error('not implemented') (08-01 stub). The properties fail at the stub.
// This is the INTENDED state of plan 08-02.
// Plan 08-03 turns this suite GREEN by implementing the merge engine.
//
// Requirements covered (RED gate):
//   D-18 / MERGE-08 — Property-based convergence proof:
//     Property 1: Commutativity — merge(A,B) and merge(B,A) yield same entry-id set.
//     Property 2: Idempotency   — merge(A,A) yields counts all 0; second merge a no-op.
//
// RUNTIME BUDGET: Unlike the vault property suite (which pays ~2 Argon2id derivations
// per run and must use numRuns:4), the merge engine is PURE TYPESCRIPT — no WASM, no
// Argon2id, no sodium. Each run is a lightweight in-memory object transformation.
// numRuns: 200 is safe and exercises the merge logic thoroughly without the
// Argon2id tax. (Mirror: vault/__tests__/property.test.ts lines 11-32 explains the
// Argon2id budget constraint; this suite is exempt from it.)
//
// Replay a failing seed with:
//   fc.assert(property, { seed: N })  — fast-check prints the seed on failure.
//
// Conventions:
//   - SYNC fc.property, NOT fc.asyncProperty (merge is pure TS — no await needed).
//   - Fixed EQUAL-CLOCK ctx (localNowMs === remoteNowMs) so the clock-skew guard
//     never trips inside these properties. Clock-skew boundary tests live in merge.test.ts.
//   - No Date.now(), no Math.random() anywhere in this file (CLAUDE.md).
//   - fc.date().map(d => d.toISOString()) avoids Date.parse NaN on arbitrary timestamps.
//   - fc.uuid() for entry ids to prevent accidental id collisions.
//   - lostVersions is added via .map() rather than fc.constant to satisfy
//     exactOptionalPropertyTypes: the field must be absent OR EntrySnapshot[], not undefined.

import { describe, it } from 'vitest';
import fc from 'fast-check';
import type { InnerDoc, Entry, PasswordHistoryItem } from '../../entries/types';
import type { MergeContext, EntrySnapshot } from '../types';
import { DEFAULT_RANDOM_OPTIONS } from '../../generator/types';
import { mergeInnerDocs } from '../merge';

// ---------------------------------------------------------------------------
// Helper: test if two Sets are equal (same elements, ignoring order)
// ---------------------------------------------------------------------------

function setsEqual<T>(a: Set<T>, b: Set<T>): boolean {
  if (a.size !== b.size) return false;
  for (const item of a) {
    if (!b.has(item)) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Fixed merge context (EQUAL clocks — skew guard intentionally not exercised here)
// ---------------------------------------------------------------------------

// Both localNowMs and remoteNowMs are identical → |Δ| = 0 → MERGE_CLOCK_SKEW never fires.
const PROPERTY_FIXED_NOW_MS = 1_735_689_600_000; // 2025-01-01T00:00:00.000Z

function makePropertyCtx(overrides?: Partial<MergeContext>): MergeContext {
  return {
    localDeviceId: 'property-device-A',
    remoteDeviceId: 'property-device-B',
    localNowMs: PROPERTY_FIXED_NOW_MS,
    remoteNowMs: PROPERTY_FIXED_NOW_MS, // EQUAL — clock-skew guard never fires
    ...overrides,
  };
}

function makeSwappedCtx(ctx: MergeContext): MergeContext {
  return {
    localDeviceId: ctx.remoteDeviceId,
    remoteDeviceId: ctx.localDeviceId,
    localNowMs: ctx.remoteNowMs,
    remoteNowMs: ctx.localNowMs,
  };
}

// ---------------------------------------------------------------------------
// Arbitraries
// ---------------------------------------------------------------------------

// PasswordHistoryItem arbitrary (RESEARCH §Property-Based Test Suite sketch)
// NOTE: noInvalidDate: true is required — fc.date() without it can generate an intentional
// NaN date (fast-check 4.8.0 feature for testing NaN handling) which causes .toISOString()
// to throw "Invalid time value" and crash the property runner before the merge code runs.
// The test comment says "avoids Date.parse NaN" which is the intent; noInvalidDate enforces it.
const historyItemArb: fc.Arbitrary<PasswordHistoryItem> = fc.record({
  password: fc.string({ minLength: 1, maxLength: 32 }),
  changedAt: fc
    .date({ min: new Date('2020-01-01'), max: new Date('2026-01-01'), noInvalidDate: true })
    .map((d) => d.toISOString()),
});

// Base entry shape WITHOUT lostVersions — required to satisfy exactOptionalPropertyTypes.
// With exactOptionalPropertyTypes: true, an optional field must be ABSENT (not undefined).
// So we build the base record without lostVersions and add it as a concrete [] via .map().
type BaseEntry = Omit<Entry, 'lostVersions'>;

const baseEntryArb: fc.Arbitrary<BaseEntry> = fc.record({
  id: fc.uuid(),
  type: fc.constant('login' as const),
  title: fc.string({ minLength: 1, maxLength: 32 }),
  username: fc.string({ minLength: 0, maxLength: 32 }),
  password: fc.string({ minLength: 0, maxLength: 64 }),
  url: fc.string({ minLength: 0, maxLength: 64 }),
  notes: fc.string({ minLength: 0, maxLength: 128 }),
  tags: fc.array(fc.string({ minLength: 1, maxLength: 16 }), { maxLength: 4 }),
  favorite: fc.boolean(),
  needsSiteUpdate: fc.boolean(),
  generatorPreset: fc.constant(null),
  passwordHistory: fc.array(historyItemArb, { maxLength: 10 }),
  createdAt: fc
    .date({ min: new Date('2020-01-01'), max: new Date('2025-01-01'), noInvalidDate: true })
    .map((d) => d.toISOString()),
  modifiedAt: fc
    .date({ min: new Date('2025-01-01'), max: new Date('2026-06-01'), noInvalidDate: true })
    .map((d) => d.toISOString()),
  deletedAt: fc.option(
    fc
      .date({ min: new Date('2025-01-01'), max: new Date('2026-06-01'), noInvalidDate: true })
      .map((d) => d.toISOString()),
    { nil: null },
  ),
});

// Full Entry arbitrary: spread the base + add concrete lostVersions: [] (not undefined).
// EntrySnapshot[] satisfies exactOptionalPropertyTypes (the field is present with a value).
const entryArb: fc.Arbitrary<Entry> = baseEntryArb.map((base) => ({
  ...base,
  lostVersions: [] as EntrySnapshot[],
}));

// InnerDoc arbitrary — schemaVersion fixed at 2; entries array up to 8.
const innerDocArb: fc.Arbitrary<InnerDoc> = fc.record({
  schemaVersion: fc.constant(2 as const),
  entries: fc.array(entryArb, { maxLength: 8 }),
  settings: fc.constant({ generator: DEFAULT_RANDOM_OPTIONS }),
});

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

describe('sync/property — commutativity + idempotency (D-18/MERGE-08)', () => {
  // -------------------------------------------------------------------------
  // Property 1: Commutativity (entry-set) — D-18 / MERGE-08
  //
  // For arbitrary InnerDoc pairs (A, B) with a fixed equal-clock ctx:
  //   mergeInnerDocs(A, B, ctx).merged.entries IDs
  //   === mergeInnerDocs(B, A, swappedCtx).merged.entries IDs
  //
  // swappedCtx models Device B's perspective: localDeviceId ↔ remoteDeviceId.
  // The entry-ID SETS must be identical — both PCs converge to the same vault
  // (D-18, core invariant: "a credential must never be silently lost").
  //
  // If this property fails, fast-check prints a reproducing seed.
  // Replay with: fc.assert(prop, { seed: N })
  // -------------------------------------------------------------------------
  it('Property 1: commutativity — merge(A,B) and merge(B,A) yield the same entry-id set', () => {
    const ctx = makePropertyCtx();
    const swappedCtx = makeSwappedCtx(ctx);

    fc.assert(
      fc.property(innerDocArb, innerDocArb, (docA, docB) => {
        const resultAB = mergeInnerDocs(docA, docB, ctx);
        const resultBA = mergeInnerDocs(docB, docA, swappedCtx);

        const idsAB = new Set(resultAB.merged.entries.map((e) => e.id));
        const idsBA = new Set(resultBA.merged.entries.map((e) => e.id));

        // Both PCs must converge to the same entry-id set (D-18 commutativity)
        return setsEqual(idsAB, idsBA);
      }),
      // numRuns: 200 — safe because the merge engine is pure TS, no Argon2id tax.
      // (Contrast: vault/property.test.ts uses numRuns:4 due to ~2s Argon2id per run.)
      { numRuns: 200 },
    );
  });

  // -------------------------------------------------------------------------
  // Property 2: Idempotency — D-18 / MERGE-08
  //
  // For arbitrary InnerDoc A, mergeInnerDocs(A, A, ctx) must yield:
  //   counts.updated === 0 && counts.added === 0 && counts.deleted === 0
  //   AND the merged entry-id set equals A's entry-id set.
  //
  // A second merge of the result against itself also changes nothing (re-merge
  // is a no-op), proving the convergence invariant: a second "Sync Now" does
  // nothing after both PCs have merged.
  //
  // If this property fails, fast-check prints a reproducing seed.
  // Replay with: fc.assert(prop, { seed: N })
  // -------------------------------------------------------------------------
  it('Property 2: idempotency — merge(A,A) yields all-zero change counts; re-merge is a no-op', () => {
    const ctx = makePropertyCtx();

    fc.assert(
      fc.property(innerDocArb, (docA) => {
        // First merge: A with itself
        const result1 = mergeInnerDocs(docA, docA, ctx);

        // D-16: all change counts must be zero — nothing should change when both sides
        // are identical (idempotency). Only `unchanged` may be non-zero.
        if (result1.counts.updated !== 0) return false;
        if (result1.counts.added !== 0) return false;
        if (result1.counts.deleted !== 0) return false;

        // Entry-id set must equal A's original set
        const originalIds = new Set(docA.entries.map((e) => e.id));
        const mergedIds = new Set(result1.merged.entries.map((e) => e.id));
        if (!setsEqual(originalIds, mergedIds)) return false;

        // Second merge: the result with itself must also be a no-op (re-merge is no-op)
        const result2 = mergeInnerDocs(result1.merged, result1.merged, ctx);

        if (result2.counts.updated !== 0) return false;
        if (result2.counts.added !== 0) return false;
        if (result2.counts.deleted !== 0) return false;

        return true;
      }),
      // numRuns: 200 — pure TS, no Argon2id tax.
      { numRuns: 200 },
    );
  });
});
