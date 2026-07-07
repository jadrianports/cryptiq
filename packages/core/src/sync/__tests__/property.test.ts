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
import type { InnerDoc, Entry, EntryCard, EntryIdentity, PasswordHistoryItem } from '../../entries/types';
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
// v3 arbitraries (Phase 22, SYNCP-01) — extend the base entry with the four
// new optional fields (email/equivalentUrls/card/identity), each independently
// present-or-absent via fc.option. Key is OMITTED when absent (conditional
// spread), never assigned `undefined` (exactOptionalPropertyTypes), mirroring
// the existing lostVersions handling above.
// ---------------------------------------------------------------------------

const cardArb: fc.Arbitrary<EntryCard> = fc.record({
  cardholderName: fc.string({ minLength: 1, maxLength: 32 }),
  number: fc.string({ minLength: 1, maxLength: 20 }),
  expiryMonth: fc.string({ minLength: 2, maxLength: 2 }),
  expiryYear: fc.string({ minLength: 4, maxLength: 4 }),
  cvv: fc.string({ minLength: 3, maxLength: 4 }),
});

const identityArb: fc.Arbitrary<EntryIdentity> = fc.record({
  name: fc.string({ minLength: 1, maxLength: 32 }),
  email: fc.string({ minLength: 1, maxLength: 32 }),
  phone: fc.string({ minLength: 1, maxLength: 16 }),
  address: fc.string({ minLength: 1, maxLength: 64 }),
});

// Full v3 Entry arbitrary: base entry + concrete lostVersions: [] + conditionally
// present new fields.
const v3EntryArb: fc.Arbitrary<Entry> = fc
  .tuple(
    baseEntryArb,
    fc.option(fc.string({ minLength: 1, maxLength: 32 }), { nil: undefined }),
    fc.option(fc.array(fc.string({ minLength: 1, maxLength: 32 }), { maxLength: 3 }), {
      nil: undefined,
    }),
    fc.option(cardArb, { nil: undefined }),
    fc.option(identityArb, { nil: undefined }),
  )
  .map(([base, email, equivalentUrls, card, identity]) => ({
    ...base,
    lostVersions: [] as EntrySnapshot[],
    ...(email !== undefined ? { email } : {}),
    ...(equivalentUrls !== undefined ? { equivalentUrls } : {}),
    ...(card !== undefined ? { card } : {}),
    ...(identity !== undefined ? { identity } : {}),
  }));

// v3 InnerDoc arbitrary — schemaVersion fixed at 3; entries may populate the new fields.
const v3InnerDocArb: fc.Arbitrary<InnerDoc> = fc.record({
  schemaVersion: fc.constant(3 as const),
  entries: fc.array(v3EntryArb, { maxLength: 8 }),
  settings: fc.constant({ generator: DEFAULT_RANDOM_OPTIONS }),
});

/**
 * Compare the new-field content (email/equivalentUrls/card/identity) of two entries.
 * Strengthens commutativity/idempotency beyond id-set equality (Phase 22) — a
 * false-equal or dropped-field bug on these fields would NOT be caught by an
 * id-set-only comparison.
 */
function newFieldContentEqual(a: Entry, b: Entry): boolean {
  if (a.email !== b.email) return false;
  const au = a.equivalentUrls;
  const bu = b.equivalentUrls;
  if (au === undefined || bu === undefined) {
    if (au !== bu) return false;
  } else {
    if (au.length !== bu.length) return false;
    for (let i = 0; i < au.length; i++) {
      if (au[i] !== bu[i]) return false;
    }
  }
  if (JSON.stringify(a.card ?? null) !== JSON.stringify(b.card ?? null)) return false;
  if (JSON.stringify(a.identity ?? null) !== JSON.stringify(b.identity ?? null)) return false;
  return true;
}

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

// ---------------------------------------------------------------------------
// v3 field-parity properties (Phase 22, SYNCP-01)
//
// Strengthen commutativity + idempotency for v3 entries carrying the four new
// optional fields — the ORIGINAL Property 1/2 above only assert entry-id-set
// equality, which would NOT catch a dropped-field or false-equal bug on
// email/equivalentUrls/card/identity. These new properties add a per-entry
// new-field content equality assertion via newFieldContentEqual.
// ---------------------------------------------------------------------------

describe('sync/property — v3 field-parity (Phase 22, SYNCP-01)', () => {
  it('Property 2 (v3): merge(A,A) is a no-op AND preserves new-field content per entry', () => {
    const ctx = makePropertyCtx();

    fc.assert(
      fc.property(v3InnerDocArb, (docA) => {
        const result1 = mergeInnerDocs(docA, docA, ctx);

        if (result1.counts.updated !== 0) return false;
        if (result1.counts.added !== 0) return false;
        if (result1.counts.deleted !== 0) return false;

        const originalIds = new Set(docA.entries.map((e) => e.id));
        const mergedIds = new Set(result1.merged.entries.map((e) => e.id));
        if (!setsEqual(originalIds, mergedIds)) return false;

        // New-field content must be preserved (no silent drop / false-equal).
        for (const original of docA.entries) {
          const merged = result1.merged.entries.find((e) => e.id === original.id);
          if (merged === undefined) return false;
          if (!newFieldContentEqual(original, merged)) return false;
        }

        return true;
      }),
      { numRuns: 200 },
    );
  });

  it('Property 1 (v3): merge(A,B) === merge(B,A) — new-field content per entry, not just id-set', () => {
    const ctx = makePropertyCtx();
    const swappedCtx = makeSwappedCtx(ctx);

    fc.assert(
      fc.property(v3InnerDocArb, v3InnerDocArb, (docA, docB) => {
        const resultAB = mergeInnerDocs(docA, docB, ctx);
        const resultBA = mergeInnerDocs(docB, docA, swappedCtx);

        const idsAB = new Set(resultAB.merged.entries.map((e) => e.id));
        const idsBA = new Set(resultBA.merged.entries.map((e) => e.id));
        if (!setsEqual(idsAB, idsBA)) return false;

        // Strengthened: per shared id, new-field content must also match.
        const mapAB = new Map(resultAB.merged.entries.map((e) => [e.id, e]));
        const mapBA = new Map(resultBA.merged.entries.map((e) => [e.id, e]));
        for (const id of idsAB) {
          const eAB = mapAB.get(id)!;
          const eBA = mapBA.get(id)!;
          if (!newFieldContentEqual(eAB, eBA)) return false;
        }

        return true;
      }),
      { numRuns: 200 },
    );
  });
});
