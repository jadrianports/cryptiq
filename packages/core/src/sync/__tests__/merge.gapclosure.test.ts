// packages/core/src/sync/__tests__/merge.gapclosure.test.ts
//
// Phase 8 gap-closure regression suite — pins the silent-merge-bug class defects
// surfaced by the post-execution adversarial review (4-lens + adversarial verify).
//
// Each test below was RED against the original 08-03 implementation and is the
// permanent regression net for the fixes. They target the defects the original
// green suite was structurally blind to, because the property tests compared only
// entry-ID SETS (never CONTENT) and no example test exercised:
//   - both-soft-deleted with differing / equal deletedAt (silent loser-password loss + divergence)
//   - isPermanentTombstone misclassifying a content-sparse SOFT delete as permanent (D-07 fail-open)
//   - both-permanent divergence; equal-deviceId differing-content divergence
//   - D-17 shape validation; duplicate.ts key-sentinel collision
//
// Conventions match merge.test.ts: fixed epoch constants, no Date.now()/Math.random(),
// typed-error asserts via expect.objectContaining({ code }).

import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import type { InnerDoc, Entry } from '../../entries/types';
import type { MergeContext } from '../types';
import { isPermanentTombstone } from '../types';
import { DEFAULT_RANDOM_OPTIONS } from '../../generator/types';
import { mergeInnerDocs } from '../merge';
import { findPossibleDuplicates } from '../duplicate';

const EPOCH = 1_735_689_600_000; // 2025-01-01T00:00:00.000Z
const iso = (ms: number): string => new Date(ms).toISOString();

function makeCtx(overrides?: Partial<MergeContext>): MergeContext {
  return {
    localDeviceId: 'device-local',
    remoteDeviceId: 'device-remote',
    localNowMs: EPOCH,
    remoteNowMs: EPOCH,
    ...overrides,
  };
}

function makeInnerDoc(entries: Entry[]): InnerDoc {
  return { schemaVersion: 2, entries, settings: { generator: DEFAULT_RANDOM_OPTIONS } };
}

function makeEntry(overrides?: Partial<Entry>): Entry {
  return {
    id: 'entry-001',
    type: 'login',
    title: 'Title',
    username: 'user',
    password: 'pw',
    url: 'https://example.com',
    notes: '',
    tags: [],
    favorite: false,
    needsSiteUpdate: false,
    generatorPreset: null,
    passwordHistory: [],
    lostVersions: [],
    createdAt: iso(EPOCH),
    modifiedAt: iso(EPOCH),
    deletedAt: null,
    ...overrides,
  };
}

/** Every place the loser's plaintext password may legitimately survive. */
function recoverablePasswords(e: Entry): Set<string> {
  const out = new Set<string>([e.password]);
  for (const h of e.passwordHistory) out.add(h.password);
  for (const s of e.lostVersions ?? []) out.add(s.password);
  return out;
}

/** Stable canonical string of a merged vault's entries (id-sorted, all content fields). */
function canonEntries(doc: InnerDoc): string {
  return [...doc.entries]
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
    .map((e) =>
      JSON.stringify([
        e.id, e.type, e.title, e.username, e.password, e.url, e.notes,
        [...e.tags], e.favorite, e.needsSiteUpdate, e.createdAt, e.modifiedAt, e.deletedAt,
        e.passwordHistory.map((h) => [h.changedAt, h.password]),
        (e.lostVersions ?? []).map((s) => [s.modifiedAt, s.deviceId, s.password, s.username, s.url, s.notes, [...s.tags]]),
      ]),
    )
    .join('|');
}

const ID = 'shared-id';

// ---------------------------------------------------------------------------
// CRITICAL: both-soft-deleted silently drops the loser's live password
// ---------------------------------------------------------------------------

describe('gap: both-soft-deleted preserves the loser password (D-05/never-silently-lost)', () => {
  it('differing deletedAt: earlier wins, later side password is still recoverable', () => {
    const localT = makeEntry({ id: ID, password: 'pw-local-earlier', deletedAt: iso(EPOCH + 1000), modifiedAt: iso(EPOCH + 1000) });
    const remoteT = makeEntry({ id: ID, password: 'pw-remote-later', deletedAt: iso(EPOCH + 5000), modifiedAt: iso(EPOCH + 5000) });
    const result = mergeInnerDocs(makeInnerDoc([localT]), makeInnerDoc([remoteT]), makeCtx());
    const merged = result.merged.entries.find((e) => e.id === ID)!;
    expect(merged).toBeDefined();
    // both soft tombstones are restorable (D-05) → BOTH passwords must remain recoverable
    const rec = recoverablePasswords(merged);
    expect(rec.has('pw-local-earlier')).toBe(true);
    expect(rec.has('pw-remote-later')).toBe(true);
  });

  it('equal deletedAt + differing content: deterministic winner + loser preserved + convergent', () => {
    const a = makeEntry({ id: ID, title: 'A-TITLE', password: 'pw-A', deletedAt: iso(EPOCH + 2000), modifiedAt: iso(EPOCH + 2000) });
    const b = makeEntry({ id: ID, title: 'B-TITLE', password: 'pw-B', deletedAt: iso(EPOCH + 2000), modifiedAt: iso(EPOCH + 2000) });
    const ctx = makeCtx();
    const swapped = makeCtx({ localDeviceId: ctx.remoteDeviceId, remoteDeviceId: ctx.localDeviceId });
    const ab = mergeInnerDocs(makeInnerDoc([a]), makeInnerDoc([b]), ctx);
    const ba = mergeInnerDocs(makeInnerDoc([b]), makeInnerDoc([a]), swapped);
    // D-18: both devices converge to byte-identical content
    expect(canonEntries(ab.merged)).toBe(canonEntries(ba.merged));
    // neither password silently lost
    const rec = recoverablePasswords(ab.merged.entries.find((e) => e.id === ID)!);
    expect(rec.has('pw-A')).toBe(true);
    expect(rec.has('pw-B')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// CRITICAL: isPermanentTombstone must NOT misclassify a sparse SOFT delete
// ---------------------------------------------------------------------------

describe('gap: sparse soft delete is NOT permanent (D-06/D-07 fail-open)', () => {
  it('soft-deleted url-only entry vs live peer: peer live password is preserved, not destroyed', () => {
    // A bookmark-style entry (title+url, never had a password) that is SOFT-deleted.
    const sparseSoft = makeEntry({
      id: ID, title: 'Bank', url: 'https://bank.example', username: '', password: '', notes: '',
      passwordHistory: [], lostVersions: [], deletedAt: iso(EPOCH + 1000), modifiedAt: iso(EPOCH + 1000),
    });
    const livePeer = makeEntry({ id: ID, title: 'Bank', url: 'https://bank.example', password: 'PEER-LIVE-SECRET', modifiedAt: iso(EPOCH + 5000) });
    const result = mergeInnerDocs(makeInnerDoc([sparseSoft]), makeInnerDoc([livePeer]), makeCtx());
    const merged = result.merged.entries.find((e) => e.id === ID)!;
    // soft delete-wins (NOT permanent): tombstone survives BUT the peer's live secret is preserved
    expect(merged.deletedAt).not.toBeNull();
    expect(recoverablePasswords(merged).has('PEER-LIVE-SECRET')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// CRITICAL (Phase 22 gap): a v3 card/identity entry is content-RICH in the new
// fields (card/identity/email/equivalentUrls) even when every login field is
// empty. isPermanentTombstone (D-06) was never widened for those fields, so a
// soft-deleted, empty-title card reads as a permanent marker → D-07 silently
// destroys the peer's live entry with no snapshot and no conflict record.
// ---------------------------------------------------------------------------

describe('gap: v3 card/identity soft delete is NOT permanent (D-06 field-parity, Phase 22)', () => {
  it('isPermanentTombstone returns false when only the new v3 fields carry content', () => {
    // Login-sparse SOFT delete: title + every login field empty, deletedAt set.
    const base = makeEntry({
      title: '', username: '', password: '', url: '', notes: '',
      tags: [], passwordHistory: [], lostVersions: [],
      deletedAt: iso(EPOCH + 1000),
    });
    // control: the genuinely-collapsed marker (no v3 content) IS permanent.
    expect(isPermanentTombstone(base)).toBe(true);
    // but any populated v3 field means real content survives → NOT permanent.
    expect(
      isPermanentTombstone({
        ...base,
        card: { cardholderName: 'Jane', number: '4111111111111111', expiryMonth: '03', expiryYear: '2030', cvv: '123' },
      }),
    ).toBe(false);
    expect(
      isPermanentTombstone({ ...base, identity: { name: 'Jane', email: 'j@x.io', phone: '555', address: '1 St' } }),
    ).toBe(false);
    expect(isPermanentTombstone({ ...base, email: 'j@x.io' })).toBe(false);
    expect(isPermanentTombstone({ ...base, equivalentUrls: ['https://alt.example'] })).toBe(false);
  });

  it('soft-deleted empty-title card vs live peer: peer secret is preserved, not destroyed by D-07', () => {
    // Card entry whose login fields are all empty (natural for a card) with an
    // empty title, SOFT-deleted on this device — must NOT be read as permanent.
    const softCard = makeEntry({
      id: ID, type: 'card', title: '', username: '', password: '', url: '', notes: '',
      tags: [], passwordHistory: [], lostVersions: [],
      card: { cardholderName: 'Jane', number: '4111111111111111', expiryMonth: '03', expiryYear: '2030', cvv: '123' },
      deletedAt: iso(EPOCH + 1000), modifiedAt: iso(EPOCH + 1000),
    });
    // The peer holds a live (active) version of the same entry carrying a secret.
    const livePeer = makeEntry({
      id: ID, type: 'card', title: '', username: '', password: 'PEER-LIVE-SECRET', url: '', notes: '',
      modifiedAt: iso(EPOCH + 5000),
    });
    const result = mergeInnerDocs(makeInnerDoc([softCard]), makeInnerDoc([livePeer]), makeCtx());
    const merged = result.merged.entries.find((e) => e.id === ID)!;
    // Correctly SOFT → delete-wins WITH preservation; the peer's live secret survives.
    expect(recoverablePasswords(merged).has('PEER-LIVE-SECRET')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// HIGH: both-permanent must converge (no positional winner)
// ---------------------------------------------------------------------------

describe('gap: both-permanent tombstone converges across argument order (D-18)', () => {
  it('two permanent markers with differing deletedAt converge to identical content', () => {
    const permA = makeEntry({ id: ID, title: '', username: '', password: '', notes: '', url: '', tags: [], passwordHistory: [], lostVersions: [], deletedAt: iso(EPOCH + 1000), modifiedAt: iso(EPOCH + 1000) });
    const permB = makeEntry({ id: ID, title: '', username: '', password: '', notes: '', url: '', tags: [], passwordHistory: [], lostVersions: [], deletedAt: iso(EPOCH + 5000), modifiedAt: iso(EPOCH + 5000) });
    const ctx = makeCtx();
    const swapped = makeCtx({ localDeviceId: ctx.remoteDeviceId, remoteDeviceId: ctx.localDeviceId });
    const ab = mergeInnerDocs(makeInnerDoc([permA]), makeInnerDoc([permB]), ctx);
    const ba = mergeInnerDocs(makeInnerDoc([permB]), makeInnerDoc([permA]), swapped);
    expect(canonEntries(ab.merged)).toBe(canonEntries(ba.merged));
  });
});

// ---------------------------------------------------------------------------
// HIGH/MEDIUM: equal modifiedAt + equal deviceId + differing content
// ---------------------------------------------------------------------------

describe('gap: equal modifiedAt + equal deviceId + differing content (D-14 fallback)', () => {
  it('is deterministic and preserves the loser instead of silently keeping local', () => {
    const ctx = makeCtx({ localDeviceId: 'same-dev', remoteDeviceId: 'same-dev' });
    const a = makeEntry({ id: ID, password: 'pw-A', modifiedAt: iso(EPOCH) });
    const b = makeEntry({ id: ID, password: 'pw-B', modifiedAt: iso(EPOCH) });
    const ab = mergeInnerDocs(makeInnerDoc([a]), makeInnerDoc([b]), ctx);
    const ba = mergeInnerDocs(makeInnerDoc([b]), makeInnerDoc([a]), ctx);
    expect(canonEntries(ab.merged)).toBe(canonEntries(ba.merged));
    const rec = recoverablePasswords(ab.merged.entries.find((e) => e.id === ID)!);
    expect(rec.has('pw-A')).toBe(true);
    expect(rec.has('pw-B')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// MEDIUM: D-17 shape validation refuses a malformed remote entry (fail-closed)
// ---------------------------------------------------------------------------

describe('gap: D-17 validates required entry shape, not just id + modifiedAt', () => {
  it('a non-string scalar field throws MergeInvalidInputError (typed, before any merge)', () => {
    const bad = makeEntry({ id: ID, username: 42 as unknown as string });
    expect(() => mergeInnerDocs(makeInnerDoc([bad]), makeInnerDoc([]), makeCtx())).toThrow(
      expect.objectContaining({ code: 'MERGE_INVALID_INPUT' }),
    );
  });

  it('a non-array tags throws MergeInvalidInputError', () => {
    const bad = makeEntry({ id: ID, tags: undefined as unknown as string[] });
    expect(() => mergeInnerDocs(makeInnerDoc([bad]), makeInnerDoc([]), makeCtx())).toThrow(
      expect.objectContaining({ code: 'MERGE_INVALID_INPUT' }),
    );
  });
});

// ---------------------------------------------------------------------------
// LOW: duplicate.ts grouping key must not be spoofable by a sentinel collision
// ---------------------------------------------------------------------------

describe('gap: findPossibleDuplicates key is collision-free (D-19)', () => {
  it('title "a\\x00b"+url "c" does NOT group with title "a"+url "b\\x00c"', () => {
    const e1 = makeEntry({ id: 'd1', title: 'a\x00b', url: 'c' });
    const e2 = makeEntry({ id: 'd2', title: 'a', url: 'b\x00c' });
    const groups = findPossibleDuplicates(makeInnerDoc([e1, e2]));
    expect(groups.length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Content-level convergence property (the gap the id-set-only properties missed)
// ---------------------------------------------------------------------------

describe('gap: content-level convergence property (D-18 — full vault, not id-sets)', () => {
  // Small fixed pools force shared ids + equal-timestamp collisions so the
  // tombstone / tiebreak branches are actually generated (the original property
  // used independent fc.uuid() ids and almost never reached them).
  const ID_POOL = ['p1', 'p2', 'p3'];
  const TS_POOL = [iso(EPOCH), iso(EPOCH + 1000), iso(EPOCH + 2000)];

  const historyItemArb = fc.record({
    password: fc.string({ minLength: 1, maxLength: 8 }),
    changedAt: fc.constantFrom(...TS_POOL),
  });

  const entryArb: fc.Arbitrary<Entry> = fc
    .record({
      id: fc.constantFrom(...ID_POOL),
      title: fc.string({ minLength: 0, maxLength: 8 }),
      username: fc.string({ minLength: 0, maxLength: 8 }),
      password: fc.string({ minLength: 0, maxLength: 8 }),
      url: fc.string({ minLength: 0, maxLength: 8 }),
      notes: fc.string({ minLength: 0, maxLength: 8 }),
      tags: fc.array(fc.string({ minLength: 1, maxLength: 4 }), { maxLength: 2 }),
      favorite: fc.boolean(),
      needsSiteUpdate: fc.boolean(),
      passwordHistory: fc.array(historyItemArb, { maxLength: 3 }),
      modifiedAt: fc.constantFrom(...TS_POOL),
      deletedAt: fc.option(fc.constantFrom(...TS_POOL), { nil: null }),
    })
    .map((r) => ({
      ...r,
      type: 'login' as const,
      generatorPreset: null,
      createdAt: iso(EPOCH),
      lostVersions: [] as Entry['lostVersions'],
    })) as fc.Arbitrary<Entry>;

  const docArb: fc.Arbitrary<InnerDoc> = fc
    .uniqueArray(entryArb, { selector: (e) => e.id, maxLength: 3 })
    .map((entries) => makeInnerDoc(entries));

  it('commutativity: canon(merge(A,B,ctx)) === canon(merge(B,A,swappedCtx)) — distinct deviceIds', () => {
    const ctx = makeCtx();
    const swapped = makeCtx({ localDeviceId: ctx.remoteDeviceId, remoteDeviceId: ctx.localDeviceId });
    fc.assert(
      fc.property(docArb, docArb, (a, b) => {
        const ab = mergeInnerDocs(a, b, ctx);
        const ba = mergeInnerDocs(b, a, swapped);
        return canonEntries(ab.merged) === canonEntries(ba.merged);
      }),
      { numRuns: 300 },
    );
  });

  it('commutativity holds even when deviceIds are equal (D-14 path)', () => {
    const ctx = makeCtx({ localDeviceId: 'same', remoteDeviceId: 'same' });
    fc.assert(
      fc.property(docArb, docArb, (a, b) => {
        const ab = mergeInnerDocs(a, b, ctx);
        const ba = mergeInnerDocs(b, a, ctx);
        return canonEntries(ab.merged) === canonEntries(ba.merged);
      }),
      { numRuns: 300 },
    );
  });

  it('idempotency: a second merge of the merged result against itself is a content no-op', () => {
    const ctx = makeCtx();
    fc.assert(
      fc.property(docArb, docArb, (a, b) => {
        const once = mergeInnerDocs(a, b, ctx).merged;
        const twice = mergeInnerDocs(once, once, ctx).merged;
        return canonEntries(once) === canonEntries(twice);
      }),
      { numRuns: 300 },
    );
  });
});
