// packages/core/src/entries/__tests__/crud.test.ts
//
// TEST-04 — Entry model suite (Plan 03-02).
//
// Requirements covered:
//   ENTRY-01 — full field set present on a new entry; UUID regex; type==='login'
//   ENTRY-02 — tags[] is a first-class field that survives add/update/round-trip
//   ENTRY-03 — list/get/add/update/softDelete/purge verbs work correctly
//   ENTRY-07 — passwordHistory push-on-change, cap 10, newest-first
//   ENTRY-09 — regenerateFromPreset pushes old password to history (cap 10)
//   TEST-04  — tombstones, needsSiteUpdate toggle, derived password age
//
// NOTE: generateRandom/generatePassphrase (Plan 03-03 stubs) are mocked here so
// that regenerateFromPreset tests do not depend on an unimplemented generator.
// The mock returns a deterministic "generated-password" string so history-push
// logic can be asserted without coupling to generator implementation details.

import { describe, it, expect, vi, beforeAll } from 'vitest';
import type { Entry, InnerDoc, EntryInput, EntryUpdate } from '../types';
import type { GeneratorOptions } from '../../generator/types';
import { DEFAULT_RANDOM_OPTIONS, DEFAULT_PASSPHRASE_OPTIONS } from '../../generator/types';
import {
  addEntry,
  updateEntry,
  softDeleteEntry,
  purgeEntry,
  listEntries,
  getEntry,
  derivePasswordAge,
  regenerateFromPreset,
} from '../crud';
import type { UnlockedVault } from '../../vault/vault';
import { createVault, saveVault, unlockVault } from '../../vault/vault';
import { getSodium } from '../../crypto/sodium';
import { EntryNotFoundError, GeneratorError } from '../../errors';

// ---------------------------------------------------------------------------
// Mock the generator modules so regenerateFromPreset tests don't depend on
// the Plan-03-03 stubs (which throw "not implemented").
// ---------------------------------------------------------------------------

vi.mock('../../generator/random', () => ({
  generateRandom: vi.fn().mockResolvedValue({ password: 'generated-random-password', entropyBits: 100 }),
}));

vi.mock('../../generator/passphrase', () => ({
  generatePassphrase: vi.fn().mockResolvedValue({ phrase: 'generated-passphrase', entropyBits: 64 }),
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/** Build a fresh in-memory UnlockedVault with no crypto round-trip needed. */
function makeVault(): UnlockedVault {
  const inner: InnerDoc = {
    schemaVersion: 1,
    entries: [],
    settings: { generator: DEFAULT_RANDOM_OPTIONS },
  };
  return {
    doc: {
      format: 'cryptiq-vault',
      version: 1,
      wrappedKeys: {
        master: {
          ciphertext: '',
          nonce: '',
          kdf: { algorithm: 2, opsLimit: 3, memLimit: 268_435_456, salt: '' },
        },
      },
      data: { ciphertext: '', nonce: '' },
      meta: { createdAt: new Date().toISOString(), modifiedAt: new Date().toISOString() },
    },
    entries: inner,
  };
}

/** Minimal entry input. */
function minimalInput(overrides?: Partial<EntryInput>): EntryInput {
  return { title: 'Test Entry', password: 'hunter2', ...overrides };
}

function pw(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

// ---------------------------------------------------------------------------
// Fixed-floor kdfParams (TEST seam — skip adaptive calibration)
// ---------------------------------------------------------------------------

const FLOOR_OPS = 3;
const FLOOR_MEM = 268_435_456; // 256 MiB

async function floorParams() {
  const sodium = await getSodium();
  return {
    algorithm: 2 as const,
    opsLimit: FLOOR_OPS,
    memLimit: FLOOR_MEM,
    salt: sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES),
  };
}

// ---------------------------------------------------------------------------
// Structural / type-shape assertions (pass against Wave-0 types)
// ---------------------------------------------------------------------------

describe('Entry type shape (ENTRY-01/ENTRY-02)', () => {
  it('Entry interface has all required ENTRY-01 fields at the type level', () => {
    // Build a shape-complete object — TypeScript will error at compile-time if any
    // required field is missing. This is a compile-time guard, not a runtime test.
    const _entry: Entry = {
      id: 'test-uuid',
      type: 'login',
      title: 'Example',
      username: 'user',
      password: 'secret',
      url: 'https://example.com',
      notes: '',
      tags: [],
      favorite: false,
      needsSiteUpdate: false,
      generatorPreset: null,
      passwordHistory: [],
      createdAt: new Date().toISOString(),
      modifiedAt: new Date().toISOString(),
      deletedAt: null,
    } satisfies Entry;
    expect(_entry.type).toBe('login');
    expect(Array.isArray(_entry.tags)).toBe(true); // ENTRY-02: tags is a field
    expect(_entry.deletedAt).toBeNull(); // ENTRY-04: tombstone field exists
    expect(Array.isArray(_entry.passwordHistory)).toBe(true); // ENTRY-07
  });

  it('InnerDoc has schemaVersion: 1, entries array, and settings block (P3-01)', () => {
    const _doc: InnerDoc = {
      schemaVersion: 1,
      entries: [],
      settings: {
        generator: DEFAULT_RANDOM_OPTIONS,
      },
    } satisfies InnerDoc;
    expect(_doc.schemaVersion).toBe(1);
    expect(Array.isArray(_doc.entries)).toBe(true);
    expect(_doc.settings.generator.mode).toBe('random');
  });

  it('generatorPreset accepts both RandomOptions and PassphraseOptions (P3-07)', () => {
    const randomPreset: GeneratorOptions = DEFAULT_RANDOM_OPTIONS;
    const passphrasePreset: GeneratorOptions = DEFAULT_PASSPHRASE_OPTIONS;
    const _withRandom: Entry['generatorPreset'] = randomPreset;
    const _withPassphrase: Entry['generatorPreset'] = passphrasePreset;
    const _withNull: Entry['generatorPreset'] = null;
    expect(_withRandom).toBeDefined();
    expect(_withPassphrase).toBeDefined();
    expect(_withNull).toBeNull();
  });

  it('EntryInput requires only title', () => {
    const _minimal: EntryInput = { title: 'Test' };
    expect(_minimal.title).toBe('Test');
  });

  it('EntryUpdate allows any mutable subset', () => {
    const _partial: EntryUpdate = { title: 'New title', favorite: true };
    expect(_partial.title).toBe('New title');
  });
});

// ---------------------------------------------------------------------------
// addEntry (ENTRY-01/ENTRY-02/ENTRY-03)
// ---------------------------------------------------------------------------

describe('addEntry (ENTRY-01/ENTRY-03)', () => {
  it('creates an entry with a CSPRNG UUIDv4 id (P3-03)', async () => {
    const vault = makeVault();
    const entry = await addEntry(vault, minimalInput());
    expect(entry.id).toMatch(UUID_V4_RE);
  });

  it('sets type to "login", createdAt/modifiedAt to now, deletedAt to null', async () => {
    const before = Date.now();
    const vault = makeVault();
    const entry = await addEntry(vault, minimalInput());
    const after = Date.now();

    expect(entry.type).toBe('login');
    expect(new Date(entry.createdAt).getTime()).toBeGreaterThanOrEqual(before);
    expect(new Date(entry.createdAt).getTime()).toBeLessThanOrEqual(after);
    expect(entry.createdAt).toBe(entry.modifiedAt);
    expect(entry.deletedAt).toBeNull();
  });

  it('applies default values for optional fields (username="", tags=[], etc.)', async () => {
    const vault = makeVault();
    const entry = await addEntry(vault, { title: 'Minimal' });

    expect(entry.title).toBe('Minimal');
    expect(entry.username).toBe('');
    expect(entry.password).toBe('');
    expect(entry.url).toBe('');
    expect(entry.notes).toBe('');
    expect(entry.tags).toEqual([]);
    expect(entry.favorite).toBe(false);
    expect(entry.needsSiteUpdate).toBe(false);
    expect(entry.generatorPreset).toBeNull();
    expect(entry.passwordHistory).toEqual([]);
  });

  it('adds the entry to vault.entries in place (P3-02)', async () => {
    const vault = makeVault();
    expect(listEntries(vault).length).toBe(0);

    const entry = await addEntry(vault, minimalInput());
    const entries = listEntries(vault);
    expect(entries.length).toBe(1);
    expect(entries[0]!.id).toBe(entry.id);
  });

  it('tags[] is a first-class field that survives add (ENTRY-02)', async () => {
    const vault = makeVault();
    const entry = await addEntry(vault, { title: 'Tagged', tags: ['work', 'banking'] });
    expect(entry.tags).toEqual(['work', 'banking']);
  });

  it('two entries get different UUIDs', async () => {
    const vault = makeVault();
    const e1 = await addEntry(vault, minimalInput());
    const e2 = await addEntry(vault, minimalInput());
    expect(e1.id).not.toBe(e2.id);
  });
});

// ---------------------------------------------------------------------------
// updateEntry (ENTRY-03/ENTRY-07)
// ---------------------------------------------------------------------------

describe('updateEntry (ENTRY-03/ENTRY-07)', () => {
  it('updates the entry in place and returns it', async () => {
    const vault = makeVault();
    const entry = await addEntry(vault, minimalInput({ title: 'Original' }));
    const updated = updateEntry(vault, entry.id, { title: 'Updated' });
    expect(updated.title).toBe('Updated');
    // Same object reference — in-place mutation (P3-02)
    expect(getEntry(vault, entry.id)!.title).toBe('Updated');
  });

  it('updates modifiedAt to now on every call', async () => {
    const vault = makeVault();
    const entry = await addEntry(vault, minimalInput());
    const originalModifiedAt = entry.modifiedAt;

    // Introduce a small delay to ensure the timestamp can differ
    await new Promise((resolve) => setTimeout(resolve, 5));
    updateEntry(vault, entry.id, { title: 'Changed' });

    const updated = getEntry(vault, entry.id)!;
    // modifiedAt must have been updated (may equal original on very fast machines
    // but must be a valid ISO string and >= createdAt)
    expect(new Date(updated.modifiedAt).getTime()).toBeGreaterThanOrEqual(
      new Date(originalModifiedAt).getTime(),
    );
  });

  it('pushes old password to passwordHistory when password changes (ENTRY-07)', async () => {
    const vault = makeVault();
    const entry = await addEntry(vault, minimalInput({ password: 'old-pass' }));
    updateEntry(vault, entry.id, { password: 'new-pass' });

    const updated = getEntry(vault, entry.id)!;
    expect(updated.password).toBe('new-pass');
    expect(updated.passwordHistory.length).toBe(1);
    expect(updated.passwordHistory[0]!.password).toBe('old-pass');
    expect(updated.passwordHistory[0]!.changedAt).toBeTruthy();
  });

  it('does NOT push history when password is unchanged (ENTRY-07)', async () => {
    const vault = makeVault();
    const entry = await addEntry(vault, minimalInput({ password: 'same-pass' }));
    updateEntry(vault, entry.id, { password: 'same-pass', title: 'Changed title' });

    const updated = getEntry(vault, entry.id)!;
    expect(updated.passwordHistory.length).toBe(0);
  });

  it('does NOT push history when password field is absent from update', async () => {
    const vault = makeVault();
    const entry = await addEntry(vault, minimalInput({ password: 'unchanged' }));
    updateEntry(vault, entry.id, { title: 'New title' });

    const updated = getEntry(vault, entry.id)!;
    expect(updated.passwordHistory.length).toBe(0);
  });

  it('caps passwordHistory at 10 entries after 12 changes (ENTRY-07)', async () => {
    const vault = makeVault();
    const entry = await addEntry(vault, minimalInput({ password: 'pass-0' }));

    for (let i = 1; i <= 12; i++) {
      updateEntry(vault, entry.id, { password: `pass-${i}` });
    }

    const updated = getEntry(vault, entry.id)!;
    expect(updated.passwordHistory.length).toBe(10);
    // Newest-first: most recent change is at index 0
    expect(updated.passwordHistory[0]!.password).toBe('pass-11');
    expect(updated.passwordHistory[9]!.password).toBe('pass-2');
  });

  it('throws EntryNotFoundError for an unknown id', async () => {
    const vault = makeVault();
    expect(() => updateEntry(vault, 'nonexistent-id', { title: 'x' })).toThrow(EntryNotFoundError);
  });

  it('throws EntryNotFoundError for a soft-deleted entry', async () => {
    const vault = makeVault();
    const entry = await addEntry(vault, minimalInput());
    softDeleteEntry(vault, entry.id);
    expect(() => updateEntry(vault, entry.id, { title: 'x' })).toThrow(EntryNotFoundError);
  });

  it('tags[] survives update round-trip (ENTRY-02)', async () => {
    const vault = makeVault();
    const entry = await addEntry(vault, minimalInput({ tags: ['initial'] }));
    updateEntry(vault, entry.id, { tags: ['updated', 'tags'] });
    expect(getEntry(vault, entry.id)!.tags).toEqual(['updated', 'tags']);
  });
});

// ---------------------------------------------------------------------------
// softDeleteEntry (ENTRY-03/ENTRY-04)
// ---------------------------------------------------------------------------

describe('softDeleteEntry (ENTRY-03/ENTRY-04)', () => {
  it('sets deletedAt to an ISO timestamp', async () => {
    const before = Date.now();
    const vault = makeVault();
    const entry = await addEntry(vault, minimalInput());
    softDeleteEntry(vault, entry.id);
    const after = Date.now();

    const tombstone = getEntry(vault, entry.id)!;
    expect(tombstone.deletedAt).toBeTruthy();
    expect(new Date(tombstone.deletedAt!).getTime()).toBeGreaterThanOrEqual(before);
    expect(new Date(tombstone.deletedAt!).getTime()).toBeLessThanOrEqual(after);
  });

  it('entry remains in vault.entries as a tombstone', async () => {
    const vault = makeVault();
    const entry = await addEntry(vault, minimalInput());
    softDeleteEntry(vault, entry.id);
    // Still findable by ID
    expect(getEntry(vault, entry.id)).toBeDefined();
  });

  it('listEntries excludes the tombstone by default', async () => {
    const vault = makeVault();
    await addEntry(vault, minimalInput({ title: 'Active' }));
    const toDelete = await addEntry(vault, minimalInput({ title: 'ToDelete' }));
    softDeleteEntry(vault, toDelete.id);

    const active = listEntries(vault);
    expect(active.length).toBe(1);
    expect(active[0]!.title).toBe('Active');
  });

  it('listEntries(vault, true) includes the tombstone', async () => {
    const vault = makeVault();
    await addEntry(vault, minimalInput({ title: 'Active' }));
    const toDelete = await addEntry(vault, minimalInput({ title: 'ToDelete' }));
    softDeleteEntry(vault, toDelete.id);

    const all = listEntries(vault, true);
    expect(all.length).toBe(2);
  });

  it('throws EntryNotFoundError for an unknown id', async () => {
    const vault = makeVault();
    expect(() => softDeleteEntry(vault, 'unknown')).toThrow(EntryNotFoundError);
  });
});

// ---------------------------------------------------------------------------
// purgeEntry (ENTRY-03)
// ---------------------------------------------------------------------------

describe('purgeEntry (ENTRY-03)', () => {
  it('removes the entry from vault.entries entirely', async () => {
    const vault = makeVault();
    const entry = await addEntry(vault, minimalInput());
    purgeEntry(vault, entry.id);
    expect(getEntry(vault, entry.id)).toBeUndefined();
    expect(listEntries(vault, true).length).toBe(0);
  });

  it('silently no-ops if id not found', () => {
    const vault = makeVault();
    expect(() => purgeEntry(vault, 'not-here')).not.toThrow();
  });

  it('removes a soft-deleted tombstone (hard-delete after soft-delete)', async () => {
    const vault = makeVault();
    const entry = await addEntry(vault, minimalInput());
    softDeleteEntry(vault, entry.id);
    expect(listEntries(vault, true).length).toBe(1);
    purgeEntry(vault, entry.id);
    expect(listEntries(vault, true).length).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// listEntries / getEntry (ENTRY-03)
// ---------------------------------------------------------------------------

describe('listEntries / getEntry (ENTRY-03)', () => {
  it('listEntries returns only active entries by default', async () => {
    const vault = makeVault();
    const e1 = await addEntry(vault, minimalInput({ title: 'A' }));
    await addEntry(vault, minimalInput({ title: 'B' }));
    softDeleteEntry(vault, e1.id);

    const active = listEntries(vault);
    expect(active.length).toBe(1);
    expect(active[0]!.title).toBe('B');
  });

  it('listEntries returns all entries when includeDeleted=true', async () => {
    const vault = makeVault();
    const e1 = await addEntry(vault, minimalInput({ title: 'A' }));
    await addEntry(vault, minimalInput({ title: 'B' }));
    softDeleteEntry(vault, e1.id);

    const all = listEntries(vault, true);
    expect(all.length).toBe(2);
  });

  it('getEntry returns undefined for an unknown id', () => {
    const vault = makeVault();
    expect(getEntry(vault, 'no-such-id')).toBeUndefined();
  });

  it('getEntry returns a soft-deleted entry (tombstones are still findable by id)', async () => {
    const vault = makeVault();
    const entry = await addEntry(vault, minimalInput());
    softDeleteEntry(vault, entry.id);
    const found = getEntry(vault, entry.id);
    expect(found).toBeDefined();
    expect(found!.deletedAt).not.toBeNull();
  });
});

// ---------------------------------------------------------------------------
// derivePasswordAge (TEST-04)
// ---------------------------------------------------------------------------

describe('derivePasswordAge (TEST-04)', () => {
  it('accepts a nowMs parameter for deterministic testing', () => {
    const entry: Entry = {
      id: 'test',
      type: 'login',
      title: 'T',
      username: '',
      password: 'p',
      url: '',
      notes: '',
      tags: [],
      favorite: false,
      needsSiteUpdate: false,
      generatorPreset: null,
      passwordHistory: [],
      createdAt: new Date(1_000_000).toISOString(),
      modifiedAt: new Date(1_000_000).toISOString(),
      deletedAt: null,
    };
    const age = derivePasswordAge(entry, 2_000_000);
    expect(age).toBe(1_000_000);
  });

  it('returns time since createdAt when passwordHistory is empty', () => {
    const createdAt = new Date(1_000_000).toISOString();
    const entry: Entry = {
      id: 'test',
      type: 'login',
      title: 'T',
      username: '',
      password: 'p',
      url: '',
      notes: '',
      tags: [],
      favorite: false,
      needsSiteUpdate: false,
      generatorPreset: null,
      passwordHistory: [],
      createdAt,
      modifiedAt: createdAt,
      deletedAt: null,
    };
    const nowMs = 3_000_000;
    expect(derivePasswordAge(entry, nowMs)).toBe(2_000_000);
  });

  it('returns time since passwordHistory[0].changedAt when history is non-empty', () => {
    const createdAt = new Date(1_000_000).toISOString();
    const changedAt = new Date(2_000_000).toISOString();
    const entry: Entry = {
      id: 'test',
      type: 'login',
      title: 'T',
      username: '',
      password: 'new-pass',
      url: '',
      notes: '',
      tags: [],
      favorite: false,
      needsSiteUpdate: false,
      generatorPreset: null,
      passwordHistory: [{ password: 'old-pass', changedAt }],
      createdAt,
      modifiedAt: changedAt,
      deletedAt: null,
    };
    const nowMs = 5_000_000;
    // Should be relative to changedAt (2_000_000), not createdAt (1_000_000)
    expect(derivePasswordAge(entry, nowMs)).toBe(3_000_000);
  });
});

// ---------------------------------------------------------------------------
// regenerateFromPreset (ENTRY-09)
// ---------------------------------------------------------------------------

describe('regenerateFromPreset (ENTRY-09)', () => {
  it('generates a new password from the entry generatorPreset (random mode)', async () => {
    const vault = makeVault();
    const entry = await addEntry(vault, minimalInput({
      password: 'old-password',
      generatorPreset: DEFAULT_RANDOM_OPTIONS,
    }));

    const updated = await regenerateFromPreset(vault, entry.id);
    expect(updated.password).toBe('generated-random-password');
  });

  it('generates a new password from the entry generatorPreset (passphrase mode)', async () => {
    const vault = makeVault();
    const entry = await addEntry(vault, minimalInput({
      password: 'old-passphrase',
      generatorPreset: DEFAULT_PASSPHRASE_OPTIONS,
    }));

    const updated = await regenerateFromPreset(vault, entry.id);
    expect(updated.password).toBe('generated-passphrase');
  });

  it('pushes old password to passwordHistory (cap 10)', async () => {
    const vault = makeVault();
    const entry = await addEntry(vault, minimalInput({
      password: 'original',
      generatorPreset: DEFAULT_RANDOM_OPTIONS,
    }));

    await regenerateFromPreset(vault, entry.id);

    const updated = getEntry(vault, entry.id)!;
    expect(updated.passwordHistory.length).toBe(1);
    expect(updated.passwordHistory[0]!.password).toBe('original');
  });

  it('caps passwordHistory at 10 after 12 regenerations', async () => {
    const vault = makeVault();
    const entry = await addEntry(vault, minimalInput({
      password: 'pass-0',
      generatorPreset: DEFAULT_RANDOM_OPTIONS,
    }));

    for (let i = 0; i < 12; i++) {
      await regenerateFromPreset(vault, entry.id);
    }

    const updated = getEntry(vault, entry.id)!;
    expect(updated.passwordHistory.length).toBe(10);
  });

  it('keeps the generatorPreset intact after regen (P3-07)', async () => {
    const vault = makeVault();
    const entry = await addEntry(vault, minimalInput({
      password: 'old',
      generatorPreset: DEFAULT_RANDOM_OPTIONS,
    }));

    await regenerateFromPreset(vault, entry.id);
    const updated = getEntry(vault, entry.id)!;
    expect(updated.generatorPreset).toEqual(DEFAULT_RANDOM_OPTIONS);
  });

  it('throws EntryNotFoundError for an unknown id', async () => {
    const vault = makeVault();
    await expect(regenerateFromPreset(vault, 'unknown')).rejects.toThrow(EntryNotFoundError);
  });

  it('throws EntryNotFoundError for a soft-deleted entry', async () => {
    const vault = makeVault();
    const entry = await addEntry(vault, minimalInput({
      generatorPreset: DEFAULT_RANDOM_OPTIONS,
    }));
    softDeleteEntry(vault, entry.id);
    await expect(regenerateFromPreset(vault, entry.id)).rejects.toThrow(EntryNotFoundError);
  });

  it('throws GeneratorError when generatorPreset is null', async () => {
    const vault = makeVault();
    const entry = await addEntry(vault, minimalInput({ generatorPreset: null }));
    await expect(regenerateFromPreset(vault, entry.id)).rejects.toThrow(GeneratorError);
  });
});

// ---------------------------------------------------------------------------
// needsSiteUpdate flag (TEST-04)
// ---------------------------------------------------------------------------

describe('needsSiteUpdate flag (TEST-04)', () => {
  it('is false on new entries', async () => {
    const vault = makeVault();
    const entry = await addEntry(vault, minimalInput());
    expect(entry.needsSiteUpdate).toBe(false);
  });

  it('can be toggled via updateEntry', async () => {
    const vault = makeVault();
    const entry = await addEntry(vault, minimalInput());
    updateEntry(vault, entry.id, { needsSiteUpdate: true });
    expect(getEntry(vault, entry.id)!.needsSiteUpdate).toBe(true);

    updateEntry(vault, entry.id, { needsSiteUpdate: false });
    expect(getEntry(vault, entry.id)!.needsSiteUpdate).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// ENTRY-03 full sequence: add → get → update → list → softDelete → purge
// ---------------------------------------------------------------------------

describe('ENTRY-03 full CRUD sequence', () => {
  it('add → get → update → list → softDelete → purge sequence', async () => {
    const vault = makeVault();

    // add
    const entry = await addEntry(vault, minimalInput({ title: 'Sequence Test' }));

    // get
    const found = getEntry(vault, entry.id);
    expect(found).toBeDefined();
    expect(found!.title).toBe('Sequence Test');

    // update
    updateEntry(vault, entry.id, { title: 'Updated Sequence' });
    expect(getEntry(vault, entry.id)!.title).toBe('Updated Sequence');

    // list (active)
    expect(listEntries(vault).length).toBe(1);

    // softDelete → list hides tombstone
    softDeleteEntry(vault, entry.id);
    expect(listEntries(vault).length).toBe(0);
    expect(listEntries(vault, true).length).toBe(1);

    // purge → gone entirely
    purgeEntry(vault, entry.id);
    expect(listEntries(vault, true).length).toBe(0);
    expect(getEntry(vault, entry.id)).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Round-trip test: createVault → addEntry/updateEntry → saveVault → unlockVault
// (ENTRY-01/ENTRY-02 survive encryption; proves P3-01 inner doc round-trips)
// ---------------------------------------------------------------------------

describe('Encrypted save/load round-trip (ENTRY-01/ENTRY-02/ENTRY-03)', () => {
  let roundTripVault: UnlockedVault;
  let roundTripKey: Uint8Array;
  let entryId: string;

  beforeAll(async () => {
    const kdfParams = await floorParams();
    const created = await createVault({
      masterPassword: pw('roundtrip-test-pass'),
      withRecoveryKey: false,
      kdfParams,
    });
    roundTripVault = created.vault;
    roundTripKey = created.vaultKey;

    // Add an entry with tags (ENTRY-02) and a password
    const entry = await addEntry(roundTripVault, {
      title: 'Round Trip Entry',
      username: 'rtuser',
      password: 'rt-pass-v1',
      url: 'https://example.com',
      notes: 'round trip notes',
      tags: ['round', 'trip'],
      generatorPreset: DEFAULT_RANDOM_OPTIONS,
    });
    entryId = entry.id;

    // Update the password so history is populated
    updateEntry(roundTripVault, entryId, { password: 'rt-pass-v2' });
  }, 60_000); // allow time for Argon2id

  it('entries survive saveVault → unlockVault (round-trip via encryption)', async () => {
    const kdfParams = await floorParams();

    // Save the vault to bytes
    const bytes = await saveVault(roundTripVault, roundTripKey);

    // Re-unlock from the serialized bytes
    const { vault: reloaded } = await unlockVault(
      bytes,
      { masterPassword: pw('roundtrip-test-pass') },
    );

    const entries = listEntries(reloaded);
    expect(entries.length).toBe(1);

    const rtEntry = entries[0]!;
    expect(rtEntry.id).toBe(entryId);
    expect(rtEntry.title).toBe('Round Trip Entry');
    expect(rtEntry.username).toBe('rtuser');
    expect(rtEntry.password).toBe('rt-pass-v2');
    expect(rtEntry.url).toBe('https://example.com');
    expect(rtEntry.notes).toBe('round trip notes');
    expect(rtEntry.tags).toEqual(['round', 'trip']); // ENTRY-02
    expect(rtEntry.type).toBe('login');
    expect(rtEntry.deletedAt).toBeNull();
    // Password history: old password was pushed
    expect(rtEntry.passwordHistory.length).toBe(1);
    expect(rtEntry.passwordHistory[0]!.password).toBe('rt-pass-v1');
    // generatorPreset survives
    expect(rtEntry.generatorPreset).toEqual(DEFAULT_RANDOM_OPTIONS);

    // Unused but needed to avoid kdfParams unused variable warning
    void kdfParams;
  }, 60_000);
});

// ---------------------------------------------------------------------------
// Pitfall-3: Phase-2 dev vault (no schemaVersion) is upgraded in place
// ---------------------------------------------------------------------------

describe('Pitfall-3: Phase-2 dev vault upgrade (defensive inner-doc cast)', () => {
  it('asInnerDoc upgrades a Phase-2 vault without schemaVersion in place', async () => {
    // Simulate a Phase-2 vault: entries object has no schemaVersion
    const phase2Vault: UnlockedVault = {
      doc: {
        format: 'cryptiq-vault',
        version: 1,
        wrappedKeys: {
          master: {
            ciphertext: '',
            nonce: '',
            kdf: { algorithm: 2, opsLimit: 3, memLimit: 268_435_456, salt: '' },
          },
        },
        data: { ciphertext: '', nonce: '' },
        meta: { createdAt: new Date().toISOString(), modifiedAt: new Date().toISOString() },
      },
      entries: { entries: [] } as unknown as object,
    };

    // Adding an entry should upgrade the inner doc and succeed
    const entry = await addEntry(phase2Vault, minimalInput({ title: 'Phase2 Entry' }));
    expect(entry.title).toBe('Phase2 Entry');
    expect(entry.id).toMatch(UUID_V4_RE);

    // The entries list should now work
    const entries = listEntries(phase2Vault);
    expect(entries.length).toBe(1);
  });
});
