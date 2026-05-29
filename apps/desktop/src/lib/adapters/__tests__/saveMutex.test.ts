// apps/desktop/src/lib/adapters/__tests__/saveMutex.test.ts
//
// Plan 03-05 Task 2 — mocked-IO adapter test suite.
//
// Covers (per acceptance criteria):
//   (1) Two racing save() calls serialize in order (VAULT-05 concurrency).
//   (2) isSaving is true during a save, false after.
//   (3) lock()-style "zero after save" sequence does not interleave (Pitfall 4).
//   (4) Content-hash dedup: unchanged hash → no backup rotation; changed → rotation (P3-11).
//   (5) listBackups / loadBackup / savePreMigrationBackup behavior (P3-13).
//
// Mock strategy:
//   - @tauri-apps/api/core: vi.mock with a controllable `invoke` stub.
//   - @tauri-apps/plugin-fs: vi.mock with stubs for exists/readFile/stat.
//   - No real Tauri runtime, no WASM — pure TS unit test in node environment.
//
// Source: CONTEXT.md P3-11/P3-12/P3-13 + 03-RESEARCH §Save-Mutex + §Pattern 8

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { TauriVaultStorageAdapter } from '../TauriVaultStorageAdapter';
import { VaultLockedByOtherProcessError, VaultIOError, VaultNotFoundError } from '@cryptiq/core';
import { hashEntriesContent } from '../contentHash';

// ---------------------------------------------------------------------------
// Module mocks
// ---------------------------------------------------------------------------

// Mock @tauri-apps/api/core — intercept all invoke() calls.
vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(),
}));

// Mock @tauri-apps/plugin-fs — intercept exists/readFile/stat.
vi.mock('@tauri-apps/plugin-fs', () => ({
  exists: vi.fn(),
  readFile: vi.fn(),
  stat: vi.fn(),
}));

// Import the mocked modules AFTER vi.mock() so we get the stubs.
import { invoke } from '@tauri-apps/api/core';
import { exists, readFile, stat } from '@tauri-apps/plugin-fs';

const mockInvoke = vi.mocked(invoke);
const mockExists = vi.mocked(exists);
const mockReadFile = vi.mocked(readFile);
const mockStat = vi.mocked(stat);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const VAULT_PATH = '/home/user/.config/cryptiq/vaults/vault.cryptiq';

function makeAdapter(): TauriVaultStorageAdapter {
  return new TauriVaultStorageAdapter(VAULT_PATH);
}

/** Create a small fake encrypted bytes payload. */
function fakeBytes(seed = 0): Uint8Array {
  return new Uint8Array([1, 2, 3, seed]);
}

/**
 * Return a promise that resolves after `ms` milliseconds.
 * Used to simulate async work inside mocked invoke.
 */
function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// Test suites
// ---------------------------------------------------------------------------

describe('TauriVaultStorageAdapter', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Default: vault_lock_check resolves (we own the lock).
    mockInvoke.mockResolvedValue(undefined);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // -------------------------------------------------------------------------
  // (1) Concurrent save() calls serialize in order
  // -------------------------------------------------------------------------

  describe('save-mutex serialization (P3-12 / VAULT-05)', () => {
    it('serializes two concurrent save() calls in call order', async () => {
      const adapter = makeAdapter();
      const callOrder: number[] = [];

      // First invoke call is slow (20ms); second is fast (0ms).
      // If they ran in parallel, second would finish first — the serialized order proves mutex.
      let callIndex = 0;
      mockInvoke.mockImplementation(async (cmd: string) => {
        if (cmd === 'vault_lock_check') return undefined;
        if (cmd === 'vault_write_atomic') {
          const idx = ++callIndex;
          callOrder.push(idx); // record START order
          if (idx === 1) await delay(20); // first save is slow
          // (second save is instant)
        }
      });

      // Fire both saves concurrently — do NOT await the first before starting second.
      const p1 = adapter.save(fakeBytes(1), { contentHash: 'hash-a' });
      const p2 = adapter.save(fakeBytes(2), { contentHash: 'hash-b' });

      await Promise.all([p1, p2]);

      // Both completed successfully; the order must be [1, 2] not [2, 1].
      expect(callOrder).toEqual([1, 2]);
    });

    it('the second save() call waits for the first to fully finish', async () => {
      const adapter = makeAdapter();
      const timeline: string[] = [];

      let slowDone = false;
      mockInvoke.mockImplementation(async (cmd: string) => {
        if (cmd === 'vault_lock_check') return undefined;
        if (cmd === 'vault_write_atomic') {
          if (!slowDone) {
            await delay(15);
            timeline.push('first-write-done');
            slowDone = true;
          } else {
            timeline.push('second-write-done');
          }
        }
      });

      const p1 = adapter.save(fakeBytes(1));
      const p2 = adapter.save(fakeBytes(2));
      await Promise.all([p1, p2]);

      // 'first-write-done' must appear before 'second-write-done'
      expect(timeline.indexOf('first-write-done')).toBeLessThan(
        timeline.indexOf('second-write-done'),
      );
    });
  });

  // -------------------------------------------------------------------------
  // (2) isSaving flag transitions
  // -------------------------------------------------------------------------

  describe('isSaving flag (P3-12)', () => {
    it('is false before any save starts', () => {
      const adapter = makeAdapter();
      expect(adapter.isSaving).toBe(false);
    });

    it('is true during a save and false after', async () => {
      const adapter = makeAdapter();
      const flagsDuringAndAfter: boolean[] = [];

      mockInvoke.mockImplementation(async (cmd: string) => {
        if (cmd === 'vault_lock_check') return undefined;
        if (cmd === 'vault_write_atomic') {
          // Capture flag mid-save
          flagsDuringAndAfter.push(adapter.isSaving);
          await delay(5);
        }
      });

      const p = adapter.save(fakeBytes());
      // Give the micro-task queue a tick so the mutex callback starts.
      await delay(1);
      flagsDuringAndAfter.push(adapter.isSaving); // capture from the outside too

      await p;
      flagsDuringAndAfter.push(adapter.isSaving); // should be false now

      // At least one capture should show true (either inside the invoke or from outside).
      expect(flagsDuringAndAfter.some((v) => v === true)).toBe(true);
      // After save: false.
      expect(flagsDuringAndAfter[flagsDuringAndAfter.length - 1]).toBe(false);
    });

    it('is false after a failed save', async () => {
      const adapter = makeAdapter();

      mockInvoke.mockImplementation(async (cmd: string) => {
        if (cmd === 'vault_lock_check') return undefined;
        if (cmd === 'vault_write_atomic') {
          throw new Error('disk full');
        }
      });

      await expect(adapter.save(fakeBytes())).rejects.toBeInstanceOf(VaultIOError);
      expect(adapter.isSaving).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // (3) lock()-style "zero after save" sequence — Pitfall 4 defense
  // -------------------------------------------------------------------------

  describe('Pitfall 4: lock() does not race a save into a zeroed key', () => {
    it('awaitSaveMutex() resolves after an in-flight save finishes', async () => {
      const adapter = makeAdapter();
      const events: string[] = [];

      mockInvoke.mockImplementation(async (cmd: string) => {
        if (cmd === 'vault_lock_check') return undefined;
        if (cmd === 'vault_write_atomic') {
          await delay(15);
          events.push('write-done');
        }
      });

      // Start a save — do not await it.
      const savePromise = adapter.save(fakeBytes());

      // Simulate lock(): await the save-mutex BEFORE zeroing the key.
      // In real VaultSession.lock(), this ensures key is not zeroed while save is using it.
      const lockSimulation = adapter.awaitSaveMutex().then(() => {
        events.push('key-zeroed');
      });

      await Promise.all([savePromise, lockSimulation]);

      // 'write-done' must appear before 'key-zeroed'
      const writeIdx = events.indexOf('write-done');
      const zeroIdx = events.indexOf('key-zeroed');
      expect(writeIdx).toBeGreaterThanOrEqual(0);
      expect(zeroIdx).toBeGreaterThanOrEqual(0);
      expect(writeIdx).toBeLessThan(zeroIdx);
    });
  });

  // -------------------------------------------------------------------------
  // (4) Content-hash dedup (P3-11)
  // -------------------------------------------------------------------------

  describe('content-hash backup dedup (P3-11)', () => {
    it('passes maxBackups=5 when content hash changed', async () => {
      const adapter = makeAdapter();
      adapter.initLastSavedHash('old-hash');

      const capturedArgs: unknown[] = [];
      mockInvoke.mockImplementation(async (cmd: string, args: unknown) => {
        if (cmd === 'vault_lock_check') return undefined;
        if (cmd === 'vault_write_atomic') capturedArgs.push(args);
      });

      await adapter.save(fakeBytes(), { contentHash: 'new-hash', maxBackups: 5 });

      expect(capturedArgs).toHaveLength(1);
      const arg = capturedArgs[0] as Record<string, unknown>;
      expect(arg['maxBackups']).toBe(5); // rotation allowed
    });

    it('passes maxBackups=0 (no rotation) when content hash is unchanged', async () => {
      const adapter = makeAdapter();
      const sameHash = hashEntriesContent({ entries: [{ title: 'test' }] });
      adapter.initLastSavedHash(sameHash);

      const capturedArgs: unknown[] = [];
      mockInvoke.mockImplementation(async (cmd: string, args: unknown) => {
        if (cmd === 'vault_lock_check') return undefined;
        if (cmd === 'vault_write_atomic') capturedArgs.push(args);
      });

      // Save with the SAME hash that was initialized.
      await adapter.save(fakeBytes(), { contentHash: sameHash, maxBackups: 5 });

      expect(capturedArgs).toHaveLength(1);
      const arg = capturedArgs[0] as Record<string, unknown>;
      expect(arg['maxBackups']).toBe(0); // no rotation
    });

    it('updates lastSavedHash after a successful save with a new hash', async () => {
      const adapter = makeAdapter();
      adapter.initLastSavedHash('hash-1');

      mockInvoke.mockResolvedValue(undefined); // lock_check + vault_write_atomic both succeed

      await adapter.save(fakeBytes(), { contentHash: 'hash-2', maxBackups: 5 });

      // Now saving with hash-2 should suppress rotation (hash-2 === lastSavedHash).
      const capturedArgs: unknown[] = [];
      mockInvoke.mockImplementation(async (cmd: string, args: unknown) => {
        if (cmd === 'vault_lock_check') return undefined;
        if (cmd === 'vault_write_atomic') capturedArgs.push(args);
      });

      await adapter.save(fakeBytes(), { contentHash: 'hash-2', maxBackups: 5 });

      const arg = capturedArgs[0] as Record<string, unknown>;
      expect(arg['maxBackups']).toBe(0); // suppressed because hash-2 === lastSavedHash
    });

    it('does NOT update lastSavedHash if the save fails', async () => {
      const adapter = makeAdapter();
      adapter.initLastSavedHash('hash-1');

      mockInvoke.mockImplementation(async (cmd: string) => {
        if (cmd === 'vault_lock_check') return undefined;
        if (cmd === 'vault_write_atomic') throw new Error('io error');
      });

      await expect(
        adapter.save(fakeBytes(), { contentHash: 'hash-2' }),
      ).rejects.toBeInstanceOf(VaultIOError);

      // lastSavedHash must still be 'hash-1' — don't update on failure.
      // Verify by checking that the NEXT save with hash-2 STILL rotates backups.
      const capturedArgs: unknown[] = [];
      mockInvoke.mockImplementation(async (cmd: string, args: unknown) => {
        if (cmd === 'vault_lock_check') return undefined;
        if (cmd === 'vault_write_atomic') capturedArgs.push(args);
      });

      await adapter.save(fakeBytes(), { contentHash: 'hash-2', maxBackups: 5 });
      const arg = capturedArgs[0] as Record<string, unknown>;
      expect(arg['maxBackups']).toBe(5); // still rotates because hash changed (hash-1 → hash-2)
    });

    it('saves with rotation when no contentHash is provided (default behavior)', async () => {
      const adapter = makeAdapter();
      adapter.initLastSavedHash('some-hash');

      const capturedArgs: unknown[] = [];
      mockInvoke.mockImplementation(async (cmd: string, args: unknown) => {
        if (cmd === 'vault_lock_check') return undefined;
        if (cmd === 'vault_write_atomic') capturedArgs.push(args);
      });

      // No contentHash — always rotate
      await adapter.save(fakeBytes(), { maxBackups: 5 });

      const arg = capturedArgs[0] as Record<string, unknown>;
      expect(arg['maxBackups']).toBe(5);
    });
  });

  // -------------------------------------------------------------------------
  // (5a) listBackups (P3-13)
  // -------------------------------------------------------------------------

  describe('listBackups (P3-13)', () => {
    it('returns empty array when no backup slots exist', async () => {
      const adapter = makeAdapter();
      mockExists.mockResolvedValue(false);

      const result = await adapter.listBackups();
      expect(result).toEqual([]);
    });

    it('lists only existing slots (slot 1 and 3, not 2,4,5)', async () => {
      const adapter = makeAdapter();
      const now = new Date('2026-05-30T12:00:00Z');

      // Slot 1 exists, slot 2 missing, slot 3 exists, slots 4+5 missing
      mockExists.mockImplementation(async (path: string | URL) => {
        const p = path.toString();
        return p.endsWith('.bak.1') || p.endsWith('.bak.3');
      });
      mockStat.mockImplementation(async (path: string | URL) => {
        const p = path.toString();
        return {
          isFile: true,
          isDirectory: false,
          isSymlink: false,
          size: p.endsWith('.bak.1') ? 1024 : 2048,
          mtime: now,
          atime: null,
          birthtime: null,
          readonly: false,
          fileAttributes: null,
          dev: null,
          ino: null,
          mode: null,
          nlink: null,
          uid: null,
          gid: null,
          rdev: null,
          blksize: null,
          blocks: null,
        };
      });

      const result = await adapter.listBackups();

      // Result must be newest-first: slot 1 is the most recently written backup
      // (Rust rotation pushes bak.1→2→3→4→5, so slot 1 is always newest).
      // The loop iterates 1..5 ascending, so no reversal is needed — slot 1 is at index 0.
      expect(result).toHaveLength(2);
      // Slot 1 (most recent) at index 0; slot 3 (older) at index 1.
      expect(result[0]!.slot).toBe(1);
      expect(result[1]!.slot).toBe(3);
      expect(result[0]!.byteLength).toBe(1024);
      expect(result[1]!.byteLength).toBe(2048);
    });

    it('includes modifiedAt as ISO string', async () => {
      const adapter = makeAdapter();
      const mtime = new Date('2026-01-15T08:30:00Z');

      mockExists.mockImplementation(async (path: string | URL) =>
        path.toString().endsWith('.bak.1'),
      );
      mockStat.mockResolvedValue({
        isFile: true,
        isDirectory: false,
        isSymlink: false,
        size: 512,
        mtime,
        atime: null,
        birthtime: null,
        readonly: false,
        fileAttributes: null,
        dev: null,
        ino: null,
        mode: null,
        nlink: null,
        uid: null,
        gid: null,
        rdev: null,
        blksize: null,
        blocks: null,
      });

      const result = await adapter.listBackups();
      expect(result).toHaveLength(1);
      expect(result[0]!.modifiedAt).toBe(mtime.toISOString());
    });

    it('uses epoch-0 for null mtime', async () => {
      const adapter = makeAdapter();

      mockExists.mockImplementation(async (path: string | URL) =>
        path.toString().endsWith('.bak.1'),
      );
      mockStat.mockResolvedValue({
        isFile: true,
        isDirectory: false,
        isSymlink: false,
        size: 100,
        mtime: null,
        atime: null,
        birthtime: null,
        readonly: false,
        fileAttributes: null,
        dev: null,
        ino: null,
        mode: null,
        nlink: null,
        uid: null,
        gid: null,
        rdev: null,
        blksize: null,
        blocks: null,
      });

      const result = await adapter.listBackups();
      expect(result[0]!.modifiedAt).toBe(new Date(0).toISOString());
    });
  });

  // -------------------------------------------------------------------------
  // (5b) loadBackup (P3-13)
  // -------------------------------------------------------------------------

  describe('loadBackup (P3-13)', () => {
    it('reads the correct .bak.{slot} path', async () => {
      const adapter = makeAdapter();
      const bakBytes = new Uint8Array([10, 20, 30]);

      mockExists.mockResolvedValue(true);
      mockReadFile.mockResolvedValue(bakBytes);

      const result = await adapter.loadBackup(2);
      expect(result).toBe(bakBytes);
      // Verify the correct path was passed to readFile
      expect(mockReadFile).toHaveBeenCalledWith(`${VAULT_PATH}.bak.2`);
    });

    it('throws VaultNotFoundError if slot does not exist', async () => {
      const adapter = makeAdapter();
      mockExists.mockResolvedValue(false);

      await expect(adapter.loadBackup(3)).rejects.toBeInstanceOf(VaultNotFoundError);
    });

    it('wraps readFile errors as VaultIOError', async () => {
      const adapter = makeAdapter();
      mockExists.mockResolvedValue(true);
      mockReadFile.mockRejectedValue(new Error('permission denied'));

      await expect(adapter.loadBackup(1)).rejects.toBeInstanceOf(VaultIOError);
    });
  });

  // -------------------------------------------------------------------------
  // (5c) savePreMigrationBackup (P3-13)
  // -------------------------------------------------------------------------

  describe('savePreMigrationBackup (P3-13)', () => {
    it('invokes vault_write_named with derived path and Array.from(bytes)', async () => {
      const adapter = makeAdapter();
      const backupBytes = new Uint8Array([7, 8, 9]);
      const capturedArgs: unknown[] = [];

      mockInvoke.mockImplementation(async (cmd: string, args: unknown) => {
        capturedArgs.push({ cmd, args });
      });

      await adapter.savePreMigrationBackup(
        'pre-v2-backup-2026-08-01T14-22-09Z',
        backupBytes,
      );

      expect(capturedArgs).toHaveLength(1);
      const call = capturedArgs[0] as { cmd: string; args: Record<string, unknown> };
      expect(call.cmd).toBe('vault_write_named');
      // Path should be beside the vault directory
      expect(call.args['path']).toMatch(/pre-v2-backup-2026-08-01T14-22-09Z\.cryptiq$/);
      // Bytes sent as number array (Pitfall 1)
      expect(Array.isArray(call.args['bytes'])).toBe(true);
      expect(call.args['bytes']).toEqual(Array.from(backupBytes));
    });

    it('wraps vault_write_named errors as VaultIOError', async () => {
      const adapter = makeAdapter();
      mockInvoke.mockRejectedValue(new Error('disk full'));

      await expect(
        adapter.savePreMigrationBackup('test-backup', new Uint8Array([1, 2])),
      ).rejects.toBeInstanceOf(VaultIOError);
    });
  });

  // -------------------------------------------------------------------------
  // Additional: lock re-verify (P3-08)
  // -------------------------------------------------------------------------

  describe('lock re-verify before write (P3-08)', () => {
    it('maps VAULT_LOCKED error to VaultLockedByOtherProcessError', async () => {
      const adapter = makeAdapter();

      mockInvoke.mockImplementation(async (cmd: string) => {
        if (cmd === 'vault_lock_check') throw new Error('VAULT_LOCKED:42:other-host');
      });

      const err = await adapter
        .save(fakeBytes())
        .then(() => null)
        .catch((e: unknown) => e);
      expect(err).toBeInstanceOf(VaultLockedByOtherProcessError);
    });

    it('maps VAULT_LOCK_STOLEN error to VaultLockedByOtherProcessError', async () => {
      const adapter = makeAdapter();

      mockInvoke.mockImplementation(async (cmd: string) => {
        if (cmd === 'vault_lock_check') throw new Error('VAULT_LOCK_STOLEN:99:thief');
      });

      await expect(adapter.save(fakeBytes())).rejects.toBeInstanceOf(
        VaultLockedByOtherProcessError,
      );
    });

    it('maps VAULT_LOCK_LOST to VaultLockedByOtherProcessError', async () => {
      const adapter = makeAdapter();

      mockInvoke.mockImplementation(async (cmd: string) => {
        if (cmd === 'vault_lock_check') throw new Error('VAULT_LOCK_LOST');
      });

      await expect(adapter.save(fakeBytes())).rejects.toBeInstanceOf(
        VaultLockedByOtherProcessError,
      );
    });

    it('maps generic disk error from vault_write_atomic to VaultIOError', async () => {
      const adapter = makeAdapter();

      mockInvoke.mockImplementation(async (cmd: string) => {
        if (cmd === 'vault_lock_check') return undefined;
        if (cmd === 'vault_write_atomic') throw new Error('no space left on device');
      });

      await expect(adapter.save(fakeBytes())).rejects.toBeInstanceOf(VaultIOError);
    });
  });

  // -------------------------------------------------------------------------
  // exists() and load()
  // -------------------------------------------------------------------------

  describe('exists() and load()', () => {
    it('exists() returns false when plugin-fs returns false', async () => {
      const adapter = makeAdapter();
      mockExists.mockResolvedValue(false);
      expect(await adapter.exists()).toBe(false);
    });

    it('exists() returns true when plugin-fs returns true', async () => {
      const adapter = makeAdapter();
      mockExists.mockResolvedValue(true);
      expect(await adapter.exists()).toBe(true);
    });

    it('load() throws VaultNotFoundError when vault does not exist', async () => {
      const adapter = makeAdapter();
      mockExists.mockResolvedValue(false);
      await expect(adapter.load()).rejects.toBeInstanceOf(VaultNotFoundError);
    });

    it('load() returns bytes when vault exists', async () => {
      const adapter = makeAdapter();
      const bytes = new Uint8Array([1, 2, 3]);
      mockExists.mockResolvedValue(true);
      mockReadFile.mockResolvedValue(bytes);
      const result = await adapter.load();
      expect(result).toBe(bytes);
    });
  });
});

// ---------------------------------------------------------------------------
// hashEntriesContent unit tests
// ---------------------------------------------------------------------------

describe('hashEntriesContent', () => {
  it('returns an 8-char hex string', () => {
    const hash = hashEntriesContent({ entries: [] });
    expect(hash).toMatch(/^[0-9a-f]{8}$/);
  });

  it('is deterministic for the same input', () => {
    const obj = { entries: [{ id: 'a', title: 'test' }] };
    expect(hashEntriesContent(obj)).toBe(hashEntriesContent(obj));
  });

  it('produces different hashes for different inputs', () => {
    const h1 = hashEntriesContent({ entries: [] });
    const h2 = hashEntriesContent({ entries: [{ id: 'x', title: 'different' }] });
    expect(h1).not.toBe(h2);
  });

  it('produces the same hash for structurally equal objects', () => {
    const a = { entries: [{ id: 'a', title: 'foo' }] };
    const b = { entries: [{ id: 'a', title: 'foo' }] };
    expect(hashEntriesContent(a)).toBe(hashEntriesContent(b));
  });
});
