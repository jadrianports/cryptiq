// apps/desktop/src/lib/bridge/rpcDispatch.test.ts
//
// Phase 16 Plan 03 — rpcDispatch.ts coverage:
//   (a) idle-isolation regression (XSEC-05/D-12/T-16-03): a burst of RPC
//       traffic through the handler must NOT reset/extend the idle timer.
//   (b) locked path (D-09/XSEC-06): { code: 'vault-locked' }, no entry data.
//   (c) match-origin path (BRIDGE-08/FILL-03): { candidates: [...] }
//       metadata only — no candidate carries a `password` field.
//   (d) fill-entry path (BRIDGE-08/V4 access control): { secret } for a live
//       id, { code: 'not-found' } for soft-deleted/missing ids.
//
// Runs under the desktop node-env vitest config (vitest.config.ts,
// `src/**/*.test.ts`) — same suite as idle.test.ts. rpcDispatch.ts is a plain
// .ts module (not a .svelte component), so no browser-mode / vitest.browser
// infrastructure is required here.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { Entry } from '@cryptiq/core';

// ---------------------------------------------------------------------------
// Module mocks — must be hoisted (vi.mock calls are hoisted by Vitest).
// vi.hoisted() gives us a mutable state box the mock factories can close
// over (mirrors idle.test.ts's mock-per-test-case control).
// ---------------------------------------------------------------------------

const vaultState = vi.hoisted(() => ({
  isUnlocked: true,
  entries: [] as unknown[],
}));

const lockSpy = vi.hoisted(() => vi.fn().mockResolvedValue(undefined));

vi.mock('../state/vault.svelte', () => ({
  vaultSession: {
    get isUnlocked() {
      return vaultState.isUnlocked;
    },
    get vault() {
      return vaultState.isUnlocked ? { entries: { entries: vaultState.entries } } : null;
    },
    isSaving: false,
    isCriticalOpInProgress: false,
    lock: lockSpy,
  },
}));

vi.mock('../state/view.svelte', () => ({
  go: vi.fn(),
  setLockReason: vi.fn(),
  view: { current: 'main' },
}));

vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(),
}));

let capturedListenHandler: ((event: { payload: unknown }) => Promise<void>) | null = null;

vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn((_eventName: string, handler: (event: { payload: unknown }) => Promise<void>) => {
    capturedListenHandler = handler;
    return Promise.resolve(() => {});
  }),
}));

// Imports AFTER vi.mock() so we get the mocked modules.
import { invoke } from '@tauri-apps/api/core';
import { startIdleController, stopIdleController } from '../state/idle.svelte';
import { handleRpcRequest, registerRpcDispatch } from './rpcDispatch';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

let idCounter = 0;

/** Minimal Entry fixture builder (mirrors matchByOrigin.test.ts). */
function makeEntry(overrides: Partial<Entry> = {}): Entry {
  idCounter += 1;
  return {
    id: `entry-${idCounter}`,
    type: 'login',
    title: `Entry ${idCounter}`,
    username: `user${idCounter}`,
    password: `super-secret-${idCounter}`,
    url: 'example.com',
    notes: '',
    tags: [],
    favorite: false,
    needsSiteUpdate: false,
    generatorPreset: null,
    passwordHistory: [],
    createdAt: '2026-01-01T00:00:00.000Z',
    modifiedAt: '2026-01-01T00:00:00.000Z',
    deletedAt: null,
    ...overrides,
  };
}

describe('bridge/rpcDispatch — XSEC-05/D-12 idle isolation + BRIDGE-08/FILL-03 routing', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vaultState.isUnlocked = true;
    vaultState.entries = [];
    capturedListenHandler = null;
  });

  afterEach(() => {
    stopIdleController();
    vi.useRealTimers();
  });

  // -------------------------------------------------------------------------
  // (a) Idle-isolation regression (T-16-03 / XSEC-05 / D-12)
  // -------------------------------------------------------------------------

  it('a burst of RPC requests through the handler does NOT reset the idle timer', async () => {
    vi.useFakeTimers();
    const entry = makeEntry({ url: 'example.com' });
    vaultState.entries = [entry];

    startIdleController(1); // 1-minute idle timeout

    // Advance to 50s — no lock yet.
    await vi.advanceTimersByTimeAsync(50_000);
    expect(lockSpy).not.toHaveBeenCalled();

    // Fire a tight burst of N synthetic RPC requests DIRECTLY through the
    // handler (match-origin + fill-entry interleaved) — if the handler ever
    // touched idle.svelte.ts's resetTimer or dispatched a window event, this
    // burst would push the deadline out past the original 60s mark.
    for (let i = 0; i < 25; i += 1) {
      handleRpcRequest({
        requestId: `burst-${String(i)}`,
        method: 'match-origin',
        params: { origin: 'https://example.com' },
      });
      handleRpcRequest({
        requestId: `burst-fill-${String(i)}`,
        method: 'fill-entry',
        params: { entryId: entry.id },
      });
    }

    // Still no lock immediately after the burst (burst itself consumed 0
    // simulated time), and critically: the ORIGINAL 60s deadline (10s from
    // here) must still fire on schedule — proving the burst never reset it.
    expect(lockSpy).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(9_999);
    expect(lockSpy).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    expect(lockSpy).toHaveBeenCalledOnce();
  });

  // -------------------------------------------------------------------------
  // (b) Locked path (D-09 / XSEC-06)
  // -------------------------------------------------------------------------

  it('returns { code: "vault-locked" } with no entry data when the vault is locked', () => {
    vaultState.isUnlocked = false;
    vaultState.entries = [makeEntry({ url: 'example.com' })];

    const result = handleRpcRequest({
      requestId: 'r1',
      method: 'match-origin',
      params: { origin: 'https://example.com' },
    });

    expect(result).toEqual({ code: 'vault-locked' });
  });

  it('locked-vault fill-entry also returns { code: "vault-locked" }, never a secret', () => {
    const entry = makeEntry({ url: 'example.com' });
    vaultState.isUnlocked = false;
    vaultState.entries = [entry];

    const result = handleRpcRequest({
      requestId: 'r2',
      method: 'fill-entry',
      params: { entryId: entry.id },
    });

    expect(result).toEqual({ code: 'vault-locked' });
  });

  it('the full listener round trip replies via invoke("bridge_rpc_response", ...) with vault-locked', async () => {
    vaultState.isUnlocked = false;

    registerRpcDispatch();
    expect(capturedListenHandler).not.toBeNull();

    await capturedListenHandler!({
      payload: { requestId: 'r3', method: 'match-origin', params: { origin: 'https://example.com' } },
    });

    expect(invoke).toHaveBeenCalledWith('bridge_rpc_response', {
      requestId: 'r3',
      result: { code: 'vault-locked' },
    });
  });

  // -------------------------------------------------------------------------
  // (c) match-origin path (BRIDGE-08 / FILL-03)
  // -------------------------------------------------------------------------

  it('match-origin returns metadata-only candidates — no candidate carries a password field', () => {
    const entry = makeEntry({ url: 'example.com', title: 'Example', username: 'alice' });
    vaultState.entries = [entry];

    const result = handleRpcRequest({
      requestId: 'r4',
      method: 'match-origin',
      params: { origin: 'https://accounts.example.com/login' },
    }) as { candidates: Array<Record<string, unknown>> };

    expect(result.candidates).toHaveLength(1);
    expect(result.candidates[0]).toEqual({
      id: entry.id,
      title: 'Example',
      username: 'alice',
      domainHint: 'example.com',
    });
    for (const candidate of result.candidates) {
      expect('password' in candidate).toBe(false);
    }
  });

  it('match-origin returns an empty candidate list for a non-matching origin', () => {
    vaultState.entries = [makeEntry({ url: 'example.com' })];

    const result = handleRpcRequest({
      requestId: 'r5',
      method: 'match-origin',
      params: { origin: 'https://other-site.test' },
    });

    expect(result).toEqual({ candidates: [] });
  });

  // -------------------------------------------------------------------------
  // (d) fill-entry path (BRIDGE-08 / V4 access control)
  // -------------------------------------------------------------------------

  it('fill-entry returns exactly the requested secret for a live entry id', () => {
    const target = makeEntry({ url: 'example.com', password: 'target-secret' });
    const other = makeEntry({ url: 'example.com', password: 'decoy-secret' });
    vaultState.entries = [target, other];

    const result = handleRpcRequest({
      requestId: 'r6',
      method: 'fill-entry',
      params: { entryId: target.id },
    });

    expect(result).toEqual({ secret: 'target-secret' });
  });

  it('fill-entry returns { code: "not-found" } for a soft-deleted entry id', () => {
    const deleted = makeEntry({
      url: 'example.com',
      password: 'should-never-surface',
      deletedAt: '2026-02-01T00:00:00.000Z',
    });
    vaultState.entries = [deleted];

    const result = handleRpcRequest({
      requestId: 'r7',
      method: 'fill-entry',
      params: { entryId: deleted.id },
    });

    expect(result).toEqual({ code: 'not-found' });
  });

  it('fill-entry returns { code: "not-found" } for an unknown entry id', () => {
    vaultState.entries = [makeEntry({ url: 'example.com' })];

    const result = handleRpcRequest({
      requestId: 'r8',
      method: 'fill-entry',
      params: { entryId: 'does-not-exist' },
    });

    expect(result).toEqual({ code: 'not-found' });
  });

  // -------------------------------------------------------------------------
  // Invalid method
  // -------------------------------------------------------------------------

  it('an unrecognized method returns { code: "invalid-request" }', () => {
    const result = handleRpcRequest({
      requestId: 'r9',
      method: 'not-a-real-method',
      params: {},
    });

    expect(result).toEqual({ code: 'invalid-request' });
  });
});
