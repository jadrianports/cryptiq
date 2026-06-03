// apps/desktop/src/lib/state/__tests__/hotData.test.ts
//
// Wave-0 RED scaffold — Plan 05-01, Task 3 (consumed by Plan 05-03).
//
// LOCK-05: HMR-clear on lock — import.meta.hot.data reset.
//
// These tests assert that:
//   (a) After vaultSession.lock() runs in a context where import.meta.hot is truthy,
//       import.meta.hot.data has been reset to an empty object.
//   (b) lock() teardown does NOT throw when import.meta.hot is undefined (production guard).
//
// These tests are intentionally RED until Plan 05-03 adds the import.meta.hot.data reset
// to the lock() teardown. Discovery is the Wave-0 bar.
//
// Mock strategy (mirrors saveMutex.test.ts exactly):
//   - @tauri-apps/api/core: vi.mock with a controllable invoke stub.
//   - import.meta.hot: stubbed per-test via vi.stubGlobal / Object.defineProperty on import.meta.
//   - No real Tauri runtime, no WASM.
//
// Node environment (vitest.config.ts: environment: 'node').

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ---------------------------------------------------------------------------
// Module mocks
// ---------------------------------------------------------------------------

vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(),
}));

import { invoke } from '@tauri-apps/api/core';
const mockInvoke = vi.mocked(invoke);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Plan 05-03 HMR seam: import _setHotForTesting from vault.svelte to wire the
// mock hot reference into lock(). In Vitest node environment, import.meta is
// module-local (not shared), so the test seam bridges the gap between the test
// file's import.meta.hot stub and vault.svelte.ts's lock() implementation.
import { _setHotForTesting } from '../vault.svelte';

/**
 * Stub import.meta.hot with a fake HMR context.
 * In production (tauri build), import.meta.hot is undefined.
 * In dev (pnpm tauri dev), Vite provides a truthy HMR handle.
 *
 * We simulate the dev case by assigning a fake object to import.meta.hot.
 * Vitest runs in Node, so import.meta.hot is undefined by default — we stub it.
 *
 * Plan 05-03 seam: also injects the hotMock into vault.svelte.ts's
 * `_hotRef` via `_setHotForTesting`, since Vitest node env does NOT share
 * `import.meta` across modules. The restore() call clears the seam.
 */
function stubHotData(dataPayload: Record<string, unknown>): {
  hotMock: { data: Record<string, unknown> };
  restore: () => void;
} {
  const hotMock = { data: dataPayload };
  // Set on the test file's import.meta.hot (documents the intent).
  const originalHot = (import.meta as { hot?: unknown }).hot;
  (import.meta as { hot?: unknown }).hot = hotMock;
  // Wire into vault.svelte.ts's _hotRef via the Plan 05-03 seam.
  _setHotForTesting(hotMock);
  return {
    hotMock,
    restore: () => {
      (import.meta as { hot?: unknown }).hot = originalHot;
      _setHotForTesting(null);
    },
  };
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe('HMR-clear on lock — LOCK-05', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockInvoke.mockResolvedValue(undefined);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // -------------------------------------------------------------------------
  // (a) import.meta.hot.data is reset to {} after lock() in dev
  // -------------------------------------------------------------------------

  it('lock() resets import.meta.hot.data to {} when import.meta.hot is truthy (dev mode)', async () => {
    // Stub import.meta.hot with pre-existing HMR data.
    const { hotMock, restore } = stubHotData({
      vaultKey: new Uint8Array(32), // simulates HMR-persisted vault key
      someState: 'persisted-across-hmr',
    });

    try {
      // Verify precondition: hot.data has content.
      expect(Object.keys(hotMock.data).length).toBeGreaterThan(0);

      // Import and mount a fake session.
      const { vaultSession } = await import('../vault.svelte');
      const fakeVaultKey = new Uint8Array(32).fill(0x50);
      const fakeVault = {
        doc: {
          format: 'cryptiq-vault' as const,
          version: 1 as const,
          wrappedKeys: {
            master: { ciphertext: '', nonce: '', kdf: { algorithm: 2 as const, opsLimit: 3, memLimit: 268_435_456, salt: '' } },
          },
          data: { ciphertext: '', nonce: '' },
          meta: { createdAt: new Date().toISOString(), modifiedAt: new Date().toISOString() },
        },
        entries: { schemaVersion: 1, entries: [], settings: { generator: { mode: 'random' as const, length: 20, useUppercase: true, useLowercase: true, useNumbers: true, useSymbols: false, customSymbols: null, excludeAmbiguous: true } } },
      };
      vaultSession.mount(fakeVault, fakeVaultKey);

      // Lock the session — this should clear import.meta.hot.data.
      await vaultSession.lock();

      // LOCK-05: After lock(), import.meta.hot.data must be an empty object.
      // The lock() teardown adds: if (import.meta.hot) { import.meta.hot.data = {}; }
      // Until Plan 05-03 adds this, hotMock.data will still have its old content → RED.
      expect(hotMock.data).toEqual({});
    } finally {
      restore();
    }
  });

  // -------------------------------------------------------------------------
  // (b) lock() does NOT throw when import.meta.hot is undefined (production)
  // -------------------------------------------------------------------------

  it('lock() does NOT throw when import.meta.hot is undefined (production guard)', async () => {
    // In production (pnpm tauri build), Vite strips HMR and import.meta.hot is undefined.
    // The lock() teardown guard: if (import.meta.hot) { ... } must handle this gracefully.

    // Ensure import.meta.hot is undefined for this test.
    const originalHot = (import.meta as { hot?: unknown }).hot;
    (import.meta as { hot?: unknown }).hot = undefined;

    try {
      const { vaultSession } = await import('../vault.svelte');
      const fakeVaultKey = new Uint8Array(32).fill(0x51);
      const fakeVault = {
        doc: {
          format: 'cryptiq-vault' as const,
          version: 1 as const,
          wrappedKeys: {
            master: { ciphertext: '', nonce: '', kdf: { algorithm: 2 as const, opsLimit: 3, memLimit: 268_435_456, salt: '' } },
          },
          data: { ciphertext: '', nonce: '' },
          meta: { createdAt: new Date().toISOString(), modifiedAt: new Date().toISOString() },
        },
        entries: { schemaVersion: 1, entries: [], settings: { generator: { mode: 'random' as const, length: 20, useUppercase: true, useLowercase: true, useNumbers: true, useSymbols: false, customSymbols: null, excludeAmbiguous: true } } },
      };
      vaultSession.mount(fakeVault, fakeVaultKey);

      // Should not throw even with hot === undefined.
      await expect(vaultSession.lock()).resolves.toBeUndefined();
    } finally {
      (import.meta as { hot?: unknown }).hot = originalHot;
    }
  });

  // -------------------------------------------------------------------------
  // Additional: verify import.meta.hot contract (the testers document expectation)
  // -------------------------------------------------------------------------

  it('import.meta.hot stub works correctly in node test environment', () => {
    // Meta-test: confirm our stub mechanism works so Plan 05-03 can trust the harness.
    const { hotMock, restore } = stubHotData({ testKey: 'testValue' });
    try {
      expect((import.meta as { hot?: unknown }).hot).toBe(hotMock);
      expect(hotMock.data).toEqual({ testKey: 'testValue' });

      // Simulate what lock() teardown does (clear IN PLACE — import.meta.hot.data
      // is getter-only on the real Vite HMRContext, so it is mutated, not reassigned).
      const hot = (import.meta as { hot?: { data: Record<string, unknown> } }).hot;
      if (hot?.data) {
        for (const k of Object.keys(hot.data)) delete hot.data[k];
      }

      expect(hotMock.data).toEqual({});
    } finally {
      restore();
    }
  });

  // -------------------------------------------------------------------------
  // (c) lock() does NOT throw when import.meta.hot.data is GETTER-ONLY —
  //     reproduces the real Vite HMRContext. Regression guard for the
  //     "Cannot set property data of #<HMRContext> which has only a getter"
  //     dev-lock bug: the plain-object seam used by (a) could not catch it.
  // -------------------------------------------------------------------------

  it('lock() clears HMR data without throwing when import.meta.hot.data is getter-only (real Vite HMRContext shape)', async () => {
    const backingData: Record<string, unknown> = {
      vaultKey: new Uint8Array(32),
      someState: 'persisted-across-hmr',
    };
    const hotMock = {} as { data: Record<string, unknown> };
    // Getter-only `data` (no setter) — assigning hotMock.data throws, exactly
    // like Vite's live HMRContext. The contents stay mutable (the Vite contract).
    Object.defineProperty(hotMock, 'data', {
      get() {
        return backingData;
      },
      enumerable: true,
      configurable: true,
    });
    _setHotForTesting(hotMock);

    try {
      const { vaultSession } = await import('../vault.svelte');
      const fakeVaultKey = new Uint8Array(32).fill(0x52);
      const fakeVault = {
        doc: {
          format: 'cryptiq-vault' as const,
          version: 1 as const,
          wrappedKeys: {
            master: { ciphertext: '', nonce: '', kdf: { algorithm: 2 as const, opsLimit: 3, memLimit: 268_435_456, salt: '' } },
          },
          data: { ciphertext: '', nonce: '' },
          meta: { createdAt: new Date().toISOString(), modifiedAt: new Date().toISOString() },
        },
        entries: { schemaVersion: 1, entries: [], settings: { generator: { mode: 'random' as const, length: 20, useUppercase: true, useLowercase: true, useNumbers: true, useSymbols: false, customSymbols: null, excludeAmbiguous: true } } },
      };
      vaultSession.mount(fakeVault, fakeVaultKey);

      // Must NOT throw — the prior `hot.data = {}` reassignment threw here.
      await expect(vaultSession.lock()).resolves.toBeUndefined();

      // Security intent preserved: HMR-persisted data wiped in place.
      expect(Object.keys(backingData).length).toBe(0);
    } finally {
      _setHotForTesting(null);
    }
  });
});
