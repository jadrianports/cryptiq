// apps/desktop/src/lib/state/__tests__/clipboardGuard.test.ts
//
// Phase 5 — LOCK-02 / P5-08: single-owner clipboard auto-clear guard tests.
//
// These tests pin the secret-lifetime fix: the authoritative clipboard auto-clear
// now lives in a module-level guard (state/clipboardGuard.svelte.ts), NOT inside
// ClipboardToast.svelte's per-second $effect. The OLD bug: when the toast's host
// component unmounted on ordinary in-app navigation (selecting another entry,
// going to Settings/Generator, advancing past the recovery-key wizard step), the
// component's $effect cleanup did clearInterval WITHOUT clipboard_clear_if_ours —
// so the secret stayed on the live OS clipboard past clearSeconds.
//
// THE KEY ASSERTION (proves the unmount fix): arming the guard then advancing time
// fires clipboard_clear_if_ours from the module-level setTimeout with NO Svelte
// component mounted at all. This file imports NO component — only the guard module.
//
// Mock strategy (mirrors saveMutex.test.ts / idle.test.ts):
//   - @tauri-apps/api/core: vi.mock with a controllable invoke stub.
//   - vi.useFakeTimers() — deterministic timer control.
//
// Node environment (vitest.config.ts: environment: 'node'). No Svelte component,
// no browser suite.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ---------------------------------------------------------------------------
// Module mocks — hoisted by Vitest.
// ---------------------------------------------------------------------------

// Mock @tauri-apps/api/core — the guard imports invoke() for the Rust clear call.
// This both prevents a Tauri runtime error in node AND lets us assert the call.
vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn().mockResolvedValue(undefined),
}));

// Import the mocked module AFTER vi.mock() so we get the stub.
import { invoke } from '@tauri-apps/api/core';

// Import the guard under test — NO component is imported (the whole point).
import {
  clipboardClear,
  armClipboardClear,
  cancelClipboardClear,
} from '../clipboardGuard.svelte';

const mockInvoke = vi.mocked(invoke);

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe('clipboard auto-clear guard — LOCK-02 / P5-08', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
    mockInvoke.mockResolvedValue(undefined);
  });

  afterEach(() => {
    // Tear down any pending guard timer so it can't leak into the next test.
    cancelClipboardClear();
    vi.useRealTimers();
  });

  // -------------------------------------------------------------------------
  // (1) THE KEY ASSERTION — module-level clear fires with NO component mounted
  // -------------------------------------------------------------------------

  it('armClipboardClear(25): advancing 25s fires clipboard_clear_if_ours EXACTLY once and resets active=false — from the module timer, NO component mounted', async () => {
    armClipboardClear(25);

    // Armed state is reflected immediately.
    expect(clipboardClear.active).toBe(true);
    expect(clipboardClear.total).toBe(25);
    expect(clipboardClear.remaining).toBe(25);

    // Just before the deadline — the clear must NOT have fired yet.
    await vi.advanceTimersByTimeAsync(24_999);
    expect(mockInvoke).not.toHaveBeenCalled();
    expect(clipboardClear.active).toBe(true);

    // Cross the 25s deadline — the AUTHORITATIVE module-level setTimeout fires.
    // No Svelte component exists in this test; the clear still happens.
    await vi.advanceTimersByTimeAsync(1);

    expect(mockInvoke).toHaveBeenCalledTimes(1);
    expect(mockInvoke).toHaveBeenCalledWith('clipboard_clear_if_ours');
    // State reset to inactive after the clear.
    expect(clipboardClear.active).toBe(false);
    expect(clipboardClear.remaining).toBe(0);
  });

  it('the 1s countdown interval decrements remaining for the display', async () => {
    armClipboardClear(25);
    expect(clipboardClear.remaining).toBe(25);

    await vi.advanceTimersByTimeAsync(1000);
    expect(clipboardClear.remaining).toBe(24);

    await vi.advanceTimersByTimeAsync(5000);
    expect(clipboardClear.remaining).toBe(19);
  });

  // -------------------------------------------------------------------------
  // (2) cancelClipboardClear() before the timeout — no clear, inactive
  // -------------------------------------------------------------------------

  it('cancelClipboardClear() before the timeout: clipboard_clear_if_ours is NOT called; active=false', async () => {
    armClipboardClear(25);
    expect(clipboardClear.active).toBe(true);

    // Advance partway, then cancel.
    await vi.advanceTimersByTimeAsync(10_000);
    cancelClipboardClear();

    expect(clipboardClear.active).toBe(false);
    expect(clipboardClear.remaining).toBe(0);
    expect(clipboardClear.total).toBe(0);

    // Advance well past the original deadline — the authoritative timer was torn
    // down, so nothing fires. (cancel itself does NOT invoke — the lock() caller
    // owns the actual Rust clear.)
    await vi.advanceTimersByTimeAsync(60_000);
    expect(mockInvoke).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // (3) Re-arm mid-countdown cancels the prior timer (only ONE clear fires)
  // -------------------------------------------------------------------------

  it('re-arming mid-countdown cancels the prior timer (only ONE clear fires, at the NEW deadline) and resets remaining', async () => {
    armClipboardClear(25);

    // Advance 10s into the first countdown.
    await vi.advanceTimersByTimeAsync(10_000);
    expect(clipboardClear.remaining).toBe(15);
    expect(mockInvoke).not.toHaveBeenCalled();

    // Re-arm with a fresh 25s — must cancel the prior timer and reset remaining.
    armClipboardClear(25);
    expect(clipboardClear.remaining).toBe(25);
    expect(clipboardClear.active).toBe(true);

    // Advance to where the ORIGINAL deadline would have been (25s from t=0 → 15s
    // more from here). The prior timer was cancelled, so STILL no clear.
    await vi.advanceTimersByTimeAsync(15_000);
    expect(mockInvoke).not.toHaveBeenCalled();

    // Advance the remaining 10s to reach the NEW deadline (25s from re-arm).
    await vi.advanceTimersByTimeAsync(10_000);

    // EXACTLY ONE clear — fired at the new deadline, not the old one.
    expect(mockInvoke).toHaveBeenCalledTimes(1);
    expect(mockInvoke).toHaveBeenCalledWith('clipboard_clear_if_ours');
    expect(clipboardClear.active).toBe(false);
  });

  // -------------------------------------------------------------------------
  // (4) No timer leak — arming twice then cancelling leaves no pending timer
  // -------------------------------------------------------------------------

  it('no timer leak: arming twice then cancelling leaves no pending timer (advancing time after cancel fires nothing)', async () => {
    armClipboardClear(25);
    await vi.advanceTimersByTimeAsync(5_000);

    // Second arm replaces the first (re-arm clears the prior handle).
    armClipboardClear(25);
    await vi.advanceTimersByTimeAsync(5_000);

    // Cancel — both the interval and the authoritative timeout must be torn down.
    cancelClipboardClear();
    expect(clipboardClear.active).toBe(false);

    // Advancing far past any deadline fires nothing — proves no orphaned timer
    // survived either the re-arm or the cancel.
    await vi.advanceTimersByTimeAsync(120_000);
    expect(mockInvoke).not.toHaveBeenCalled();
  });

  it('cancelClipboardClear() is idempotent and safe to call when nothing is armed', () => {
    // No arm — cancelling should not throw and should leave inactive state.
    expect(() => {
      cancelClipboardClear();
      cancelClipboardClear();
    }).not.toThrow();
    expect(clipboardClear.active).toBe(false);
    expect(clipboardClear.remaining).toBe(0);
  });
});
