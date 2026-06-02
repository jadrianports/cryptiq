// apps/desktop/src/lib/state/__tests__/idle.test.ts
//
// Wave-0 RED scaffold — Plan 05-01, Task 3 (consumed by Plan 05-03).
//
// LOCK-01: Idle controller unit tests.
//
// These tests define the BEHAVIORAL CONTRACT for the `idle.svelte.ts` module that
// Plan 05-03 will create. They are intentionally RED until that plan lands — the
// test file's DISCOVERY by Vitest is the Wave-0 deliverable; GREEN is Plan 05-03's job.
//
// Contracts asserted:
//   (a) startIdleController('never') arms NO timer — advancing time does not lock.
//   (b) startIdleController(1) fires vaultSession.lock() after 60_000ms of no activity.
//   (c) Dispatching pointermove/keydown before expiry resets the timer (no lock at deadline).
//   (d) cancelIdleTimer() prevents the pending lock.
//
// Mock strategy (mirrors saveMutex.test.ts):
//   - @tauri-apps/api/core: vi.mock with a controllable invoke stub.
//   - vaultSession.lock: vi.spyOn — asserts when the idle lock fires.
//   - go / setLockReason: module-level mocks — verify view transitions.
//   - vi.useFakeTimers() — deterministic timer control.
//
// Node environment (vitest.config.ts: environment: 'node').
// Do NOT import Svelte components or use the browser suite.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ---------------------------------------------------------------------------
// Module mocks — must be hoisted (vi.mock calls are hoisted by Vitest)
// ---------------------------------------------------------------------------

// Mock @tauri-apps/api/core — the idle controller imports invoke() for any
// Rust event calls. This prevents Tauri runtime errors in node environment.
vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(),
}));

// Mock the view module — the idle controller calls go('unlock') and setLockReason.
vi.mock('../view.svelte', () => ({
  go: vi.fn(),
  setLockReason: vi.fn(),
  view: { current: 'main' },
}));

// Mock the vault session — we spy on lock() to verify it fires (or doesn't).
vi.mock('../vault.svelte', () => ({
  vaultSession: {
    lock: vi.fn().mockResolvedValue(undefined),
    isUnlocked: true,
    isSaving: false,
    isCriticalOpInProgress: false,
  },
}));

// Import the mocked modules AFTER vi.mock() so we get the stubs.
import { vaultSession } from '../vault.svelte';
import { go, setLockReason } from '../view.svelte';

// Import the Plan-05-03 surfaces — created by Plan 05-03 (this plan).
// The @ts-expect-error directive from the Wave-0 RED scaffold is removed now
// that idle.svelte.ts exists and exports these functions.
import { startIdleController, cancelIdleTimer, stopIdleController } from '../idle.svelte';

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe('idle controller — LOCK-01', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
  });

  afterEach(() => {
    // Ensure the idle controller is stopped between tests.
    stopIdleController();
    vi.useRealTimers();
  });

  // -------------------------------------------------------------------------
  // (a) 'never' arms no timer
  // -------------------------------------------------------------------------

  it("startIdleController('never') arms NO timer — advancing time does not lock", async () => {
    startIdleController('never');

    // Advance far past any reasonable idle timeout.
    await vi.advanceTimersByTimeAsync(10 * 60 * 1000); // 10 minutes

    // lock() must NEVER have been called.
    expect(vaultSession.lock).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // (b) startIdleController(1) fires lock() after 60_000ms with no activity
  // -------------------------------------------------------------------------

  it('startIdleController(1) fires vaultSession.lock() after 60_000ms of no activity', async () => {
    startIdleController(1); // 1-minute idle timeout

    // Advance just under the timeout — no lock should have fired yet.
    await vi.advanceTimersByTimeAsync(59_999);
    expect(vaultSession.lock).not.toHaveBeenCalled();

    // Advance past the deadline.
    await vi.advanceTimersByTimeAsync(1);
    expect(vaultSession.lock).toHaveBeenCalledOnce();
    expect(setLockReason).toHaveBeenCalledWith('idle');
    expect(go).toHaveBeenCalledWith('unlock');
  });

  // -------------------------------------------------------------------------
  // (c) Activity event resets the timer
  // -------------------------------------------------------------------------

  it('dispatching pointermove before expiry resets the timer (lock does NOT fire at the original deadline)', async () => {
    startIdleController(1); // 1-minute idle timeout

    // Advance to 50s — no lock yet.
    await vi.advanceTimersByTimeAsync(50_000);
    expect(vaultSession.lock).not.toHaveBeenCalled();

    // Simulate user activity — dispatch a pointermove event on the window.
    window.dispatchEvent(new Event('pointermove', { bubbles: true }));

    // Advance another 59s from the activity event — still under 60s.
    await vi.advanceTimersByTimeAsync(59_000);
    expect(vaultSession.lock).not.toHaveBeenCalled();

    // Now the original deadline (50+10=60s from start) has passed, but the timer
    // was RESET at 50s → lock fires 60s AFTER the activity (at 110s from start).
    // We've only advanced 50+59=109s, so still no lock.
    expect(vaultSession.lock).not.toHaveBeenCalled();
  });

  it('dispatching keydown before expiry resets the timer', async () => {
    startIdleController(1);

    await vi.advanceTimersByTimeAsync(30_000); // 30s
    window.dispatchEvent(new Event('keydown', { bubbles: true }));

    // 31s since reset — well within the 60s window after keydown.
    await vi.advanceTimersByTimeAsync(31_000);
    expect(vaultSession.lock).not.toHaveBeenCalled();

    // Complete the 60s from the keydown activity.
    await vi.advanceTimersByTimeAsync(29_000);
    expect(vaultSession.lock).toHaveBeenCalledOnce();
  });

  // -------------------------------------------------------------------------
  // (d) cancelIdleTimer() prevents the pending lock
  // -------------------------------------------------------------------------

  it('cancelIdleTimer() prevents the pending lock', async () => {
    startIdleController(1);

    // Advance to 50s — approaching deadline.
    await vi.advanceTimersByTimeAsync(50_000);
    expect(vaultSession.lock).not.toHaveBeenCalled();

    // Cancel the timer.
    cancelIdleTimer();

    // Advance past the deadline.
    await vi.advanceTimersByTimeAsync(20_000);

    // lock() must NOT have fired — timer was cancelled.
    expect(vaultSession.lock).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // Edge cases
  // -------------------------------------------------------------------------

  it('stopIdleController() cleans up event listeners and clears the timer', async () => {
    startIdleController(1);

    await vi.advanceTimersByTimeAsync(30_000);
    stopIdleController();

    // Advance well past the deadline — no lock because controller is stopped.
    await vi.advanceTimersByTimeAsync(60_000);
    expect(vaultSession.lock).not.toHaveBeenCalled();
  });

  it('calling startIdleController twice replaces the previous controller (no double-lock)', async () => {
    startIdleController(1); // First controller

    await vi.advanceTimersByTimeAsync(50_000);

    // Start a new controller — must cancel the previous one.
    startIdleController(1);

    // Advance 60s from the NEW start — first controller's deadline (50+10=60s) passes.
    // Only the NEW controller should eventually fire.
    await vi.advanceTimersByTimeAsync(60_000);

    // lock() should have been called ONCE (by the second controller).
    expect(vaultSession.lock).toHaveBeenCalledOnce();
  });
});
