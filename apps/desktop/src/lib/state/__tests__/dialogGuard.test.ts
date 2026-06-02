// apps/desktop/src/lib/state/__tests__/dialogGuard.test.ts
//
// Fix-forward (import-auto-lock regression): native OS dialog guard tests.
//
// These tests pin the behavioral contract for `dialogGuard.svelte.ts`:
//   (a) checkAndLock (idle) DEFERS while the dialog guard is set.
//   (b) The dialog guard self-clears via its hard-bounded timeout (30s).
//   (c) The dialog guard self-clears on focus return AFTER a real blur; a
//       focus with no preceding blur does NOT clear it (premature-clear race).
//   (d) clearNativeDialogOpen() proactively clears the guard (on file-select).
//   (e) Genuine idle still locks when the guard is clear.
//   (f) The guard is idempotent — double-set, double-clear are safe.
//   (g) The focus-return listener is torn down when clearNativeDialogOpen() is
//       called manually (no double-fire on subsequent focus events).
//
// Mock strategy (mirrors idle.test.ts):
//   - @tauri-apps/api/core: vi.mock (dialogGuard has no Tauri calls, but the
//     import graph through idle/vault may need it; explicit mock is safe).
//   - vault.svelte: mock isSaving, isCriticalOpInProgress, lock().
//   - view.svelte: mock go(), setLockReason().
//   - vi.useFakeTimers() — deterministic timer + setTimeout control.
//
// Node environment (vitest.config.ts: environment: 'node').

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ---------------------------------------------------------------------------
// Module mocks — hoisted by Vitest.
// ---------------------------------------------------------------------------

vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(),
}));

vi.mock('../view.svelte', () => ({
  go: vi.fn(),
  setLockReason: vi.fn(),
  view: { current: 'main' },
}));

vi.mock('../vault.svelte', () => ({
  vaultSession: {
    lock: vi.fn().mockResolvedValue(undefined),
    isUnlocked: true,
    isSaving: false,
    isCriticalOpInProgress: false,
  },
}));

// Import mocked modules.
import { vaultSession } from '../vault.svelte';
import { go, setLockReason } from '../view.svelte';

// Import the dialog guard under test.
import {
  setNativeDialogOpen,
  clearNativeDialogOpen,
  isNativeDialogOpen,
} from '../dialogGuard.svelte';

// Import the idle controller to test defer integration.
import { startIdleController, stopIdleController } from '../idle.svelte';

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe('dialogGuard — native OS file-picker guard', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
    // Ensure guard is clean at the start of each test.
    clearNativeDialogOpen();
  });

  afterEach(() => {
    // Clean up guard + idle controller between tests.
    clearNativeDialogOpen();
    stopIdleController();
    vi.useRealTimers();
  });

  // -------------------------------------------------------------------------
  // (a) isNativeDialogOpen() basic get/set/clear
  // -------------------------------------------------------------------------

  it('isNativeDialogOpen() returns false by default', () => {
    expect(isNativeDialogOpen()).toBe(false);
  });

  it('setNativeDialogOpen() sets the guard to true', () => {
    setNativeDialogOpen();
    expect(isNativeDialogOpen()).toBe(true);
  });

  it('clearNativeDialogOpen() clears the guard to false', () => {
    setNativeDialogOpen();
    expect(isNativeDialogOpen()).toBe(true);
    clearNativeDialogOpen();
    expect(isNativeDialogOpen()).toBe(false);
  });

  // -------------------------------------------------------------------------
  // (b) Hard-bounded self-clear timeout (SECURITY_INVARIANT 4)
  // -------------------------------------------------------------------------

  it('guard self-clears after 30s hard timeout even with no focus or change event', async () => {
    setNativeDialogOpen();
    expect(isNativeDialogOpen()).toBe(true);

    // Just under the 30s threshold — guard must still be set.
    await vi.advanceTimersByTimeAsync(29_999);
    expect(isNativeDialogOpen()).toBe(true);

    // Cross the 30s threshold — guard must self-clear.
    await vi.advanceTimersByTimeAsync(1);
    expect(isNativeDialogOpen()).toBe(false);
  });

  it('no further timeout fires after self-clear (no double-fire)', async () => {
    setNativeDialogOpen();
    await vi.advanceTimersByTimeAsync(30_000); // self-clear fires
    expect(isNativeDialogOpen()).toBe(false);

    // Advancing again does not change the flag.
    await vi.advanceTimersByTimeAsync(60_000);
    expect(isNativeDialogOpen()).toBe(false);
  });

  // -------------------------------------------------------------------------
  // (c) Focus-return listener clears the guard — but ONLY after a real blur
  //     (covers dialog cancel/return; closes the premature-clear race)
  // -------------------------------------------------------------------------

  it('guard clears on focus AFTER a blur (genuine dialog return/cancel path)', () => {
    setNativeDialogOpen();
    expect(isNativeDialogOpen()).toBe(true);

    // OS dialog opened → window blurs; dismissed → window regains focus.
    window.dispatchEvent(new Event('blur'));
    window.dispatchEvent(new Event('focus'));

    expect(isNativeDialogOpen()).toBe(false);
  });

  it('REGRESSION: a focus with NO preceding blur does NOT clear the guard', () => {
    // Repro of the premature-clear race: clicking <input type=file> can focus
    // the input WITHIN the webview before the OS dialog steals focus. That
    // focus must NOT clear the guard, or the blur-lock fires when the dialog
    // finally opens (re-exposing the original import re-lock bug).
    setNativeDialogOpen();
    expect(isNativeDialogOpen()).toBe(true);

    window.dispatchEvent(new Event('focus')); // no prior blur
    expect(isNativeDialogOpen()).toBe(true); // guard MUST still be set

    // A genuine blur→focus round-trip still clears it.
    window.dispatchEvent(new Event('blur'));
    window.dispatchEvent(new Event('focus'));
    expect(isNativeDialogOpen()).toBe(false);
  });

  it('focus-return is one-shot per set: re-set re-arms a fresh blur→focus clear', () => {
    setNativeDialogOpen();
    window.dispatchEvent(new Event('blur'));
    window.dispatchEvent(new Event('focus')); // clears guard
    expect(isNativeDialogOpen()).toBe(false);

    // Re-set the guard — a NEW blur listener is armed.
    setNativeDialogOpen();
    expect(isNativeDialogOpen()).toBe(true);

    window.dispatchEvent(new Event('blur'));
    window.dispatchEvent(new Event('focus'));
    expect(isNativeDialogOpen()).toBe(false);
  });

  // -------------------------------------------------------------------------
  // (d) clearNativeDialogOpen() tears down the timeout + focus listener
  // -------------------------------------------------------------------------

  it('clearNativeDialogOpen() cancels the hard-timeout — no self-clear fires after manual clear', async () => {
    setNativeDialogOpen();
    clearNativeDialogOpen();
    expect(isNativeDialogOpen()).toBe(false);

    // Advancing past the 30s threshold fires nothing (timeout was torn down).
    await vi.advanceTimersByTimeAsync(60_000);
    expect(isNativeDialogOpen()).toBe(false);
  });

  it('clearNativeDialogOpen() tears down handlers — a stale blur/focus does not affect a freshly set guard', () => {
    setNativeDialogOpen();
    window.dispatchEvent(new Event('blur')); // arms the focus listener
    clearNativeDialogOpen(); // tears down blur + focus listeners + timeout

    // Re-set the guard (fresh blur listener; focus not yet armed).
    setNativeDialogOpen();
    expect(isNativeDialogOpen()).toBe(true);

    // A focus with no NEW blur must not clear (race closed) and the torn-down
    // old focus listener must not fire either.
    window.dispatchEvent(new Event('focus'));
    expect(isNativeDialogOpen()).toBe(true);

    // Proper blur→focus on the new guard clears it.
    window.dispatchEvent(new Event('blur'));
    window.dispatchEvent(new Event('focus'));
    expect(isNativeDialogOpen()).toBe(false);
  });

  // -------------------------------------------------------------------------
  // (e) Idle lock DEFERS while guard is set (SECURITY_INVARIANT 1)
  // -------------------------------------------------------------------------

  it('checkAndLock DEFERS while dialog guard is set — lock does not fire at idle deadline', async () => {
    startIdleController(1); // 1-minute idle timeout

    // Let the idle timer expire.
    await vi.advanceTimersByTimeAsync(59_999);
    expect(vaultSession.lock).not.toHaveBeenCalled();

    // Set the dialog guard just before the deadline.
    setNativeDialogOpen();

    // The idle deadline passes — but the guard is set so lock is DEFERRED.
    await vi.advanceTimersByTimeAsync(1); // idle expires at 60s
    // The 500ms retry fires, but the guard is still set.
    await vi.advanceTimersByTimeAsync(499);
    expect(vaultSession.lock).not.toHaveBeenCalled();

    // Now clear the guard — on the next retry the lock fires.
    clearNativeDialogOpen();
    await vi.advanceTimersByTimeAsync(1); // fire the pending 500ms retry
    expect(vaultSession.lock).toHaveBeenCalledOnce();
    expect(setLockReason).toHaveBeenCalledWith('idle');
    expect(go).toHaveBeenCalledWith('unlock');
  });

  it('idle lock DEFERS on the 500ms retry loop while guard is set, then fires immediately once the guard clears', async () => {
    startIdleController(1);

    // Let the idle expire.
    await vi.advanceTimersByTimeAsync(60_000);
    // Guard is clear → lock fires on the first check.
    expect(vaultSession.lock).toHaveBeenCalledOnce();
  });

  // -------------------------------------------------------------------------
  // (f) Genuine idle locks when guard is clear (SECURITY_INVARIANT 1 — not broken)
  // -------------------------------------------------------------------------

  it('genuine idle lock fires normally when the guard is NOT set', async () => {
    startIdleController(1);

    await vi.advanceTimersByTimeAsync(60_000);
    expect(vaultSession.lock).toHaveBeenCalledOnce();
    expect(setLockReason).toHaveBeenCalledWith('idle');
    expect(go).toHaveBeenCalledWith('unlock');
  });

  // -------------------------------------------------------------------------
  // (g) Guard idempotency — double-set, double-clear are safe
  // -------------------------------------------------------------------------

  it('setNativeDialogOpen() is idempotent — double-set resets the timeout from scratch', async () => {
    setNativeDialogOpen();
    // Advance halfway through the 30s timeout.
    await vi.advanceTimersByTimeAsync(20_000);
    expect(isNativeDialogOpen()).toBe(true);

    // Re-arm — the 30s timeout resets from NOW.
    setNativeDialogOpen();
    expect(isNativeDialogOpen()).toBe(true);

    // Advance the remaining 10s (to where the FIRST timeout would have fired).
    // The re-armed timeout still has 30s from here → guard must still be set.
    await vi.advanceTimersByTimeAsync(10_000);
    expect(isNativeDialogOpen()).toBe(true);

    // Advance the full 30s from the re-arm → guard self-clears.
    await vi.advanceTimersByTimeAsync(20_000); // now 30s past the second set
    expect(isNativeDialogOpen()).toBe(false);
  });

  it('clearNativeDialogOpen() is idempotent — calling when not active is safe', () => {
    expect(() => {
      clearNativeDialogOpen();
      clearNativeDialogOpen();
      clearNativeDialogOpen();
    }).not.toThrow();
    expect(isNativeDialogOpen()).toBe(false);
  });
});
