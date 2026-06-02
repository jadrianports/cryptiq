// apps/desktop/src/lib/state/idle.svelte.ts
//
// Phase 5 — LOCK-01: Pure rune idle-controller module.
//
// Manages the in-window idle timeout that auto-locks the vault after the
// configured number of minutes of user inactivity.
//
// Module shape: mirrors ui.svelte.ts — module-level `let` for non-reactive
// state (timer handles), exported functions, NO class. Pure rune module.
//
// RULES (CLAUDE.md + LOCK-04 / Pitfall 7):
//   - NO @tauri-apps/* imports — this module holds no IO.
//   - NO @cryptiq/core imports — pure presenter-layer controller.
//   - Idle = ONLY in-window events ('pointermove', 'keydown', 'focus') reset
//     the timer. Background activity does NOT reset it.
//   - startIdleController MUST be called ONLY after the vault is unlocked
//     (vaultSession.isUnlocked === true). Never call at module top-level or
//     in the boot .then() before any unlock (Pitfall 7 defense — the caller
//     in App.svelte enforces this via an isUnlocked $effect).
//   - LOCK-04: Before firing lock(), check isSaving || isCriticalOpInProgress;
//     if either is true, defer by re-arming a short retry (~500ms).
//   - 'never': arms NO timer (but sleep/close lock-events still work because
//     those are wired independently in App.svelte).
//   - startIdleController is idempotent: always calls stopIdleController()
//     first so double-start never creates two active controllers.

import { vaultSession } from './vault.svelte';
import { go, setLockReason } from './view.svelte';
// Fix-forward (import-auto-lock regression): defer idle lock while an
// app-initiated native OS dialog is open (file-picker false-positive).
// Static import is safe: dialogGuard does NOT import idle (no cycle).
import { isNativeDialogOpen } from './dialogGuard.svelte';

// ---------------------------------------------------------------------------
// Module-level state (non-reactive — timer handles are not secret/UI data).
// Using bare `let` (not $state) because no component needs to react to the
// timer handle value itself. The Svelte Pitfall-7 defense: no deep proxy on
// non-UI implementation details.
// ---------------------------------------------------------------------------

/** The active idle expiry timer, or null if not armed. */
let idleTimer: ReturnType<typeof setTimeout> | null = null;

/**
 * Cleanup function returned by the most recent startIdleController call.
 * Cancels the timer + removes window event listeners.
 */
let _cleanup: (() => void) | null = null;

// ---------------------------------------------------------------------------
// Exported controller API
// ---------------------------------------------------------------------------

/**
 * Start the idle controller with the given timeout.
 *
 * LOCK-01: Listens to ['pointermove', 'keydown', 'focus'] window events
 * (capture + passive) and resets the timeout on each. On expiry, checks the
 * LOCK-04 guard (isSaving || isCriticalOpInProgress) — if either is true,
 * re-arms a short 500ms retry instead of locking immediately.
 *
 * @param idleMinutes  Minutes of inactivity before locking. Pass 'never' to
 *                     arm no timer (sleep/close listeners still work).
 * @returns A cleanup function. Also stored internally; stopIdleController()
 *          calls it. Callers from App.svelte should use stopIdleController().
 */
export function startIdleController(idleMinutes: number | 'never'): () => void {
  // Idempotent: tear down any prior controller before starting a new one.
  stopIdleController();

  if (idleMinutes === 'never') {
    // No timer; return a no-op cleanup.
    return () => {};
  }

  const ms = idleMinutes * 60 * 1000;

  /**
   * Check LOCK-04 guard, then lock. If a save or critical op is in flight,
   * re-arm a short retry.
   */
  async function checkAndLock(): Promise<void> {
    if (vaultSession.isSaving || vaultSession.isCriticalOpInProgress || isNativeDialogOpen()) {
      // Defer: re-arm a short retry (500ms) and wait for the op/dialog to complete.
      // SECURITY_INVARIANT 1: the underlying idle deadline is NOT reset — only the
      // lock-fire is deferred. Once the guard clears, the genuinely-elapsed idle
      // lock fires immediately on the next 500ms retry.
      idleTimer = setTimeout(() => {
        void checkAndLock();
      }, 500);
      return;
    }
    // Guard passed — perform the lock sequence.
    setLockReason('idle');
    await vaultSession.lock();
    go('unlock');
  }

  /**
   * Reset (or arm) the idle expiry timer. Called on each activity event and
   * once immediately on startIdleController to arm the initial timeout.
   */
  const resetTimer = () => {
    if (idleTimer !== null) clearTimeout(idleTimer);
    idleTimer = setTimeout(() => {
      void checkAndLock();
    }, ms);
  };

  // Activity events that constitute "in-window user activity".
  const events = ['pointermove', 'keydown', 'focus'] as const;

  // Register listeners with capture + passive (matches PATTERNS.md §idle.svelte.ts).
  for (const ev of events) {
    window.addEventListener(ev, resetTimer, { passive: true, capture: true });
  }

  // Arm the initial timer.
  resetTimer();

  // Build the cleanup function for this controller instance.
  _cleanup = () => {
    if (idleTimer !== null) {
      clearTimeout(idleTimer);
      idleTimer = null;
    }
    for (const ev of events) {
      window.removeEventListener(ev, resetTimer, { capture: true });
    }
  };

  return _cleanup;
}

/**
 * Stop the idle controller: cancel the timer and remove all window event
 * listeners. Idempotent — calling on an already-stopped controller is a no-op.
 *
 * Called from App.svelte's $effect cleanup when isUnlocked flips back to
 * false (i.e. after lock() clears the session).
 */
export function stopIdleController(): void {
  _cleanup?.();
  _cleanup = null;
}

/**
 * Cancel the active idle timer WITHOUT removing the activity-event listeners.
 * Used by lock() itself to prevent a double-lock when it's called from outside
 * the idle path (e.g. the user clicks Lock, or a sleep/close event fires).
 *
 * After cancelIdleTimer(), the listeners are still attached — the next user
 * activity will re-arm the timer (only relevant if the vault is immediately
 * re-unlocked in the same session lifecycle).
 */
export function cancelIdleTimer(): void {
  if (idleTimer !== null) {
    clearTimeout(idleTimer);
    idleTimer = null;
  }
}
