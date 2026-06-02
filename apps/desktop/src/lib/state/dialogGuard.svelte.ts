// apps/desktop/src/lib/state/dialogGuard.svelte.ts
//
// Fix-forward (import-auto-lock regression): native OS file-dialog guard.
//
// ROOT CAUSE: When the user clicks the <input type="file"> in ImportView, the
// OS file-picker dialog steals webview focus. That triggers:
//   (a) the cryptiq-window-blur Tauri listener in App.svelte (which locks when
//       lockOnMinimize is enabled), and
//   (b) the idle controller's checkAndLock loop, which sees the activity gap
//       and fires if the idle deadline happened to elapse while the dialog
//       was open.
// Both are false positives — the user is actively engaged in importing, not
// idle, and the window has not been minimized by the user. This guard lets
// the blur-lock and idle-lock DEFER while a known app-initiated OS dialog
// is open, without touching the sleep/close locks or the underlying idle
// deadline.
//
// Module shape: mirrors clipboardGuard.svelte.ts — module-level bare `let`
// for non-reactive timer/listener handles, exported functions, NO class.
//
// RULES (CLAUDE.md):
//   - No @tauri-apps/* imports — this guard has NO IO.
//   - No @cryptiq/core imports — pure presenter-layer guard.
//   - MUST NOT import any Svelte component (one-way dependency).
//   - Does NOT import vault.svelte or idle.svelte (no circular dependency).
//   - The guard tracks only a boolean flag — never any secret material.
//   - No plaintext logging of any kind.
//
// SECURITY INVARIANTS (all must hold — SECURITY_INVARIANT 1-5):
//   1. IDLE: checkAndLock in idle.svelte.ts DEFERS (re-arms 500ms) while this
//      guard is set; the guard itself never cancels/extends the idle deadline.
//      Once the guard clears, a genuinely-elapsed idle lock fires immediately.
//      NOTE: idle.svelte.ts independently treats window 'focus' as an activity
//      event, so a genuine return-from-dialog (focus) resets the idle deadline
//      as it would for any window refocus — intended "user is back" behavior.
//      A walk-away (no return) still locks within idleMinutes + the 30s cap.
//   2. MINIMIZE: App.svelte's cryptiq-window-blur listener early-returns only
//      while this guard is set (the brief, app-initiated OS dialog). A real
//      user minimize (guard clear) still locks when lockOnMinimize is true.
//   3. SLEEP/CLOSE: cryptiq-sleep-lock and cryptiq-window-close listeners in
//      App.svelte are UNCHANGED — they always lock regardless of this guard.
//   4. HARD BOUNDED: the guard self-clears via a 30s hard timeout so an
//      abandoned/cancelled OS dialog (which emits NO DOM change event) can
//      never pin the vault unlocked. Also clears on file-select (onchange)
//      and on window 'focus' return. All three paths tear down each other's
//      handles to prevent double-fires.
//   5. CRITICAL-OP WRAPPER: the import commit loop is wrapped in
//      vaultSession.runCriticalOp (vault.svelte.ts), which is internally
//      try/finally-safe — the counter cannot leak even on a thrown error.

// ---------------------------------------------------------------------------
// Hard-bounded timeout constant (SECURITY_INVARIANT 4).
//
// 30 000 ms: generous enough for a user to navigate a file picker (even slow
// network shares), strict enough that a forgotten/crashed dialog can never pin
// the vault unlocked for more than 30 seconds beyond normal idle timeout.
// ---------------------------------------------------------------------------
const DIALOG_GUARD_TIMEOUT_MS = 30_000;

// ---------------------------------------------------------------------------
// Module-level handles (non-reactive — not UI data, not secrets).
// ---------------------------------------------------------------------------

/** True while a native OS file-picker dialog is known to be open. */
let _dialogOpen = false;

/** Hard-bounded self-clear timeout handle, or null when no guard is active. */
let _timeoutHandle: ReturnType<typeof setTimeout> | null = null;

/** One-shot focus-return listener handle. Captured so it can be removed
 *  by clearNativeDialogOpen() and prevented from double-firing. Armed ONLY
 *  after a real blur fires (see _blurListener) — never at set-time. */
let _focusListener: (() => void) | null = null;

/** One-shot blur listener handle. Arms the focus-return clear ONLY after the
 *  window has actually lost focus to the OS dialog. This closes a premature-
 *  clear race: clicking <input type=file> can focus the input within the
 *  webview, and arming the focus-clear at set-time could fire on that focus
 *  BEFORE the OS dialog steals focus — clearing the guard and re-exposing the
 *  blur-lock. Gating focus behind blur guarantees the focus-clear only triggers
 *  on a genuine return FROM the dialog. Captured so _clear() can tear it down. */
let _blurListener: (() => void) | null = null;

// ---------------------------------------------------------------------------
// Internal clear helper — tears down all handles and resets the flag.
// Idempotent: safe to call when nothing is set.
// ---------------------------------------------------------------------------

function _clear(): void {
  _dialogOpen = false;

  if (_timeoutHandle !== null) {
    clearTimeout(_timeoutHandle);
    _timeoutHandle = null;
  }

  if (_blurListener !== null) {
    // Remove the one-shot blur listener so a later blur can't arm a stale
    // focus-clear against a future guard.
    window.removeEventListener('blur', _blurListener);
    _blurListener = null;
  }

  if (_focusListener !== null) {
    // Remove the one-shot focus listener so it can't double-fire.
    window.removeEventListener('focus', _focusListener);
    _focusListener = null;
  }
}

// ---------------------------------------------------------------------------
// Exported guard API
// ---------------------------------------------------------------------------

/**
 * Mark a native OS file-picker dialog as open.
 *
 * Installs two automatic boundedness mechanisms (SECURITY_INVARIANT 4):
 *   (a) A 30s hard-timeout that self-clears the guard even if the OS dialog
 *       is cancelled without emitting any DOM change event.
 *   (b) A one-shot `blur` listener that, only AFTER the window genuinely loses
 *       focus to the OS dialog, arms a one-shot `focus` listener which clears
 *       the guard on return — covering OS-dialog-cancel (no change event) and
 *       normal file selection. Gating focus behind blur prevents the input
 *       gaining focus on click from clearing the guard before the dialog opens.
 *
 * Calling this function while a guard is already active re-arms all handles
 * (idempotent re-entry safe).
 *
 * Call immediately BEFORE the file-picker can open (e.g. on the input's
 * `onclick`). Call `clearNativeDialogOpen()` in the input's `onchange`
 * handler to proactively clear before the handlers above fire.
 */
export function setNativeDialogOpen(): void {
  // Tear down any prior handles before re-arming (idempotent).
  _clear();

  _dialogOpen = true;

  // (a) Hard-bounded self-clearing timeout (SECURITY_INVARIANT 4 — ~30s).
  _timeoutHandle = setTimeout(() => {
    _clear();
  }, DIALOG_GUARD_TIMEOUT_MS);

  // (b) Arm the focus-return clear ONLY after a real blur fires. The OS dialog
  // opening blurs the webview window; the focus-clear is then armed so it only
  // triggers on a genuine return FROM the dialog. A focus from the input
  // gaining focus on click (before the dialog opens) therefore cannot clear the
  // guard early and re-expose the blur-lock.
  _blurListener = () => {
    _blurListener = null; // consumed (registered with { once: true })
    _focusListener = () => {
      _clear();
    };
    window.addEventListener('focus', _focusListener, { once: true });
  };
  window.addEventListener('blur', _blurListener, { once: true });
}

/**
 * Proactively clear the native OS dialog guard.
 *
 * Call at the top of the file input's `onchange` handler so the guard is
 * removed as soon as a file is selected (before blur/idle checks can race).
 * Also tears down the pending hard-timeout and focus-return listener to
 * prevent them from double-firing.
 *
 * Idempotent — safe to call when no guard is active.
 */
export function clearNativeDialogOpen(): void {
  _clear();
}

/**
 * Returns true while a native OS file-picker dialog is known to be open.
 *
 * Read by:
 *   - App.svelte's cryptiq-window-blur listener (SECURITY_INVARIANT 2)
 *   - idle.svelte.ts's checkAndLock() defer predicate (SECURITY_INVARIANT 1)
 */
export function isNativeDialogOpen(): boolean {
  return _dialogOpen;
}
