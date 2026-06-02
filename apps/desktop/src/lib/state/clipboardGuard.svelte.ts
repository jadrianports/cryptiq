// apps/desktop/src/lib/state/clipboardGuard.svelte.ts
//
// Phase 5 — LOCK-02 / P5-08 hardening: single-owner clipboard auto-clear guard.
//
// THE FIX (secret-lifetime gap): the 25s clipboard auto-clear used to live entirely
// inside ClipboardToast.svelte's per-second $effect interval. Its cleanup did
// `clearInterval` WITHOUT calling `clipboard_clear_if_ours`, so when the host
// component unmounted on ordinary in-app navigation (selecting another entry —
// EntryDetail is wrapped in {#key ui.selectedEntryId}; going to Settings/Generator;
// advancing past the recovery-key wizard step), the auto-clear was silently
// abandoned and the copied password / recovery key stayed on the live OS clipboard
// past clearSeconds (until a manual lock/sleep/close).
//
// This module relocates the AUTHORITATIVE clear timer OUT of the component into a
// persistent module-level guard. The secret's clipboard lifetime no longer depends
// on any component staying mounted: the setTimeout below fires regardless of whether
// ClipboardToast (or any component) is in the DOM.
//
// Module shape: mirrors idle.svelte.ts — module-level state, non-reactive timer
// handles, exported functions, NO class. The reactive display state is the ONE
// thing components react to; the timer handles are bare `let` (not secret/UI data).
//
// RULES (CLAUDE.md):
//   - This is desktop STATE, not @cryptiq/core — core-purity does NOT apply. It MAY
//     import `invoke` from @tauri-apps/api/core (it owns the Rust clear call).
//   - It MUST NOT import any Svelte component (one-way dependency; components import
//     the guard, never the reverse — same discipline as idle.svelte.ts).
//   - It does NOT import vault.svelte (peer module): vault.svelte.ts statically
//     imports cancelClipboardClear from HERE, so this module importing vault would
//     create a cycle. Keep this module dependency-free except for invoke.
//   - The guard NEVER sees the copied value — only the duration. The value lives in
//     the Rust stash; clipboard_clear_if_ours does the still-ours compare (T-5-TOAST /
//     T-5-CLIP-OURS / value-free invariant preserved).

import { invoke } from '@tauri-apps/api/core';

// ---------------------------------------------------------------------------
// Reactive display state — the ONLY thing components react to.
//
// Plain $state (not $state.raw, not deep-secret): these are countdown integers
// and an active flag, never secret material. The toast reads `remaining` /
// `total` to drive its depleting bar, and `active` to decide whether to render.
// ---------------------------------------------------------------------------

export const clipboardClear = $state<{
  /** True while a clear is armed (toast renders only while this is true). */
  active: boolean;
  /** Seconds remaining until the authoritative clear fires (drives the countdown). */
  remaining: number;
  /** The total countdown duration the clear was armed with (drives the bar ratio). */
  total: number;
}>({ active: false, remaining: 0, total: 0 });

// ---------------------------------------------------------------------------
// Module-level timer handles (non-reactive — handles are not UI data).
//
// Two timers, both single-owner:
//   - #countdownInterval: the 1s tick that decrements `remaining` for the display.
//   - #clearTimeout: the AUTHORITATIVE setTimeout(seconds * 1000) that invokes
//     clipboard_clear_if_ours. This is the real guarantee; it is NOT tied to any
//     component lifetime. The interval is purely cosmetic — if it were the only
//     timer, an off-by-one or a paused tab could miss the deadline, but the
//     setTimeout fires deterministically.
// ---------------------------------------------------------------------------

let countdownInterval: ReturnType<typeof setInterval> | null = null;
let clearTimeout_: ReturnType<typeof setTimeout> | null = null;

/**
 * Clear both timer handles in place and null them out. Idempotent — safe to call
 * when either (or both) is already null. Used by arm (re-arm path), cancel, and
 * the authoritative timeout's own completion. Never leaks a handle: always clears
 * the prior handle before a new one is set (the single-owner invariant).
 */
function clearTimers(): void {
  if (countdownInterval !== null) {
    clearInterval(countdownInterval);
    countdownInterval = null;
  }
  if (clearTimeout_ !== null) {
    clearTimeout(clearTimeout_);
    clearTimeout_ = null;
  }
}

// ---------------------------------------------------------------------------
// Exported guard API
// ---------------------------------------------------------------------------

/**
 * Arm (or re-arm) the authoritative clipboard auto-clear.
 *
 * Behaviour:
 *   1. Cancels ANY prior timers first (re-arm) so only ONE clear is ever pending.
 *   2. Sets the display state: active=true, total=seconds, remaining=seconds.
 *   3. Starts a 1s interval that decrements `remaining` (cosmetic countdown).
 *   4. Starts the AUTHORITATIVE setTimeout(seconds * 1000) that, on fire:
 *        - awaits invoke('clipboard_clear_if_ours') (Rust still-ours compare),
 *        - resets display state to inactive (active=false, remaining=0),
 *        - clears both timers.
 *
 * The setTimeout is the real guarantee and is NOT tied to any component lifetime —
 * it fires even if ClipboardToast (or any component) has unmounted. THIS is the
 * unmount fix.
 *
 * @param seconds  The configured clearSeconds (e.g. vault settings clipboard.clearSeconds).
 */
export function armClipboardClear(seconds: number): void {
  // Re-arm: cancel any prior timers first so we never leak a handle and only ONE
  // clear is ever pending (the single-owner invariant).
  clearTimers();

  clipboardClear.active = true;
  clipboardClear.total = seconds;
  clipboardClear.remaining = seconds;

  // Cosmetic per-second countdown — drives the toast's "clears in {N}s" number.
  // Floors at 0 so the display never shows a negative value if the interval and
  // the authoritative timeout race at the final tick.
  countdownInterval = setInterval(() => {
    clipboardClear.remaining = Math.max(0, clipboardClear.remaining - 1);
  }, 1000);

  // AUTHORITATIVE clear — the real guarantee. Module-level, component-independent.
  clearTimeout_ = setTimeout(() => {
    void (async () => {
      try {
        await invoke('clipboard_clear_if_ours');
      } catch {
        // Non-fatal — best-effort clear on timer expiry (e.g. invoke unavailable
        // in tests, or the clipboard was already overwritten by another app).
      } finally {
        // Reset display state + tear down timers regardless of the invoke result.
        clearTimers();
        clipboardClear.active = false;
        clipboardClear.remaining = 0;
      }
    })();
  }, seconds * 1000);
}

/**
 * Cancel the pending clipboard auto-clear: clear both timers and reset the display
 * state to inactive. Idempotent — safe to call repeatedly and when nothing is armed.
 *
 * Does NOT itself invoke clipboard_clear_if_ours — it is used on (a) re-arm, where
 * armClipboardClear already calls clearTimers, and (b) lock(), where the caller has
 * already issued its own clipboard_clear_if_ours and only needs the pending guard
 * timer torn down so it can't fire after the vault is unlocked again.
 */
export function cancelClipboardClear(): void {
  clearTimers();
  clipboardClear.active = false;
  clipboardClear.remaining = 0;
  clipboardClear.total = 0;
}
