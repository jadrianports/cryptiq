// apps/desktop/src/lib/sync/sasCountdown.ts
//
// Pure SAS countdown timer logic (D-07).
//
// Extracts the setInterval-driven countdown logic from SasCountdownRing.svelte
// into a testable pure function. The component holds $state; this module holds
// the logic. The interval driver is injectable so the test advances without
// real time.
//
// Source: 12-PATTERNS.md "SasCountdownRing.svelte" + 12-RESEARCH.md lines 305-360.
// No Svelte, no Tauri, no IO — pure TS.

/** Injectable interval function signature (mirrors setInterval). */
export type IntervalFn = (callback: () => void, ms: number) => { clear: () => void };

/** State exposed by createSasCountdown. */
export interface SasCountdownState {
  /** Seconds remaining (60 → 0). Confirm button should be disabled when <= 0. */
  secondsRemaining: number;
  /**
   * Whether the confirmation window has expired.
   * Derivable as `secondsRemaining <= 0` — provided as a convenience predicate.
   */
  readonly isExpired: boolean;
  /** Stop the interval and release resources (call in $effect cleanup). */
  destroy: () => void;
}

/** Options for createSasCountdown. */
export interface SasCountdownOptions {
  /** Called exactly once when secondsRemaining reaches 0. */
  onExpired: () => void;
  /**
   * Injectable interval driver for testing.
   * Defaults to the real setInterval/clearInterval if not provided.
   * The returned object must have a `clear()` method.
   */
  intervalFn?: IntervalFn;
  /** Starting seconds (default: 60). */
  startSeconds?: number;
}

/**
 * Create a SAS countdown timer.
 *
 * Drives secondsRemaining from startSeconds (default 60) down to 0,
 * calling onExpired exactly once when it reaches 0.
 *
 * The returned object is NOT reactive — the caller (SasCountdownRing.svelte) owns
 * a local `$state(secondsRemaining)` and calls `tick()` to update it, or uses the
 * returned `state.secondsRemaining` getter for polling from tests.
 *
 * The `intervalFn` parameter accepts a test-injectable driver (a function that
 * takes a callback + ms and returns `{ clear() }`) so unit tests can advance the
 * clock by calling `tick()` manually without sleeping.
 *
 * @param options SasCountdownOptions
 * @returns       SasCountdownState with secondsRemaining, isExpired, destroy.
 */
export function createSasCountdown(options: SasCountdownOptions): SasCountdownState {
  const { onExpired, startSeconds = 60 } = options;

  let secondsRemaining = startSeconds;
  let expired = false;
  let destroyed = false;

  // Default intervalFn uses real setInterval.
  const intervalFn: IntervalFn =
    options.intervalFn ??
    ((callback, ms) => {
      const id = setInterval(callback, ms);
      return { clear: () => { clearInterval(id); } };
    });

  const handle = intervalFn(() => {
    if (destroyed) return;
    secondsRemaining -= 1;
    if (secondsRemaining <= 0) {
      secondsRemaining = 0;
      if (!expired) {
        expired = true;
        handle.clear();
        onExpired();
      }
    }
  }, 1000);

  const state: SasCountdownState = {
    get secondsRemaining(): number {
      return secondsRemaining;
    },
    get isExpired(): boolean {
      return secondsRemaining <= 0;
    },
    destroy(): void {
      destroyed = true;
      handle.clear();
    },
  };

  return state;
}
