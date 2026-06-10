// apps/desktop/src/lib/sync/__tests__/sasCountdown.test.ts
//
// Wave-0 node test: SAS countdown timer logic (D-07).
// Uses an injectable interval driver so tests advance without real time.
//
// Environment: node (vitest.config.ts — no browser provider invoked).

import { describe, it, expect, vi } from 'vitest';
import { createSasCountdown } from '../sasCountdown';
import type { IntervalFn } from '../sasCountdown';

/**
 * Build a controllable tick-based interval driver.
 * Returns the driver and a `tick()` function that fires the callback once.
 */
function makeTestIntervalFn(): { intervalFn: IntervalFn; tick: () => void } {
  let storedCallback: (() => void) | null = null;
  let cleared = false;

  const intervalFn: IntervalFn = (callback) => {
    storedCallback = callback;
    cleared = false;
    return {
      clear() {
        cleared = true;
      },
    };
  };

  function tick(): void {
    if (!cleared && storedCallback !== null) {
      storedCallback();
    }
  }

  return { intervalFn, tick };
}

describe('createSasCountdown — D-07 injectable timer logic', () => {
  it('starts at 60 seconds remaining by default', () => {
    const onExpired = vi.fn();
    const { intervalFn } = makeTestIntervalFn();
    const state = createSasCountdown({ onExpired, intervalFn });
    expect(state.secondsRemaining).toBe(60);
    expect(state.isExpired).toBe(false);
    state.destroy();
  });

  it('decrements secondsRemaining by 1 on each tick', () => {
    const onExpired = vi.fn();
    const { intervalFn, tick } = makeTestIntervalFn();
    const state = createSasCountdown({ onExpired, intervalFn });

    tick();
    expect(state.secondsRemaining).toBe(59);
    tick();
    expect(state.secondsRemaining).toBe(58);
    expect(onExpired).not.toHaveBeenCalled();
    state.destroy();
  });

  it('calls onExpired exactly once when countdown reaches 0 (60 ticks)', () => {
    const onExpired = vi.fn();
    const { intervalFn, tick } = makeTestIntervalFn();
    const state = createSasCountdown({ onExpired, intervalFn });

    // Advance 60 ticks — should hit 0 and fire onExpired exactly once.
    for (let i = 0; i < 60; i++) {
      tick();
    }

    expect(state.secondsRemaining).toBe(0);
    expect(onExpired).toHaveBeenCalledTimes(1);
  });

  it('does NOT call onExpired again after expiry (idempotent)', () => {
    const onExpired = vi.fn();
    const { intervalFn, tick } = makeTestIntervalFn();
    const state = createSasCountdown({ onExpired, intervalFn });

    for (let i = 0; i < 60; i++) {
      tick();
    }
    // Tick a few more times after expiry — should NOT call onExpired again.
    tick();
    tick();

    expect(onExpired).toHaveBeenCalledTimes(1);
    state.destroy();
  });

  it('isExpired is true at expiry (confirm-disabled predicate)', () => {
    const onExpired = vi.fn();
    const { intervalFn, tick } = makeTestIntervalFn();
    const state = createSasCountdown({ onExpired, intervalFn });

    expect(state.isExpired).toBe(false);

    for (let i = 0; i < 60; i++) {
      tick();
    }

    expect(state.isExpired).toBe(true);
    state.destroy();
  });

  it('isExpired is false before expiry', () => {
    const onExpired = vi.fn();
    const { intervalFn, tick } = makeTestIntervalFn();
    const state = createSasCountdown({ onExpired, intervalFn });

    for (let i = 0; i < 59; i++) {
      tick();
    }

    expect(state.secondsRemaining).toBe(1);
    expect(state.isExpired).toBe(false);
    expect(onExpired).not.toHaveBeenCalled();
    state.destroy();
  });

  it('destroy() stops further ticks from decrementing', () => {
    const onExpired = vi.fn();
    const { intervalFn, tick } = makeTestIntervalFn();
    const state = createSasCountdown({ onExpired, intervalFn });

    tick();
    tick();
    expect(state.secondsRemaining).toBe(58);

    state.destroy();
    // After destroy, ticks should not affect state.
    tick();
    tick();
    expect(state.secondsRemaining).toBe(58);
    expect(onExpired).not.toHaveBeenCalled();
  });

  it('respects custom startSeconds', () => {
    const onExpired = vi.fn();
    const { intervalFn, tick } = makeTestIntervalFn();
    const state = createSasCountdown({ onExpired, intervalFn, startSeconds: 5 });

    expect(state.secondsRemaining).toBe(5);

    for (let i = 0; i < 5; i++) {
      tick();
    }

    expect(state.secondsRemaining).toBe(0);
    expect(onExpired).toHaveBeenCalledTimes(1);
    state.destroy();
  });
});
