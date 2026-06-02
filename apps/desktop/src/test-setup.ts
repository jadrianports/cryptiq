// apps/desktop/src/test-setup.ts
//
// Vitest setup file for the desktop node-env unit tests.
//
// The idle controller and its tests use `window` as the event target for
// in-window activity events (pointermove, keydown, focus). In the Vitest
// node environment `window` is undefined; this setup file provides a minimal
// EventTarget-based window shim so the idle controller's addEventListener
// and the test's dispatchEvent share the same object.
//
// Why EventTarget and not globalThis:
//   Node's globalThis does NOT implement EventTarget (no addEventListener /
//   dispatchEvent). We create a singleton EventTarget and alias it as `window`
//   on globalThis so the idle controller and the tests operate identically.
//
// This is safe for the node unit tests because:
//   - The idle controller ONLY uses window for activity-event listeners.
//   - No browser-DOM semantics (document, location, etc.) are needed.
//   - The saveMutex tests do not use window and are unaffected.

if (typeof window === 'undefined') {
  const windowShim = new EventTarget() as EventTarget & {
    addEventListener: typeof EventTarget.prototype.addEventListener;
    removeEventListener: typeof EventTarget.prototype.removeEventListener;
    dispatchEvent: typeof EventTarget.prototype.dispatchEvent;
  };

  (globalThis as Record<string, unknown>)['window'] = windowShim;
}
