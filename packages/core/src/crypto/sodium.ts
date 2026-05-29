// packages/core/src/crypto/sodium.ts
//
// THE SINGLE WASM ENTRY POINT. This is the ONLY file in packages/core permitted to
// `import _sodium from 'libsodium-wrappers-sumo'`. ESLint `no-restricted-imports`
// bans the raw import everywhere else and points callers here (SEC-01, SEC-02).
//
// WHY (Pitfall 3 — libsodium init race): libsodium-wrappers-sumo bootstraps its WASM
// module asynchronously. Reading ANY constant or calling ANY primitive before
// `sodium.ready` resolves yields `undefined` / throws. A top-level
//   `const SALTBYTES = _sodium.crypto_pwhash_SALTBYTES`
// evaluates at module-load time — before ready — and silently captures `undefined`.
// The fix is to funnel every access through a single async factory that awaits
// `sodium.ready` exactly once and memoizes the resolved instance.
//
// Source: PITFALLS.md Pitfall 3 + STACK.md §Q4 + RESEARCH Pattern 1.

import _sodium from 'libsodium-wrappers-sumo';

// Memoized ready-promise. `null` until the first getSodium() call kicks off the
// `sodium.ready` await; thereafter every caller shares the same resolved instance.
let _ready: Promise<typeof _sodium> | null = null;

/**
 * Returns a ready libsodium instance. Awaits `sodium.ready` on first call and
 * memoizes the result so subsequent calls resolve to the SAME instance with no
 * re-initialization. Every crypto operation in core MUST start with:
 *
 *   const sodium = await getSodium();
 */
export async function getSodium(): Promise<typeof _sodium> {
  if (!_ready) {
    _ready = _sodium.ready.then(() => _sodium);
  }
  return _ready;
}
