// apps/desktop/src/tests/support/testState.ts
//
// Test-only re-export barrel for the UI rune-state singletons the specs read and
// mutate (the `ui` toast/selection state, the `vaultSession`, and the `view` enum).
//
// Under the Vitest browser-mode harness (vitest.browser.config.ts) the spec and the
// component it renders share ONE module realm, so the `ui`/`vaultSession`/`view` a
// spec imports here are the SAME instances the components import from
// ../../lib/state/*.svelte — which is exactly what makes the shared-singleton
// assertions (saveCount, ui.toasts, view.current) meaningful. This barrel keeps those
// imports in one place so specs don't reach into lib/state paths individually.
//
// Usage in specs:
//   import { ui, vaultSession, view } from '../support/testState';
//   ui.toasts = [];

export { ui, pushToast, clearToast } from '../../lib/state/ui.svelte';
export { vaultSession } from '../../lib/state/vault.svelte';
export { view, go } from '../../lib/state/view.svelte';
