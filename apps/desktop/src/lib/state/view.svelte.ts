// apps/desktop/src/lib/state/view.svelte.ts
//
// P4-06 — hand-rolled rune view-state enum. No router dependency: the webview
// has no URL bar and there are only six views, so a router library is unjustified
// weight against the minimal-deps supply-chain ethos.
//
// RULES:
//   - Plain $state (NOT $state.raw) — view state is NOT secret data.
//   - No @tauri-apps/* or @cryptiq/core imports — purely presentational state.
//   - All six P4-06 view values must be present in the union.

/**
 * The full set of top-level views in the application.
 *
 * first-run  — initial wizard (explainer → vault location → password → recovery key)
 * unlock     — unlock an existing vault (master password or recovery key)
 * relocate   — P4-10 missing-vault recovery (locate/create fresh)
 * main       — three-column shell (sidebar | entry list | detail pane)
 * generator  — standalone generator screen (GEN-05/06)
 * settings   — settings shell (UI-13 placeholders)
 */
export type View = 'first-run' | 'unlock' | 'relocate' | 'main' | 'generator' | 'settings';

/**
 * Module-level singleton driving which screen renders behind the sodium.ready gate.
 * Seeded to 'unlock'; App.svelte re-seeds to 'first-run' if config.vaultPath is null.
 */
export const view = $state<{ current: View }>({ current: 'unlock' });

/**
 * Transition to a new view. This is the ONLY place that should mutate view.current.
 * Screens call go() at the end of their flows (e.g. after successful unlock → go('main')).
 */
export function go(v: View): void {
  view.current = v;
}
