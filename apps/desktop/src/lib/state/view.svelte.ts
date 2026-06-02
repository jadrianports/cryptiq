// apps/desktop/src/lib/state/view.svelte.ts
//
// P4-06 — hand-rolled rune view-state enum. No router dependency: the webview
// has no URL bar and there are only six views, so a router library is unjustified
// weight against the minimal-deps supply-chain ethos.
//
// Phase 5 (Plan 05-01): additive additions:
//   - View union extended with 'change-master' | 'recently-deleted' (P5-10/P5-11)
//   - lockState + setLockReason (P5-06): contextual reason for lock (idle/sleep/user)
//     so the unlock screen can show a quiet "Locked due to inactivity" note.
//
// RULES:
//   - Plain $state (NOT $state.raw) — view state is NOT secret data.
//   - No @tauri-apps/* or @cryptiq/core imports — purely presentational state.
//   - All view values must be present in the union.

/**
 * The full set of top-level views in the application.
 *
 * first-run       — initial wizard (explainer → vault location → password → recovery key)
 * unlock          — unlock an existing vault (master password or recovery key)
 * relocate        — P4-10 missing-vault recovery (locate/create fresh)
 * main            — three-column shell (sidebar | entry list | detail pane)
 * generator       — standalone generator screen (GEN-05/06)
 * settings        — settings shell (UI-13)
 * change-master   — Phase 5: change master password flow (AUTH-10, P5-10)
 * recently-deleted — Phase 5: recently deleted list (P5-11)
 * import          — Phase 6: CSV import wizard (IMPORT-01..08, P6-02)
 * health          — Phase 6: health audit view (AUDIT-01..06, P6-06)
 *
 * Note: 'about' is NOT a top-level View — About/Security is a sub-view reached
 * via a row in Settings (P6-12), not a separate sidebar item.
 */
export type View =
  | 'first-run'
  | 'unlock'
  | 'relocate'
  | 'main'
  | 'generator'
  | 'settings'
  | 'change-master'
  | 'recently-deleted'
  | 'import'    // Phase 6 — P6-02 CSV import wizard (IMPORT-01..08)
  | 'health';   // Phase 6 — P6-06 health audit view (AUDIT-01..06)

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

/**
 * P5-06: reason the vault locked — drives the contextual unlock-screen copy.
 *
 * idle   — auto-locked due to inactivity (idle timeout)
 * sleep  — locked due to system sleep / suspend event
 * user   — explicitly locked by the user or minimize/blur (when toggle is on)
 * null   — not yet locked (or reason cleared)
 *
 * Use plain $state (not $state.raw) — lock reason is NOT secret data.
 */
export const lockState = $state<{ reason: 'idle' | 'sleep' | 'user' | null }>({ reason: null });

/**
 * Set the lock reason before calling vaultSession.lock(). The idle controller,
 * sleep-lock listener, and blur listener each call this with their specific reason.
 * Clear to null after a successful unlock via setLockReason(null).
 */
export function setLockReason(r: 'idle' | 'sleep' | 'user' | null): void {
  lockState.reason = r;
}

/**
 * P5-05 (AUTH-10): Pinned post-change-master success flag.
 *
 * Set to true by ChangeMasterView before go('settings') so SettingsShell can
 * render the calm "Master password changed." panel. Not secret — only a boolean
 * flag used to drive UI. Plain $state (NOT $state.raw).
 *
 * Lifecycle: ChangeMasterView sets it to true on success; SettingsShell reads it
 * and clears it (setChangeMasterSuccess(false)) when the user navigates away.
 */
export const changeMasterSuccess = $state<{ value: boolean }>({ value: false });

/**
 * Set or clear the post-change-master success flag.
 * Call with `true` immediately before go('settings') on a successful master-password change.
 * Call with `false` when SettingsShell unmounts / the user navigates away from Settings.
 */
export function setChangeMasterSuccess(v: boolean): void {
  changeMasterSuccess.value = v;
}
