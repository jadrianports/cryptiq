// apps/desktop/src/lib/bridge/extensionUnpairConfirm.ts
//
// Pure revoke-confirm toggle reducer (BRIDGE-09 / D-04).
//
// Verbatim rename of apps/desktop/src/lib/sync/unpairConfirm.ts — ZERO logic change,
// only the parameter name (deviceId -> clientId) and exported symbol names are
// renamed for the Browser Extensions domain.
//
// Models the inline danger-ack panel state for ExtensionSettingsSection.svelte.
// Only ONE association row can be in the confirming state at a time — opening a
// different row replaces the prior pending row.
//
// Design rationale:
//   The state is the single currently-confirming clientId (or null).
//   All three exported functions are pure: they receive a state value and
//   return a new value. No mutation, no Svelte, no IO.
//
//   ExtensionSettingsSection.svelte (Plan 15-05 Task 2) holds the state in a local
//   $state:
//     let revokeState = $state<ExtensionRevokeConfirmState>(null);
//   and calls openExtensionRevokeConfirm / closeExtensionRevokeConfirm /
//   isExtensionRevokeConfirming.
//
// Source: 15-05-PLAN.md Task 1; 15-PATTERNS.md "extensionUnpairConfirm.ts" section.

/**
 * The revoke-confirm state: the clientId of the association row whose inline
 * danger-ack panel is currently open, or null when no row is open.
 */
export type ExtensionRevokeConfirmState = string | null;

/**
 * Open the inline revoke confirm panel for the given clientId.
 *
 * Only one row can be confirming at a time. If another row is already open,
 * this call replaces it (opens the new row, closes the previous one).
 *
 * @param _state   The current revoke-confirm state (ignored — new state replaces it).
 * @param clientId The clientId of the row to open the confirm panel for.
 * @returns        A new state where `clientId` is the confirming row.
 */
export function openExtensionRevokeConfirm(
  _state: ExtensionRevokeConfirmState,
  clientId: string,
): ExtensionRevokeConfirmState {
  return clientId;
}

/**
 * Close the inline revoke confirm panel (cancel action).
 *
 * @param _state The current revoke-confirm state (ignored).
 * @returns      null — no row is confirming.
 */
export function closeExtensionRevokeConfirm(
  _state: ExtensionRevokeConfirmState,
): ExtensionRevokeConfirmState {
  return null;
}

/**
 * Returns true if the given clientId currently has its inline revoke confirm
 * panel open.
 *
 * @param state    The current revoke-confirm state.
 * @param clientId The clientId to check.
 * @returns        true if clientId is the currently-confirming row.
 */
export function isExtensionRevokeConfirming(
  state: ExtensionRevokeConfirmState,
  clientId: string,
): boolean {
  return state === clientId;
}
