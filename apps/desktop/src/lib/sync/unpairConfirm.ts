// apps/desktop/src/lib/sync/unpairConfirm.ts
//
// Pure unpair-confirm toggle reducer (UI-16 / D-17).
//
// Models the inline danger-ack panel state for the DeviceList component.
// Only ONE device row can be in the confirming state at a time — opening a
// different row replaces the prior pending row.
//
// Design rationale:
//   The state is the single currently-confirming deviceId (or null).
//   All three exported functions are pure: they receive a state value and
//   return a new value. No mutation, no Svelte, no IO.
//
//   DeviceList.svelte (Plan 12-03) holds the state in a local $state:
//     let unpairState = $state<UnpairConfirmState>(null);
//   and calls openUnpairConfirm / closeUnpairConfirm / isUnpairConfirming.
//
// Source: 12-01-PLAN.md Task 1, 12-UI-SPEC.md "Device Management (UI-16) Copy".

/**
 * The unpair-confirm state: the deviceId of the device row whose inline
 * danger-ack panel is currently open, or null when no row is open.
 */
export type UnpairConfirmState = string | null;

/**
 * Open the inline unpair confirm panel for the given deviceId.
 *
 * Only one row can be confirming at a time. If another row is already open,
 * this call replaces it (opens the new row, closes the previous one).
 *
 * @param _state   The current unpair-confirm state (ignored — new state replaces it).
 * @param deviceId The deviceId of the row to open the confirm panel for.
 * @returns        A new state where `deviceId` is the confirming row.
 */
export function openUnpairConfirm(_state: UnpairConfirmState, deviceId: string): UnpairConfirmState {
  return deviceId;
}

/**
 * Close the inline unpair confirm panel (cancel action).
 *
 * @param _state The current unpair-confirm state (ignored).
 * @returns      null — no row is confirming.
 */
export function closeUnpairConfirm(_state: UnpairConfirmState): UnpairConfirmState {
  return null;
}

/**
 * Returns true if the given deviceId currently has its inline unpair confirm
 * panel open.
 *
 * @param state    The current unpair-confirm state.
 * @param deviceId The deviceId to check.
 * @returns        true if deviceId is the currently-confirming row.
 */
export function isUnpairConfirming(state: UnpairConfirmState, deviceId: string): boolean {
  return state === deviceId;
}
