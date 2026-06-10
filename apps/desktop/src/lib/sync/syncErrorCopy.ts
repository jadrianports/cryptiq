// apps/desktop/src/lib/sync/syncErrorCopy.ts
//
// Maps a sync error (typed error instance or raw string) to a
// UI-SPEC heading + body for the SyncErrorAlert component (D-15).
//
// SECURITY (D-15 fence):
//   ALL error body strings are STATIC — no entry data, no URL, no key material.
//   Connect and handshake failures both map to the SAME "Couldn't reach…" copy
//   to prevent crypto-state distinction from being visible to the user (T-10-20).
//   The node test asserts every body: length < 300 and no http:// patterns.
//
// Usage:
//   const { heading, body } = syncErrorToCopy(syncStore.lastError);
//   (syncStore.lastError is already a safe display string set by syncOrchestration.ts)
//
// Source: 12-UI-SPEC.md "Error Copy (D-15)" table, 12-01-PLAN.md Task 1.

import {
  SyncPeerUnreachableError,
  SyncAuthFailedError,
  SyncBindingMismatchError,
  SyncTransportError,
  SyncPartnerNotSavedError,
  SyncNoAckError,
  SyncPartnerBusyError,
  SyncLockedMidSyncError,
} from '@cryptiq/core';

export interface SyncErrorCopy {
  heading: string;
  body: string;
}

/**
 * Map a sync error to a UI-SPEC heading and recovery hint body (D-15).
 *
 * Accepts: typed error instances OR raw string error codes/messages (for
 * cases where the store holds a display string rather than the typed error).
 *
 * Connect failures and handshake failures both produce "Couldn't reach…" copy
 * (T-10-20 — no crypto-state distinction). The device-name substitution
 * ("Couldn't reach {device name}") is handled by the caller (SyncErrorAlert),
 * which has access to pairingStore.peers[0].deviceName. This helper returns
 * the raw heading constant with "{device name}" placeholder if no name is
 * provided, or substitutes the provided deviceName.
 *
 * @param error      The error to map (typed instance, string code, or unknown).
 * @param deviceName Optional device name to substitute into the heading.
 * @returns          { heading, body } — both are static strings, no entry data.
 */
export function syncErrorToCopy(error: unknown, deviceName?: string): SyncErrorCopy {
  const name = deviceName ?? 'the other device';

  // --- SyncPeerUnreachableError: connect/handshake both map here (T-10-20) ---
  if (error instanceof SyncPeerUnreachableError) {
    return {
      heading: `Couldn't reach ${name}`,
      body: "Make sure both devices are on the same network and Cryptiq is open on the other device.",
    };
  }

  // --- SyncAuthFailedError ---
  if (error instanceof SyncAuthFailedError) {
    return {
      heading: 'Authentication failed',
      body: "The master passwords on both devices must match. Unlock both vaults with the same master password and try again.",
    };
  }

  // --- SyncBindingMismatchError ---
  if (error instanceof SyncBindingMismatchError) {
    return {
      heading: 'Vault mismatch',
      body: "This device is paired with a different vault. Unpair and re-pair to sync.",
    };
  }

  // --- SyncTransportError ---
  if (error instanceof SyncTransportError) {
    return {
      heading: 'Connection lost',
      body: "The connection dropped mid-sync. Your vault is unchanged — try again.",
    };
  }

  // --- SyncPartnerNotSavedError / SyncNoAckError: collapse to same copy ---
  if (error instanceof SyncPartnerNotSavedError || error instanceof SyncNoAckError) {
    return {
      heading: 'Sync incomplete',
      body: "The other device didn't confirm. Your vault is unchanged — try again when both devices are ready.",
    };
  }

  // --- SyncPartnerBusyError ---
  if (error instanceof SyncPartnerBusyError) {
    return {
      heading: 'Other device is busy',
      body: "A sync is already in progress on the other device. Wait a moment and try again.",
    };
  }

  // --- SyncLockedMidSyncError ---
  if (error instanceof SyncLockedMidSyncError) {
    return {
      heading: 'Vault locked during sync',
      body: "Your vault locked while syncing. Unlock and try again.",
    };
  }

  // --- String fallback: check for known code/display string substrings ---
  // syncStore.lastError holds a safe display string from mapRustSyncError; check for
  // known substrings to route to the right copy without re-exposing raw Rust strings.
  if (typeof error === 'string') {
    const lower = error.toLowerCase();

    if (
      lower.includes("couldn't reach") ||
      lower.includes('could not reach') ||
      lower.includes('unreachable') ||
      lower.includes('peer') ||
      lower.includes('connect')
    ) {
      return {
        heading: `Couldn't reach ${name}`,
        body: "Make sure both devices are on the same network and Cryptiq is open on the other device.",
      };
    }

    if (lower.includes('binding') || lower.includes('mismatch') || lower.includes('different vault')) {
      return {
        heading: 'Vault mismatch',
        body: "This device is paired with a different vault. Unpair and re-pair to sync.",
      };
    }

    if (lower.includes('busy') || lower.includes('already syncing')) {
      return {
        heading: 'Other device is busy',
        body: "A sync is already in progress on the other device. Wait a moment and try again.",
      };
    }

    if (lower.includes('locked mid') || lower.includes('locked_mid')) {
      return {
        heading: 'Vault locked during sync',
        body: "Your vault locked while syncing. Unlock and try again.",
      };
    }

    if (lower.includes("didn't confirm") || lower.includes('no ack') || lower.includes('not saved')) {
      return {
        heading: 'Sync incomplete',
        body: "The other device didn't confirm. Your vault is unchanged — try again when both devices are ready.",
      };
    }

    if (lower.includes('connection') || lower.includes('transport') || lower.includes('dropped')) {
      return {
        heading: 'Connection lost',
        body: "The connection dropped mid-sync. Your vault is unchanged — try again.",
      };
    }

    if (lower.includes('auth') || lower.includes('password')) {
      return {
        heading: 'Authentication failed',
        body: "The master passwords on both devices must match. Unlock both vaults with the same master password and try again.",
      };
    }
  }

  // --- Generic fallback ---
  return {
    heading: 'Sync failed',
    body: "An unexpected error occurred. Your vault is unchanged — try again.",
  };
}
