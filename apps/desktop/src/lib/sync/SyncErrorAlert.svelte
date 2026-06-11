<!--
  SyncErrorAlert.svelte — Persistent inline error alert for sync failures (D-15 / SC-4).

  Renders the named error heading + recovery hint + "Try Again" + "Dismiss" buttons.
  The heading and body are resolved via `syncErrorToCopy` (Plan 12-01 tested mapper) —
  this component does NOT re-map error codes inline. The device name for "Couldn't reach
  {device}" is read from `pairingStore.peers[0].deviceName`.

  SECURITY (D-15 fence):
    - Error copy is resolved by `syncErrorToCopy` — all strings are static (no entry data).
    - `syncStore.lastError` (a safe display string from mapRustSyncError) is passed to
      `syncErrorToCopy` to pick the right heading/body — no raw Rust strings shown to user.
    - No entry title, username, password, or URL interpolated in any string here.

  Accessibility:
    - `role="alert"`: live-region announcement when the alert mounts (D-15 / accessibility
      contract). Screen readers announce the heading immediately.
    - This component MUST be mounted OUTSIDE the D-11 `pointer-events-none` locked container
      (Pitfall 6) so "Try Again" is always clickable after a mid-merge error.

  Props:
    onRetry   — called when the user presses "Try Again" (usually `syncStore.reset()`).
    onDismiss — called when the user presses "Dismiss" (usually `syncStore.reset()`).

  Source: 12-04-PLAN.md Task 1, 12-UI-SPEC.md §"Error Copy (D-15)",
    12-PATTERNS.md §"SyncErrorAlert.svelte (NEW)", 12-CONTEXT.md D-15.
-->
<script lang="ts">
  import { pairingStore } from './PairingStore.svelte';
  import { syncStore } from './SyncStore.svelte';
  import { syncErrorToCopy } from './syncErrorCopy';

  type Props = {
    /** Called when the user presses "Try Again". Usually `syncStore.reset()`. */
    onRetry: () => void;
    /** Called when the user presses "Dismiss". Usually `syncStore.reset()`. */
    onDismiss: () => void;
  };

  let { onRetry, onDismiss }: Props = $props();

  // Read the device name for heading substitution ("Couldn't reach {device name}").
  // pairingStore.peers is $state.raw — read through the getter, never copy into local $state.
  const deviceName = $derived(pairingStore.peers[0]?.deviceName ?? undefined);

  // Resolve the heading + body via the tested syncErrorToCopy mapper (D-15).
  // The error may be a typed error instance (if caller passes it) or the safe display
  // string stored in syncStore.lastError. We pass lastError as the primary signal.
  const errorCopy = $derived(syncErrorToCopy(syncStore.lastError, deviceName));
</script>

<!--
  role="alert": live-region — screen readers announce the heading immediately on mount.
  Danger shell: matches the SettingsShell inline danger-ack panel pattern exactly.
-->
<div
  role="alert"
  class="rounded-cryptiq border border-cryptiq-danger-border bg-cryptiq-danger-surface p-4"
>
  <!-- Warning icon + heading row -->
  <div class="mb-2 flex items-center gap-2">
    <svg
      class="size-4 shrink-0 text-cryptiq-danger"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="1.75"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      <path
        d="m10.29 3.86-8.18 14.17a1 1 0 0 0 .86 1.5h16.36a1 1 0 0 0 .86-1.5L11.71 3.86a1 1 0 0 0-1.72 0z"
      />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
    <p class="text-body font-semibold text-cryptiq-fg">{errorCopy.heading}</p>
  </div>

  <!-- Recovery hint body -->
  <p class="mb-3 text-body text-cryptiq-fg">{errorCopy.body}</p>

  <!-- Actions: Try Again (accent) + Dismiss (text) -->
  <div class="flex items-center gap-4">
    <button
      type="button"
      onclick={onRetry}
      class="rounded-cryptiq bg-cryptiq-accent px-3 py-1.5 text-body font-semibold text-cryptiq-accent-fg transition-colors hover:opacity-90"
    >
      Try Again
    </button>
    <button
      type="button"
      onclick={onDismiss}
      class="text-body text-cryptiq-fg-muted hover:text-cryptiq-fg"
    >
      Dismiss
    </button>
  </div>
</div>
