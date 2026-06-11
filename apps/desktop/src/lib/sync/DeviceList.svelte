<!--
  DeviceList.svelte — Paired device rows for the Settings → Sync section (UI-16).

  Each row shows:
    - Device name (click-to-rename via inline <input>)
    - Last synced relative time (via formatRelativeLastSynced from Plan 12-01)
    - Inline unpair confirm panel (no modal — D-17) driven by unpairConfirm reducer
      from Plan 12-01 (single-row-open invariant enforced by the reducer)

  Security:
    - Reads pairingStore.peers through the store getter in {#each} — NEVER copies
      peer data into local $state (preserves $state.raw discipline, Pitfall 7).
    - Rows render ONLY deviceName + last-synced relative time. No entry data.
    - D-16: NO live presence dot — status is last-synced only.
    - D-17: inline confirm (NO role="dialog" / aria-modal — not a modal).

  Source: 12-03-PLAN.md Task 1; 12-UI-SPEC.md "Device Management (UI-16) Copy";
          12-PATTERNS.md DeviceList section; 12-CONTEXT.md D-16/D-17.
-->
<script lang="ts">
  import { pairingStore } from './PairingStore.svelte';
  import {
    openUnpairConfirm,
    closeUnpairConfirm,
    isUnpairConfirming,
    type UnpairConfirmState,
  } from './unpairConfirm';
  import { formatRelativeLastSynced } from './syncFormat';

  // ---------------------------------------------------------------------------
  // Props
  // ---------------------------------------------------------------------------

  type Props = {
    /** Tauri app config directory — passed to pairingStore.unpair(). */
    configDir: string;
  };
  let { configDir }: Props = $props();

  // ---------------------------------------------------------------------------
  // Unpair confirm state — single $state for the whole list.
  // The unpairConfirm reducer enforces the single-row-open invariant:
  // opening a second row replaces the prior pending one.
  // ---------------------------------------------------------------------------
  let unpairState = $state<UnpairConfirmState>(null);

  // ---------------------------------------------------------------------------
  // Per-row rename state — track which deviceId is in rename mode and its
  // draft value. These are plain UI strings, not secret data.
  // ---------------------------------------------------------------------------
  let renamingDeviceId = $state<string | null>(null);
  let renameValue = $state('');

  // ---------------------------------------------------------------------------
  // Handlers
  // ---------------------------------------------------------------------------

  function startRename(deviceId: string, currentName: string): void {
    renamingDeviceId = deviceId;
    renameValue = currentName;
  }

  function commitRename(deviceId: string): void {
    const trimmed = renameValue.trim();
    if (trimmed.length > 0) {
      pairingStore.renameDevice(deviceId, trimmed);
    }
    renamingDeviceId = null;
    renameValue = '';
  }

  function cancelRename(): void {
    renamingDeviceId = null;
    renameValue = '';
  }

  function handleRenameKeydown(e: KeyboardEvent, deviceId: string): void {
    if (e.key === 'Enter') {
      e.preventDefault();
      commitRename(deviceId);
    } else if (e.key === 'Escape') {
      e.preventDefault();
      cancelRename();
    }
  }

  async function handleUnpair(deviceId: string): Promise<void> {
    await pairingStore.unpair(configDir, deviceId);
    unpairState = closeUnpairConfirm(unpairState);
  }
</script>

<!--
  {#each pairingStore.peers as peer (peer.deviceId)}
  Reads the store getter directly — NO local $state copy (Pitfall 7 / $state.raw discipline).
-->
{#each pairingStore.peers as peer (peer.deviceId)}
  <div>
    <!-- Standard settings-row layout (SettingsShell pattern lines 329-333) -->
    <div class="px-4 py-3.5">
      <div class="flex items-center justify-between gap-4">

        <!-- Left: device name + last-synced label -->
        <div class="min-w-0 flex-1">
          {#if renamingDeviceId === peer.deviceId}
            <!-- Inline rename input — Enter saves, Escape cancels -->
            <input
              type="text"
              bind:value={renameValue}
              onkeydown={(e) => handleRenameKeydown(e, peer.deviceId)}
              onblur={() => commitRename(peer.deviceId)}
              aria-label="Rename {peer.deviceName}"
              class="w-full rounded-cryptiq border border-cryptiq-border-strong bg-cryptiq-surface-2 px-2 py-0.5 text-body font-medium text-cryptiq-fg focus:border-cryptiq-accent focus:outline-none focus:ring-1 focus:ring-cryptiq-ring"
            />
          {:else}
            <p class="text-body font-medium text-cryptiq-fg">{peer.deviceName}</p>
          {/if}
          <p class="mt-0.5 text-meta text-cryptiq-fg-subtle">
            {formatRelativeLastSynced(peer.lastSyncedAt)}
          </p>
        </div>

        <!-- Right: action buttons -->
        <div class="flex shrink-0 items-center gap-3">
          <!-- Rename button (pencil icon) — appears as hover affordance -->
          {#if renamingDeviceId !== peer.deviceId}
            <button
              type="button"
              onclick={() => startRename(peer.deviceId, peer.deviceName)}
              aria-label="Rename {peer.deviceName}"
              title="Rename device"
              class="grid size-7 place-items-center rounded-cryptiq text-cryptiq-fg-subtle transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-fg focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cryptiq-ring"
            >
              <!-- Pencil icon (inline SVG) -->
              <svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" />
                <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" />
              </svg>
            </button>
          {/if}

          <!-- Remove button — opens the inline unpair confirm panel -->
          {#if !isUnpairConfirming(unpairState, peer.deviceId)}
            <button
              type="button"
              onclick={() => { unpairState = openUnpairConfirm(unpairState, peer.deviceId); }}
              class="shrink-0 text-meta text-cryptiq-fg-muted transition-colors hover:text-cryptiq-danger focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cryptiq-ring"
            >
              Remove
            </button>
          {/if}
        </div>
      </div>

      <!-- Inline unpair danger-ack panel (D-17 — no modal, no role="dialog") -->
      <!-- isUnpairConfirming gates this per-row (single-row-open via reducer) -->
      {#if isUnpairConfirming(unpairState, peer.deviceId)}
        <div class="mt-3 rounded-cryptiq border border-cryptiq-danger-border bg-cryptiq-danger-surface p-4">
          <!-- Warning icon + eyebrow -->
          <div class="mb-2 flex items-center gap-2">
            <svg class="size-4 shrink-0 text-cryptiq-danger" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="m10.29 3.86-8.18 14.17a1 1 0 0 0 .86 1.5h16.36a1 1 0 0 0 .86-1.5L11.71 3.86a1 1 0 0 0-1.72 0z" />
              <line x1="12" y1="9" x2="12" y2="13" />
              <line x1="12" y1="17" x2="12.01" y2="17" />
            </svg>
          </div>
          <!-- Heading -->
          <p class="mb-1 text-body font-semibold text-cryptiq-fg">Remove {peer.deviceName}?</p>
          <!-- Body (UI-SPEC exact copy) -->
          <p class="mb-3 text-body text-cryptiq-fg">
            This removes the pairing record. The other device will no longer be able to sync with you.
          </p>
          <!-- Actions — grouped for accessibility (UI-SPEC Accessibility Contract) -->
          <div
            role="group"
            aria-label="Remove {peer.deviceName}?"
            class="flex items-center gap-4"
          >
            <button
              type="button"
              onclick={() => void handleUnpair(peer.deviceId)}
              class="rounded-cryptiq bg-cryptiq-danger px-3 py-1.5 text-body font-semibold text-cryptiq-danger-fg transition-colors hover:opacity-90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cryptiq-ring"
            >
              Remove {peer.deviceName}
            </button>
            <button
              type="button"
              onclick={() => { unpairState = closeUnpairConfirm(unpairState); }}
              class="text-body text-cryptiq-fg-muted transition-colors hover:text-cryptiq-fg focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cryptiq-ring"
            >
              Cancel
            </button>
          </div>
        </div>
      {/if}
    </div>

    <!-- Row divider (not after the last row — Svelte's {#each} index needed) -->
    {#if peer.deviceId !== pairingStore.peers[pairingStore.peers.length - 1]?.deviceId}
      <div class="mx-4 border-t border-cryptiq-border" aria-hidden="true"></div>
    {/if}
  </div>
{/each}
