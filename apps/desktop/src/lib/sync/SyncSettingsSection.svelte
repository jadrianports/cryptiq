<!--
  SyncSettingsSection.svelte — Sync section body for Settings → Sync (UI-16 / D-01).

  Renders:
    - Empty state with "Pair a Device" CTA when no peers are paired (D-02).
    - DeviceList when at least one peer is paired (D-16/D-17).
    - D-18 "Paired! Sync now?" inline prompt after a pairing transitions 0→>0
      (user-initiated — does NOT auto-run sync on mount or in any unconditional $effect).
    - D-01 "Receive syncs on this device" kill-switch toggle (Plan 13-06).
      Persists listenerEnabled to device-local config.json (never InnerDoc.settings — D-03).
      Outbound Sync Now remains available when OFF (D-02).

  Security:
    - NO entry data anywhere (UI-18 fence).
    - NO literal hex/oklch — cryptiq-* tokens only.
    - D-18 "Sync Now" calls onSyncNow() which routes to the header sync trigger
      via go('main') — does NOT call runSyncNow() directly (not a silent auto-sync).
    - This component does NOT host the firewall heads-up — PairingScreen is the
      single owner of the pre-listener firewall notice (Plan 12-02).
    - The kill-switch toggle is NOT gated on vaultSession.isUnlocked — it is a
      device-local config preference, not a vault setting (D-03 / Plan 13-06).

  Source: 12-03-PLAN.md Task 2; 12-UI-SPEC.md "Device Management (UI-16) Copy",
          "Pairing success"; 12-PATTERNS.md SyncSettingsSection section;
          12-CONTEXT.md D-01/D-02/D-18; 13-06-PLAN.md Task 1.
-->
<script lang="ts">
  import { onMount } from 'svelte';
  import { pairingStore } from './PairingStore.svelte';
  import DeviceList from './DeviceList.svelte';
  import { loadConfig, saveConfig } from '../config/config-adapter';
  import {
    startSyncListenerIfPaired,
    stopSyncListener,
  } from './syncOrchestration';

  // ---------------------------------------------------------------------------
  // Props
  // ---------------------------------------------------------------------------

  type Props = {
    /** Tauri app config directory — passed to DeviceList for unpair calls and
     *  to startSyncListenerIfPaired when the kill-switch is flipped ON. */
    configDir: string;
    /** Vault file path — passed to startSyncListenerIfPaired when the kill-switch
     *  is flipped ON (D-01 / Plan 13-06). */
    vaultPath: string;
    /** Called when the user wants to open the PairingScreen sub-view. */
    onPair: () => void;
    /**
     * Called when the user clicks "Sync Now" in the D-18 post-pairing prompt.
     * Concrete handler in SettingsShell: routes the user to go('main') so the
     * header Sync Now button (Plan 12-04) is the user-initiated sync entry.
     * Must NOT be a no-op — the plan requires a real navigation handler.
     */
    onSyncNow: () => void;
  };

  let { configDir, vaultPath, onPair, onSyncNow }: Props = $props();

  // ---------------------------------------------------------------------------
  // D-01 Kill-switch: "Receive syncs on this device"
  //
  // Initialized from loadConfig().listenerEnabled (default true when absent).
  // Persisted to device-local config.json via saveConfig — NEVER to
  // InnerDoc.settings or vaultSession (D-03). Outbound Sync Now is unaffected (D-02).
  // NOT gated on vaultSession.isUnlocked — this is a device config preference.
  // ---------------------------------------------------------------------------
  let listenerEnabled = $state(true);

  onMount(async () => {
    const cfg = await loadConfig();
    listenerEnabled = cfg.listenerEnabled ?? true;
  });

  async function handleListenerToggle(): Promise<void> {
    const next = !listenerEnabled;
    listenerEnabled = next;
    // Load the full current config first so vaultPath/schemaVersion are preserved.
    const currentConfig = await loadConfig();
    await saveConfig({ ...currentConfig, listenerEnabled: next });
    if (next) {
      await startSyncListenerIfPaired(configDir, vaultPath);
    } else {
      await stopSyncListener();
    }
  }

  // ---------------------------------------------------------------------------
  // D-18 "Paired! Sync now?" transient prompt state.
  //
  // justPaired is set to true when the peers count transitions 0 → >0.
  // It is NOT set on mount when peers are already > 0 (no prompt for pre-existing peers).
  // Cleared by clicking "Sync Now" or "Not yet".
  //
  // This is plain $state (the boolean is not secret data).
  // The $effect only fires on peers array reference change — it does NOT call
  // runSyncNow or any sync trigger (D-18 user-initiated invariant).
  // ---------------------------------------------------------------------------
  let justPaired = $state(false);
  let prevPeersLength = $state(pairingStore.peers.length);

  $effect(() => {
    const currentLength = pairingStore.peers.length;
    if (prevPeersLength === 0 && currentLength > 0) {
      justPaired = true;
    }
    prevPeersLength = currentLength;
  });

  function handleSyncNow(): void {
    justPaired = false;
    onSyncNow();
  }

  function handleNotYet(): void {
    justPaired = false;
  }
</script>

{#if pairingStore.peers.length === 0}
  <!-- Empty state (no peers paired yet) — UI-SPEC "Device Management" empty state copy -->
  <div class="flex flex-col items-center gap-3 px-6 py-8 text-center">
    <p class="text-body font-medium text-cryptiq-fg">No devices paired yet</p>
    <p class="text-meta text-cryptiq-fg-subtle">
      Pair another device running Cryptiq on the same network to sync your vault.
    </p>
    <button
      type="button"
      onclick={onPair}
      class="rounded-cryptiq bg-cryptiq-accent px-4 py-2 text-body font-semibold text-cryptiq-accent-fg transition-colors hover:bg-cryptiq-accent-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cryptiq-ring"
    >
      Pair a Device
    </button>
  </div>

  <div class="mx-4 border-t border-cryptiq-border" aria-hidden="true"></div>

  <!-- D-01 Kill-switch toggle (Plan 13-06) — shown regardless of pairing state;
       the listener preference is a device-local config setting, not a vault setting. -->
  <div class="flex items-center justify-between gap-4 px-4 py-3.5">
    <div class="min-w-0">
      <p class="text-body font-medium text-cryptiq-fg">Receive syncs on this device</p>
      <p class="mt-0.5 text-meta text-cryptiq-fg-subtle">
        Allow paired devices to push updates to this device's vault.
      </p>
    </div>
    <!-- Toggle switch — identical shape to the lock-on-minimize toggle (SettingsShell.svelte lines 452–467) -->
    <button
      type="button"
      role="switch"
      aria-checked={listenerEnabled}
      aria-label="Receive syncs on this device"
      onclick={handleListenerToggle}
      class="relative h-5 w-9 shrink-0 rounded-full transition-colors
             {listenerEnabled ? 'bg-cryptiq-accent' : 'bg-cryptiq-border-strong'}"
    >
      <span
        class="absolute top-0.5 left-0.5 size-4 rounded-full bg-white shadow-cryptiq-panel transition-transform
               {listenerEnabled ? 'translate-x-4' : ''}"
      ></span>
    </button>
  </div>

  {#if !listenerEnabled}
    <p class="px-4 pb-3.5 text-meta text-cryptiq-fg-subtle">
      Incoming syncs are off — Sync Now still works
    </p>
  {/if}
{:else}
  <!-- Device list — rendered when at least one peer is paired (D-16/D-17) -->
  <DeviceList {configDir} />

  <div class="mx-4 border-t border-cryptiq-border" aria-hidden="true"></div>

  <!-- D-01 Kill-switch toggle (Plan 13-06) — after DeviceList, before D-18 prompt.
       Persists listenerEnabled to device-local config.json (D-03 — never InnerDoc.settings).
       Outbound Sync Now remains available when OFF (D-02). -->
  <div class="flex items-center justify-between gap-4 px-4 py-3.5">
    <div class="min-w-0">
      <p class="text-body font-medium text-cryptiq-fg">Receive syncs on this device</p>
      <p class="mt-0.5 text-meta text-cryptiq-fg-subtle">
        Allow paired devices to push updates to this device's vault.
      </p>
    </div>
    <!-- Toggle switch — identical shape to the lock-on-minimize toggle (SettingsShell.svelte lines 452–467) -->
    <button
      type="button"
      role="switch"
      aria-checked={listenerEnabled}
      aria-label="Receive syncs on this device"
      onclick={handleListenerToggle}
      class="relative h-5 w-9 shrink-0 rounded-full transition-colors
             {listenerEnabled ? 'bg-cryptiq-accent' : 'bg-cryptiq-border-strong'}"
    >
      <span
        class="absolute top-0.5 left-0.5 size-4 rounded-full bg-white shadow-cryptiq-panel transition-transform
               {listenerEnabled ? 'translate-x-4' : ''}"
      ></span>
    </button>
  </div>

  {#if !listenerEnabled}
    <p class="px-4 pb-3.5 text-meta text-cryptiq-fg-subtle">
      Incoming syncs are off — Sync Now still works
    </p>
  {/if}

  <!-- D-18 "Paired! Sync now?" inline prompt — user-initiated only.
       Appears after a successful pairing (peers 0→>0 transition).
       Does NOT call runSyncNow on mount or in any unconditional $effect. -->
  {#if justPaired}
    <div class="mx-4 border-t border-cryptiq-border" aria-hidden="true"></div>
    <div class="flex items-center justify-between gap-4 px-4 py-3.5">
      <p class="text-body font-medium text-cryptiq-fg">Paired! Sync now?</p>
      <div class="flex shrink-0 items-center gap-3">
        <button
          type="button"
          onclick={handleSyncNow}
          class="rounded-cryptiq bg-cryptiq-accent px-3 py-1.5 text-body font-semibold text-cryptiq-accent-fg transition-colors hover:bg-cryptiq-accent-hover focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cryptiq-ring"
        >
          Sync Now
        </button>
        <button
          type="button"
          onclick={handleNotYet}
          class="text-body text-cryptiq-fg-muted transition-colors hover:text-cryptiq-fg focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cryptiq-ring"
        >
          Not yet
        </button>
      </div>
    </div>
  {/if}
{/if}
