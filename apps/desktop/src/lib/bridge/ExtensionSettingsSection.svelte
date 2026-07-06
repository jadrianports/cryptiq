<!--
  ExtensionSettingsSection.svelte — Association rows for the Settings -> Browser
  Extensions section (BRIDGE-09 / D-03).

  Each row shows:
    - Label (click-to-rename via inline <input>) — auto-named from the detected
      browser at approval (D-02), renamable here.
    - Paired date + last-used relative time (bridgeFormat.ts) — DeviceList only has
      "last synced"; this section adds the last-used row DeviceList lacks (D-03).
    - Inline revoke confirm panel (no modal — mirrors D-17's inline-panel discipline)
      driven by the extensionUnpairConfirm reducer (single-row-open invariant).

  Security:
    - Reads extensionPeerStore.associations through the store getter in {#each} —
      NEVER copies association data into local $state (preserves $state.raw
      discipline, T-15-10).
    - Rows render ONLY label + detected-browser + paired/last-used timestamps. No
      vault entry data, no raw public key, no pairing token.
    - Revoke removes ONLY that one association (V4 Access Control) — the app's own
      identification keypair is untouched.

  Source: 15-05-PLAN.md Task 2; 15-PATTERNS.md "ExtensionSettingsSection.svelte";
          15-CONTEXT.md D-03/D-04.
-->
<script lang="ts">
  import { onMount } from 'svelte';
  import { extensionPeerStore } from './ExtensionPeerStore.svelte';
  import {
    openExtensionRevokeConfirm,
    closeExtensionRevokeConfirm,
    isExtensionRevokeConfirming,
    type ExtensionRevokeConfirmState,
  } from './extensionUnpairConfirm';
  import { formatPairedAt, formatLastUsedAt } from './bridgeFormat';
  import { loadConfig, saveConfig } from '../config/config-adapter';
  import {
    startExtensionBridgeListener,
    stopExtensionBridgeListener,
  } from './bridgeCommands';

  // ---------------------------------------------------------------------------
  // Props
  // ---------------------------------------------------------------------------

  type Props = {
    /** Tauri app config directory — passed to extensionPeerStore.revoke()/renameLabel(). */
    configDir: string;
  };
  let { configDir }: Props = $props();

  // ---------------------------------------------------------------------------
  // UX-05 Kill-switch: "Allow browser extension connections"
  //
  // Initialized from loadConfig().extensionBridgeEnabled (default true when
  // absent). Persisted to device-local config.json via saveConfig — NEVER to
  // InnerDoc.settings or vaultSession (D-04). Associations persist while OFF
  // (D-02). NOT gated on vaultSession.isUnlocked — this is a device config
  // preference, mirroring SyncSettingsSection's listener toggle (D-03).
  // ---------------------------------------------------------------------------
  let bridgeEnabled = $state(true);

  onMount(async () => {
    const cfg = await loadConfig();
    bridgeEnabled = cfg.extensionBridgeEnabled ?? true;
  });

  async function handleBridgeToggle(): Promise<void> {
    const next = !bridgeEnabled;
    bridgeEnabled = next;
    // Load the full current config first so vaultPath/schemaVersion/listenerEnabled
    // are preserved (never a bare {extensionBridgeEnabled} object — T-20-10).
    const currentConfig = await loadConfig();
    await saveConfig({ ...currentConfig, extensionBridgeEnabled: next });
    // Drive the real Rust listener lifecycle — the toggle must not lie about the
    // pipe state (T-20-09). OFF actually stops accepting connections (D-01).
    if (next) {
      await startExtensionBridgeListener();
    } else {
      await stopExtensionBridgeListener();
    }
  }

  // ---------------------------------------------------------------------------
  // Revoke confirm state — single $state for the whole list.
  // The extensionUnpairConfirm reducer enforces the single-row-open invariant:
  // opening a second row replaces the prior pending one.
  // ---------------------------------------------------------------------------
  let revokeState = $state<ExtensionRevokeConfirmState>(null);

  // ---------------------------------------------------------------------------
  // Per-row rename state — track which clientId is in rename mode and its
  // draft value. These are plain UI strings, not secret data.
  // ---------------------------------------------------------------------------
  let renamingClientId = $state<string | null>(null);
  let renameValue = $state('');

  // ---------------------------------------------------------------------------
  // Handlers
  // ---------------------------------------------------------------------------

  function startRename(clientId: string, currentLabel: string): void {
    renamingClientId = clientId;
    renameValue = currentLabel;
  }

  async function commitRename(clientId: string): Promise<void> {
    const trimmed = renameValue.trim();
    if (trimmed.length > 0) {
      await extensionPeerStore.renameLabel(configDir, clientId, trimmed);
    }
    renamingClientId = null;
    renameValue = '';
  }

  function cancelRename(): void {
    renamingClientId = null;
    renameValue = '';
  }

  function handleRenameKeydown(e: KeyboardEvent, clientId: string): void {
    if (e.key === 'Enter') {
      e.preventDefault();
      void commitRename(clientId);
    } else if (e.key === 'Escape') {
      e.preventDefault();
      cancelRename();
    }
  }

  async function handleRevoke(clientId: string): Promise<void> {
    await extensionPeerStore.revoke(configDir, clientId);
    revokeState = closeExtensionRevokeConfirm(revokeState);
  }
</script>

<!-- UX-05 Kill-switch toggle (D-03) — top of the Browser Extensions section, above
     the associations list. Persists extensionBridgeEnabled to device-local config.json
     (never InnerDoc.settings — D-04) and drives the Rust start/stop listener commands
     (20-01). Associations persist while OFF (D-02). NOT gated on vault-unlock. -->
<div class="flex items-center justify-between gap-4 px-4 py-3.5">
  <div class="min-w-0">
    <p class="text-body font-medium text-cryptiq-fg">Allow browser extension connections</p>
    <p class="mt-0.5 text-meta text-cryptiq-fg-subtle">
      Let the Cryptiq browser extension talk to this app on this device.
    </p>
  </div>
  <!-- Toggle switch — LOCKED design system, identical shape to SyncSettingsSection's
       "Receive syncs on this device" toggle (cryptiq-* tokens only, h-5 w-9, size-4). -->
  <button
    type="button"
    role="switch"
    aria-checked={bridgeEnabled}
    aria-label="Allow browser extension connections"
    onclick={handleBridgeToggle}
    class="relative h-5 w-9 shrink-0 rounded-full transition-colors
           {bridgeEnabled ? 'bg-cryptiq-accent' : 'bg-cryptiq-border-strong'}"
  >
    <span
      class="absolute top-0.5 left-0.5 size-4 rounded-full bg-white shadow-cryptiq-panel transition-transform
             {bridgeEnabled ? 'translate-x-4' : ''}"
    ></span>
  </button>
</div>

{#if !bridgeEnabled}
  <p class="px-4 pb-3.5 text-meta text-cryptiq-fg-subtle">
    Connections are off — associations are kept
  </p>
{/if}

<div class="mx-4 border-t border-cryptiq-border" aria-hidden="true"></div>

{#if extensionPeerStore.associations.length === 0}
  <!-- Empty state — no browser extensions paired yet -->
  <div class="flex flex-col items-center gap-2 px-6 py-8 text-center">
    <p class="text-body font-medium text-cryptiq-fg">No browser extensions paired yet</p>
    <p class="text-meta text-cryptiq-fg-subtle">
      Install the Cryptiq browser extension and approve it here on first connection.
    </p>
  </div>
{:else}
  <!--
    {#each extensionPeerStore.associations as assoc (assoc.clientId)}
    Reads the store getter directly — NO local $state copy ($state.raw discipline, T-15-10).
  -->
  {#each extensionPeerStore.associations as assoc (assoc.clientId)}
    <div>
      <!-- Standard settings-row layout (SettingsShell pattern, mirrors DeviceList) -->
      <div class="px-4 py-3.5">
        <div class="flex items-center justify-between gap-4">

          <!-- Left: label + paired/last-used timestamps -->
          <div class="min-w-0 flex-1">
            {#if renamingClientId === assoc.clientId}
              <!-- Inline rename input — Enter saves, Escape cancels -->
              <input
                type="text"
                bind:value={renameValue}
                onkeydown={(e) => handleRenameKeydown(e, assoc.clientId)}
                onblur={() => void commitRename(assoc.clientId)}
                aria-label="Rename {assoc.label}"
                class="w-full rounded-cryptiq border border-cryptiq-border-strong bg-cryptiq-surface-2 px-2 py-0.5 text-body font-medium text-cryptiq-fg focus:border-cryptiq-accent focus:outline-none focus:ring-1 focus:ring-cryptiq-ring"
              />
            {:else}
              <p class="text-body font-medium text-cryptiq-fg">{assoc.label}</p>
            {/if}
            <p class="mt-0.5 text-meta text-cryptiq-fg-subtle">
              {formatPairedAt(assoc.pairedAt)} · {formatLastUsedAt(assoc.lastUsedAt)}
            </p>
          </div>

          <!-- Right: action buttons -->
          <div class="flex shrink-0 items-center gap-3">
            <!-- Rename button (pencil icon) -->
            {#if renamingClientId !== assoc.clientId}
              <button
                type="button"
                onclick={() => startRename(assoc.clientId, assoc.label)}
                aria-label="Rename {assoc.label}"
                title="Rename association"
                class="grid size-7 place-items-center rounded-cryptiq text-cryptiq-fg-subtle transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-fg focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cryptiq-ring"
              >
                <!-- Pencil icon (inline SVG) -->
                <svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                  <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" />
                  <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" />
                </svg>
              </button>
            {/if}

            <!-- Revoke button — opens the inline revoke confirm panel -->
            {#if !isExtensionRevokeConfirming(revokeState, assoc.clientId)}
              <button
                type="button"
                onclick={() => { revokeState = openExtensionRevokeConfirm(revokeState, assoc.clientId); }}
                class="shrink-0 text-meta text-cryptiq-fg-muted transition-colors hover:text-cryptiq-danger focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cryptiq-ring"
              >
                Revoke
              </button>
            {/if}
          </div>
        </div>

        <!-- Inline revoke danger-ack panel (D-04 — confirm, not instant) -->
        {#if isExtensionRevokeConfirming(revokeState, assoc.clientId)}
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
            <p class="mb-1 text-body font-semibold text-cryptiq-fg">Revoke {assoc.label}?</p>
            <!-- Body -->
            <p class="mb-3 text-body text-cryptiq-fg">
              This removes the association. The extension will need to be re-approved to reconnect.
            </p>
            <!-- Actions — grouped for accessibility -->
            <div
              role="group"
              aria-label="Revoke {assoc.label}?"
              class="flex items-center gap-4"
            >
              <button
                type="button"
                onclick={() => void handleRevoke(assoc.clientId)}
                class="rounded-cryptiq bg-cryptiq-danger px-3 py-1.5 text-body font-semibold text-cryptiq-danger-fg transition-colors hover:opacity-90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cryptiq-ring"
              >
                Revoke {assoc.label}
              </button>
              <button
                type="button"
                onclick={() => { revokeState = closeExtensionRevokeConfirm(revokeState); }}
                class="text-body text-cryptiq-fg-muted transition-colors hover:text-cryptiq-fg focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cryptiq-ring"
              >
                Cancel
              </button>
            </div>
          </div>
        {/if}
      </div>

      <!-- Row divider (not after the last row) -->
      {#if assoc.clientId !== extensionPeerStore.associations[extensionPeerStore.associations.length - 1]?.clientId}
        <div class="mx-4 border-t border-cryptiq-border" aria-hidden="true"></div>
      {/if}
    </div>
  {/each}
{/if}
