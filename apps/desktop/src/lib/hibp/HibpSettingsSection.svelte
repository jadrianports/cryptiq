<!--
  HibpSettingsSection.svelte — Settings → "Breach Checking" toggle row (HIBP-01, D-01).

  Mirrors SyncSettingsSection.svelte / ExtensionSettingsSection.svelte's device-local
  toggle shape exactly (role="switch" aria-checked, h-5 w-9 track, size-4 thumb,
  bg-cryptiq-accent ON / bg-cryptiq-border-strong OFF).

  The load-bearing deviation from those two toggles (D-03): turning ON does NOT
  self-persist on click. It opens HibpConsentDialog.svelte first — the toggle only
  flips ON and hibpEntryScanEnabled only becomes true on the dialog's explicit
  "Enable breach checking" confirm. Cancel/Escape/backdrop-click leaves the toggle
  OFF and persists nothing. Turning OFF (ON -> OFF) flips immediately with no
  dialog (D-01 SS6 — non-destructive, no data loss).

  Security:
    - Reads cfg.hibpEntryScanEnabled ?? false in onMount — default OFF on every
      fresh install and every pre-Phase-31 config.json (field absent).
    - Every saveConfig call spreads a freshly loaded config (never a bare object),
      so a toggle write can't drop listenerEnabled/extensionBridgeEnabled/vaultPath.
    - No Rust start/stop side effect (HIBP has no listener, unlike sync/extension
      kill-switches). Never logs anything password-derived.

  Source: 31-03-PLAN.md Task 1; 31-UI-SPEC.md "Interaction Contract §1" +
          "Copywriting Contract"; 31-PATTERNS.md HibpSettingsSection section;
          31-CONTEXT.md D-01/D-02/D-03.
-->
<script lang="ts">
  import { onMount } from 'svelte';
  import { loadConfig, saveConfig } from '../config/config-adapter';
  import HibpConsentDialog from './HibpConsentDialog.svelte';

  // ---------------------------------------------------------------------------
  // Toggle state — default OFF (D-02). Populated from config.json on mount.
  // ---------------------------------------------------------------------------
  let entryScanEnabled = $state(false);

  onMount(async () => {
    const cfg = await loadConfig();
    entryScanEnabled = cfg.hibpEntryScanEnabled ?? false;
  });

  // ---------------------------------------------------------------------------
  // D-03 consent gate: OFF -> ON opens the dialog instead of self-persisting.
  // ---------------------------------------------------------------------------
  let showConsentDialog = $state(false);

  function handleToggleClick(): void {
    if (entryScanEnabled) {
      // ON -> OFF: flips immediately, no dialog, persists false (D-01 SS6).
      void handleDisable();
    } else {
      // OFF -> ON: open the disclosure dialog first — do NOT persist yet.
      showConsentDialog = true;
    }
  }

  async function handleDisable(): Promise<void> {
    entryScanEnabled = false;
    const currentConfig = await loadConfig();
    await saveConfig({ ...currentConfig, hibpEntryScanEnabled: false });
  }

  /**
   * The ONLY site that ever persists hibpEntryScanEnabled: true — reachable
   * exclusively from HibpConsentDialog's confirm handler below, never from the
   * toggle's onclick directly (D-03, acceptance-grepped).
   */
  async function handleConsentConfirm(): Promise<void> {
    const currentConfig = await loadConfig();
    await saveConfig({ ...currentConfig, hibpEntryScanEnabled: true });
    entryScanEnabled = true;
    showConsentDialog = false;
  }

  function handleConsentCancel(): void {
    // Consent stays OFF, nothing persisted (D-03).
    showConsentDialog = false;
  }
</script>

<div class="flex items-center justify-between gap-4 px-4 py-3.5">
  <div class="min-w-0">
    <p class="text-body font-medium text-cryptiq-fg">Check passwords against known breaches</p>
    <p class="mt-0.5 text-meta text-cryptiq-fg-subtle">
      {#if entryScanEnabled}
        Passwords are checked against known breaches using k-anonymity — only a 5-character
        hash prefix ever leaves this device.
      {:else}
        Cryptiq can check your stored passwords against HaveIBeenPwned's Pwned Passwords
        list. Off by default — enabling sends a partial hash for each password over the
        network.
      {/if}
    </p>
  </div>
  <!-- Toggle switch — identical shape to SyncSettingsSection's / ExtensionSettingsSection's
       device-local toggles (cryptiq-* tokens only, h-5 w-9, size-4). -->
  <button
    type="button"
    role="switch"
    aria-checked={entryScanEnabled}
    aria-label="Check passwords against known breaches"
    onclick={handleToggleClick}
    class="relative h-5 w-9 shrink-0 rounded-full transition-colors
           {entryScanEnabled ? 'bg-cryptiq-accent' : 'bg-cryptiq-border-strong'}"
  >
    <span
      class="absolute top-0.5 left-0.5 size-4 rounded-full bg-white shadow-cryptiq-panel transition-transform
             {entryScanEnabled ? 'translate-x-4' : ''}"
    ></span>
  </button>
</div>

{#if showConsentDialog}
  <HibpConsentDialog
    kind="entry-scan"
    onConfirm={() => void handleConsentConfirm()}
    onCancel={handleConsentCancel}
  />
{/if}
