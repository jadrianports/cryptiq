<!--
  SettingsShell.svelte — Settings screen (UI-13).

  Phase 5 scope: live wiring of security controls.

  Controls (UI-13):
    1. Auto-lock timeout     — live <select> (1/5/15/30/Never). "Never" requires
                               an explicit danger-ack before persisting (P5-03).
    2. Lock-on-minimize      — toggle (OFF default, P5-05). Persists to settings.lock.
    3. Clipboard auto-clear  — disabled placeholder (Phase 5: LOCK-02/06)
    4. Change master password — enabled → go('change-master') (AUTH-10)
    5. Favicon fetch toggle   — rendered OFF by default (UI-10); no network call
                                in this phase (T-04-23). Toggle is visually interactive
                                but its state does NOT persist this phase.

  Post-change success panel (ROADMAP SC-5 / UI-SPEC Surface 4):
    When changeMasterSuccess.value is true (set by ChangeMasterView before
    go('settings')), a calm "Master password changed." + "Your recovery key still
    works." panel renders in the Security section below the Change button.
    Cleared via setChangeMasterSuccess(false) on onDestroy / navigation away.

  Security (T-5-SETTINGS):
    Lock settings persist to encrypted InnerDoc.settings.lock — never to plaintext
    config. All reads go through getVaultSettings() (Pitfall 7 defense). "Never"
    is gated by an explicit danger-ack so the user cannot accidentally disable
    auto-lock (P5-03).

  Token rules: cryptiq-* tokens only; no literal hex/oklch.
-->
<script lang="ts">
  import { onDestroy } from 'svelte';
  import { go, changeMasterSuccess, setChangeMasterSuccess } from '../state/view.svelte';
  import { vaultSession } from '../state/vault.svelte';
  import { getVaultSettings } from '@cryptiq/core';
  import { save as dialogSave } from '@tauri-apps/plugin-dialog';
  import { invoke } from '@tauri-apps/api/core';
  import { pushToast } from '../state/ui.svelte';
  import { setNativeDialogOpen, clearNativeDialogOpen } from '../state/dialogGuard.svelte';
  import ConfirmMasterPassword from '../components/ConfirmMasterPassword.svelte';
  import AboutView from './AboutView.svelte';
  import PairingScreen from '../sync/PairingScreen.svelte';
  import SyncSettingsSection from '../sync/SyncSettingsSection.svelte';

  /**
   * Props contract for Phase 12 (Plan 12-01 Task 3).
   * configDir and vaultPath are threaded from App.svelte so Plan 12-03 can
   * host the Sync section + PairingScreen sub-view without prop-drilling.
   */
  type Props = {
    /** Tauri app config directory (passed to sync/pairing Rust commands). */
    configDir: string;
    /** Filesystem path to the vault file (passed to Rust sync listener). */
    vaultPath: string;
  };
  let { configDir, vaultPath }: Props = $props();

  // ── Favicon toggle local state (UI-10) ────────────────────────────────────
  // OFF by default. NOT persisted — the toggle is a preview of the control
  // shape for a future update. No network call made regardless of state.
  let faviconEnabled = $state(false);

  // ── Current generator default mode (for the generator row summary) ────────
  function getGeneratorDefault(vault: { entries: object } | null): string {
    if (vault === null) return 'Random';
    const raw = vault.entries as Record<string, unknown>;
    const settings = raw['settings'] as Record<string, unknown> | undefined;
    const gen = settings?.['generator'] as Record<string, unknown> | undefined;
    if (!gen) return 'Random';
    return gen['mode'] === 'passphrase' ? 'Passphrase' : 'Random';
  }

  const generatorDefaultLabel = $derived(getGeneratorDefault(vaultSession.vault));

  // ── Lock settings (Pitfall 7 defense) ─────────────────────────────────────
  // Read the PRIMITIVES directly off vaultSession.vault so each $derived depends
  // on the #vault reference (reassigned by saveSettingsChange) and yields a
  // value-type. Do NOT route through an intermediate `lockSettings` object
  // $derived: an in-place settings mutation keeps the SAME `.lock` object
  // reference, so that intermediate is === its previous value and Svelte
  // short-circuits propagation — the toggle then only refreshes on remount
  // (Svelte 5 ref-equality short-circuit; same class as the Phase 4 entry-list
  // bug). Reading the boolean/number directly avoids that. Guarded for the
  // locked state (vault === null).
  const currentIdleMinutes = $derived(
    vaultSession.vault !== null
      ? (getVaultSettings(vaultSession.vault).lock?.idleMinutes ?? 5)
      : 5,
  );

  const currentLockOnMinimize = $derived(
    vaultSession.vault !== null
      ? (getVaultSettings(vaultSession.vault).lock?.lockOnMinimize ?? false)
      : false,
  );

  // ── Never danger-ack state ─────────────────────────────────────────────────
  let showNeverAck = $state(false);
  let neverAckChecked = $state(false);
  // Track the previous value so we can revert if the user cancels.
  let preNeverValue = $state<number | 'never'>(5);

  // ── Select visual value (local $state for immediate revert on "Never") ────
  // Drives the <select bind:value> so we can reset the displayed option
  // immediately when "Never" is chosen (before the user confirms), keeping
  // the dropdown in sync with the persisted setting while the ack panel is open.
  // Synced back from currentIdleMinutes after every vault save (the $derived
  // reference changes when vaultSession.save() reassigns #vault).
  // Initialized to '5' (the default fallback); the $effect below syncs it from
  // currentIdleMinutes on the first render and after every vault save.
  let selectedIdleValue = $state('5');
  $effect(() => {
    // Re-sync whenever currentIdleMinutes changes (post-save or on initial load).
    // Only update if the ack panel is closed — while it is open the select must
    // show the pre-Never value, not "never".
    if (!showNeverAck) {
      selectedIdleValue = String(currentIdleMinutes);
    }
  });

  // ── Save lock setting helper ───────────────────────────────────────────────
  async function saveLockSettings(
    update: Partial<{ idleMinutes: number | 'never'; lockOnMinimize: boolean }>,
  ): Promise<void> {
    if (!vaultSession.isUnlocked || vaultSession.vault === null) return;
    const vault = vaultSession.vault;
    // Read via getVaultSettings to ensure defaults are filled (Pitfall 7).
    const settings = getVaultSettings(vault);
    // Mutate the InnerDoc settings.lock in place — same pattern as
    // GeneratorScreen.handleSaveDefault (single-cast strategy).
    if (update.idleMinutes !== undefined) {
      settings.lock!.idleMinutes = update.idleMinutes;
    }
    if (update.lockOnMinimize !== undefined) {
      settings.lock!.lockOnMinimize = update.lockOnMinimize;
    }
    // saveSettingsChange reassigns #vault ($state.raw) so the toggle/select
    // $derived values recompute — plain save() mutates in place and the UI
    // would stay frozen (the lock-on-minimize "stuck toggle" bug).
    await vaultSession.saveSettingsChange();
  }

  // ── Idle timeout select handler ────────────────────────────────────────────
  async function handleIdleChange(e: Event): Promise<void> {
    const select = e.target as HTMLSelectElement;
    const raw = select.value;

    if (raw === 'never') {
      // "Never" selected — store previous value and open the danger-ack panel.
      // Do NOT persist yet.
      preNeverValue = currentIdleMinutes;
      neverAckChecked = false;
      showNeverAck = true;
      // Revert the <select> visual to the previous value immediately so
      // the UI doesn't show "Never" until the user confirms.
      // selectedIdleValue drives the bind:value on the <select>; resetting it
      // here causes Svelte to re-render the control to the prior option before
      // the ack panel appears — the dropdown never visually lands on "Never".
      selectedIdleValue = String(preNeverValue);
    } else {
      // 1/5/15/30 — persist immediately.
      showNeverAck = false;
      await saveLockSettings({ idleMinutes: parseInt(raw, 10) });
    }
  }

  // "Confirm — disable auto-lock" in the danger-ack panel.
  async function handleNeverConfirm(): Promise<void> {
    if (!neverAckChecked) return;
    showNeverAck = false;
    await saveLockSettings({ idleMinutes: 'never' });
  }

  // "Cancel" in the danger-ack panel — revert dropdown.
  async function handleNeverCancel(): Promise<void> {
    showNeverAck = false;
    neverAckChecked = false;
    // Revert to the previous value (persists pre-Never setting; $effect will
    // re-sync selectedIdleValue from currentIdleMinutes after the vault save
    // reassigns #vault, keeping the select in sync).
    await saveLockSettings({ idleMinutes: preNeverValue });
  }

  // ── Lock-on-minimize toggle handler ───────────────────────────────────────
  async function handleMinimizeToggle(): Promise<void> {
    await saveLockSettings({ lockOnMinimize: !currentLockOnMinimize });
  }

  // ── Clear success flag on navigation away (Warning 2 — pinned trigger) ────
  // SettingsShell unmount = user navigated away from Settings. Clear the flag
  // so re-entering Settings later does not show a stale success panel.
  onDestroy(() => {
    if (changeMasterSuccess.value) {
      setChangeMasterSuccess(false);
    }
  });

  // ── About sub-view (P6-12) ────────────────────────────────────────────────
  let showAbout = $state(false);

  // ── Pairing sub-view (Plan 12-03 / D-02) ──────────────────────────────────
  // Mirrors the showAbout/AboutView pattern. When true, PairingScreen replaces
  // the settings shell content (sub-view, not a modal).
  let showPairing = $state(false);

  /**
   * D-18 onSyncNow handler: concrete navigation to the main vault view so the
   * user lands at the header Sync Now button (Plan 12-04 — the daily sync trigger).
   * Closes any open sub-view and routes via go('main').
   */
  function handleSyncNowFromSettings(): void {
    showPairing = false;
    showAbout = false;
    go('main');
  }

  // ── Export confirm-master gate flag (P6-09) ────────────────────────────────
  let showExportConfirm = $state(false);

  // ── Audit settings (AUDIT-04 / Phase 6) ───────────────────────────────────
  // Read the PRIMITIVE directly off vaultSession.vault (Pitfall 7 defense — same
  // class as currentIdleMinutes above). Do NOT route through an intermediate
  // auditSettings object $derived: saveSettingsChange() shallow-copies #vault at
  // the top level only, so nested settings.audit keeps the SAME object reference,
  // making the intermediate === its previous value and short-circuiting propagation.
  const currentStaleThreshold = $derived(
    vaultSession.vault !== null
      ? (getVaultSettings(vaultSession.vault).audit?.staleThresholdDays ?? 365)
      : 365,
  );

  // Save audit settings (mirrors saveLockSettings pattern — P5-12 precedent).
  async function saveAuditSettings(
    update: Partial<{ staleThresholdDays: number }>,
  ): Promise<void> {
    if (!vaultSession.isUnlocked || vaultSession.vault === null) return;
    const vault = vaultSession.vault;
    // Read via getVaultSettings to ensure defaults are filled (Pitfall 7).
    const settings = getVaultSettings(vault);
    // Mutate in place — same pattern as saveLockSettings (single-cast strategy).
    if (settings.audit === undefined) {
      (settings as Record<string, unknown>)['audit'] = { staleThresholdDays: 365, ...update };
    } else {
      if (update.staleThresholdDays !== undefined) {
        settings.audit.staleThresholdDays = update.staleThresholdDays;
      }
    }
    await vaultSession.saveSettingsChange();
  }

  async function handleStaleThresholdChange(e: Event): Promise<void> {
    const input = e.target as HTMLInputElement;
    const value = parseInt(input.value, 10);
    if (!Number.isNaN(value) && value > 0) {
      await saveAuditSettings({ staleThresholdDays: value });
    }
  }

  // ── Export flow (EXPORT-01 / P6-09 / P6-10) ────────────────────────────────
  // 1. User clicks "Export" → showExportConfirm = true (renders ConfirmMasterPassword).
  // 2. onConfirmed: open native save dialog (bounded by 30s dialogGuard) → if cancelled,
  //    return early; if vault locked while dialog was open, fail safe with toast.
  //    Then wrap ONLY the flush+copy in runCriticalOp (LOCK-04 / Pitfall 1).
  // 3. onCancelled: hide the confirm gate.
  //
  // Security: the interactive dialogSave() call is OUTSIDE runCriticalOp so the vault
  // can auto-lock while the OS dialog is open (idle guard fires after 30s dialogGuard
  // expires). Only the brief awaitSaveMutex + vault_export_copy is a critical op.
  // This restores the idle auto-lock bound: dialog is bounded by the 30s dialogGuard;
  // once it clears AND no critical op is running, checkAndLock can fire normally.
  async function handleExportConfirmed(): Promise<void> {
    // Open the native save dialog OUTSIDE runCriticalOp — the dialog is bounded by the
    // 30s dialogGuard hard-timeout (SECURITY_INVARIANT 4 in dialogGuard.svelte.ts).
    // Once the hard-timeout clears isNativeDialogOpen AND isCriticalOpInProgress is false
    // (we are not inside runCriticalOp here), checkAndLock can fire → auto-lock is restored.
    setNativeDialogOpen();
    let destinationPath: string | null;
    try {
      destinationPath = await dialogSave({
        title: 'Export Encrypted Backup',
        defaultPath: 'cryptiq-backup.cryptiq',
        filters: [{ name: 'Cryptiq Vault', extensions: ['cryptiq'] }],
      });
    } finally {
      clearNativeDialogOpen();
    }

    if (destinationPath === null) {
      // User cancelled the dialog.
      showExportConfirm = false;
      return;
    }

    // Capture vaultPath NOW — if the vault locked while the dialog was open (idle
    // can now fire after the dialogGuard expires), vaultPath is null and we fail safe.
    const sourcePath = vaultSession.vaultPath;
    if (sourcePath === null) {
      showExportConfirm = false;
      pushToast('Export cancelled — vault is locked.');
      return;
    }

    // Only the brief flush + byte-copy is a critical op (LOCK-04 / Pitfall 1).
    // This is not interactive — it completes in milliseconds.
    try {
      await vaultSession.runCriticalOp(async () => {
        // P6-10 Pitfall 3: flush any in-flight save BEFORE copying the bytes so
        // the exported file includes the latest edits (not an earlier committed state).
        await vaultSession.awaitSaveMutex();

        // Invoke the Rust export command (byte copy of the already-encrypted file — EXPORT-01).
        await invoke('vault_export_copy', { sourcePath, destinationPath: destinationPath! });
      });

      showExportConfirm = false;
      pushToast('Backup saved.');
    } catch (e) {
      showExportConfirm = false;
      pushToast(e instanceof Error ? e.message : 'Export failed.');
    }
  }

  function handleExportCancelled(): void {
    showExportConfirm = false;
  }
</script>

{#if showAbout}
  <!-- About & Security sub-view (P6-12) — rendered over Settings -->
  <AboutView onBack={() => { showAbout = false; }} />
{:else if showPairing}
  <!-- Pairing sub-view (Plan 12-03 / D-02) — mirrors showAbout/AboutView pattern -->
  <PairingScreen onBack={() => { showPairing = false; }} {configDir} {vaultPath} />
{:else}
<div class="flex h-screen flex-col bg-cryptiq-bg">
  <!-- Page header with back navigation -->
  <header class="flex items-center gap-3 border-b border-cryptiq-border bg-cryptiq-surface px-6 py-4">
    <button
      type="button"
      onclick={() => go('main')}
      class="grid size-8 place-items-center rounded-cryptiq text-cryptiq-fg-muted transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-fg"
      aria-label="Back to vault"
      title="Back to vault"
    >
      <svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path d="M19 12H5" /><path d="m12 5-7 7 7 7" />
      </svg>
    </button>
    <h1 class="text-title font-semibold text-cryptiq-fg">Settings</h1>
  </header>

  <!-- Settings content -->
  <div class="flex-1 overflow-y-auto px-6 py-6">
    <div class="mx-auto max-w-lg space-y-6">

      <!-- ── Section: Security ──────────────────────────────────────────── -->
      <section aria-labelledby="security-heading">
        <h2 id="security-heading" class="mb-2 px-1 text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">
          Security
        </h2>
        <div class="overflow-hidden rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface shadow-cryptiq-panel">

          <!-- Auto-lock timeout (P5-03 / LOCK-01) -->
          <div class="px-4 py-3.5">
            <div class="flex items-center justify-between gap-4">
              <div class="min-w-0">
                <p class="text-body font-medium text-cryptiq-fg">Auto-lock timeout</p>
                <p class="mt-0.5 text-meta text-cryptiq-fg-subtle">
                  Lock the vault after a period of inactivity. The vault also locks on system sleep — this cannot be disabled.
                </p>
              </div>
              <!-- Live <select> — bg-cryptiq-surface-2 + border-cryptiq-border-strong treatment.
                   bind:value={selectedIdleValue} drives the visible selection; selectedIdleValue
                   is a local $state that is synced from currentIdleMinutes (via $effect) and
                   immediately reverted to the pre-Never value when "Never" is chosen, so the
                   dropdown never visually shows "Never" while the danger-ack panel is open. -->
              <select
                bind:value={selectedIdleValue}
                onchange={handleIdleChange}
                disabled={!vaultSession.isUnlocked}
                aria-label="Auto-lock timeout"
                class="shrink-0 rounded-cryptiq border border-cryptiq-border-strong bg-cryptiq-surface-2 px-3 py-1.5 text-meta text-cryptiq-fg focus:border-cryptiq-accent focus:outline-none focus:ring-1 focus:ring-cryptiq-ring disabled:opacity-60"
              >
                <option value="1">1 minute</option>
                <option value="5">5 minutes</option>
                <option value="15">15 minutes</option>
                <option value="30">30 minutes</option>
                <option value="never">Never</option>
              </select>
            </div>

            <!-- "Never" danger-ack inline panel (P5-03) -->
            {#if showNeverAck}
              <div class="mt-3 rounded-cryptiq border border-cryptiq-danger-border bg-cryptiq-danger-surface p-4">
                <!-- Warning icon + eyebrow -->
                <div class="mb-2 flex items-center gap-2">
                  <svg class="size-4 shrink-0 text-cryptiq-danger" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <path d="m10.29 3.86-8.18 14.17a1 1 0 0 0 .86 1.5h16.36a1 1 0 0 0 .86-1.5L11.71 3.86a1 1 0 0 0-1.72 0z" />
                    <line x1="12" y1="9" x2="12" y2="13" />
                    <line x1="12" y1="17" x2="12.01" y2="17" />
                  </svg>
                  <p class="text-meta font-semibold uppercase text-cryptiq-danger">SECURITY RISK</p>
                </div>
                <!-- Heading -->
                <p class="mb-1 text-body font-semibold text-cryptiq-fg">Your vault will never lock automatically.</p>
                <!-- Body -->
                <p class="mb-3 text-body text-cryptiq-fg">
                  Without auto-lock, anyone with access to your computer while Cryptiq is open can see your passwords.
                  This does not affect sleep-lock, which always activates.
                </p>
                <!-- Checkbox -->
                <label class="mb-3 flex cursor-pointer items-start gap-2">
                  <input
                    type="checkbox"
                    bind:checked={neverAckChecked}
                    class="mt-0.5 shrink-0 accent-cryptiq-danger"
                  />
                  <span class="text-body text-cryptiq-fg">I understand the risk and want to disable auto-lock.</span>
                </label>
                <!-- Actions -->
                <div class="flex items-center gap-4">
                  <button
                    type="button"
                    onclick={handleNeverConfirm}
                    disabled={!neverAckChecked}
                    class="rounded-cryptiq bg-cryptiq-danger px-3 py-1.5 text-body font-semibold text-cryptiq-danger-fg transition-colors hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    Confirm — disable auto-lock
                  </button>
                  <button
                    type="button"
                    onclick={handleNeverCancel}
                    class="text-body text-cryptiq-fg-muted hover:text-cryptiq-fg"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            {/if}
          </div>

          <div class="mx-4 border-t border-cryptiq-border" aria-hidden="true"></div>

          <!-- Lock-on-minimize toggle (P5-05) -->
          <div class="flex items-center justify-between gap-4 px-4 py-3.5">
            <div class="min-w-0">
              <p class="text-body font-medium text-cryptiq-fg">Lock when window is minimized</p>
              <p class="mt-0.5 text-meta text-cryptiq-fg-subtle">
                Lock the vault immediately when you minimize or hide the Cryptiq window.
              </p>
            </div>
            <!-- Toggle switch — identical shape to the favicon toggle (P5-05 / UI-SPEC Surface 1) -->
            <button
              type="button"
              role="switch"
              aria-checked={currentLockOnMinimize}
              aria-label="Lock when window is minimized"
              disabled={!vaultSession.isUnlocked}
              onclick={handleMinimizeToggle}
              class="relative h-5 w-9 shrink-0 rounded-full transition-colors
                     {currentLockOnMinimize ? 'bg-cryptiq-accent' : 'bg-cryptiq-border-strong'}
                     disabled:opacity-60"
            >
              <span
                class="absolute top-0.5 left-0.5 size-4 rounded-full bg-white shadow-cryptiq-panel transition-transform
                       {currentLockOnMinimize ? 'translate-x-4' : ''}"
              ></span>
            </button>
          </div>

          <div class="mx-4 border-t border-cryptiq-border" aria-hidden="true"></div>

          <!-- Clipboard auto-clear (Phase 5: LOCK-02/06 — still a placeholder in this plan) -->
          <div class="flex items-center justify-between gap-4 px-4 py-3.5">
            <div class="min-w-0">
              <p class="text-body font-medium text-cryptiq-fg-muted">Clipboard auto-clear</p>
              <p class="mt-0.5 text-meta text-cryptiq-fg-subtle">Automatically clear copied passwords after a delay.</p>
            </div>
            <span
              class="shrink-0 rounded-cryptiq border border-cryptiq-border px-3 py-1.5 text-meta text-cryptiq-fg-subtle"
              aria-label="Clipboard auto-clear — available in a future update"
              title="Available in a future update"
            >
              Future update
            </span>
          </div>

          <div class="mx-4 border-t border-cryptiq-border" aria-hidden="true"></div>

          <!-- Change master password (AUTH-10) — enabled in Phase 5 -->
          <div class="flex items-center justify-between gap-4 px-4 py-3.5">
            <div class="min-w-0">
              <p class="text-body font-medium text-cryptiq-fg">Change master password</p>
              <p class="mt-0.5 text-meta text-cryptiq-fg-subtle">Update the password used to unlock this vault.</p>
            </div>
            <button
              type="button"
              onclick={() => go('change-master')}
              disabled={!vaultSession.isUnlocked}
              aria-label="Change master password"
              class="shrink-0 rounded-cryptiq border border-cryptiq-border px-3 py-1.5 text-meta font-medium text-cryptiq-fg transition-colors hover:bg-cryptiq-hover disabled:cursor-not-allowed disabled:opacity-50"
            >
              Change…
            </button>
          </div>

          <!-- Post-change success panel (ROADMAP SC-5 / UI-SPEC Surface 4)
               Rendered when changeMasterSuccess.value is true — set by ChangeMasterView
               before go('settings'). Gated on the pinned flag (NOT an ad-hoc local).
               Cleared by onDestroy (navigation away) via setChangeMasterSuccess(false). -->
          {#if changeMasterSuccess.value}
            <div class="mx-4 border-t border-cryptiq-border" aria-hidden="true"></div>
            <div
              class="mx-4 my-3 flex items-start gap-3 rounded-cryptiq border border-cryptiq-border bg-cryptiq-surface-2 px-4 py-3"
              role="status"
            >
              <!-- Checkmark icon -->
              <svg class="mt-0.5 size-4 shrink-0 text-cryptiq-success" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <polyline points="20 6 9 17 4 12" />
              </svg>
              <div>
                <p class="text-body font-medium text-cryptiq-fg">Master password changed.</p>
                <p class="mt-0.5 text-meta text-cryptiq-fg-muted">
                  Your recovery key still works. The vault key is the same — only the master password wrapper changed.
                </p>
              </div>
            </div>
          {/if}

        </div>
      </section>

      <!-- ── Section: Sync (Plan 12-03 / D-01/D-02/D-16/D-17/D-18) ──────── -->
      <section aria-labelledby="sync-heading">
        <h2 id="sync-heading" class="mb-2 px-1 text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">
          Sync
        </h2>
        <div class="overflow-hidden rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface shadow-cryptiq-panel">
          <SyncSettingsSection
            {configDir}
            {vaultPath}
            onPair={() => { showPairing = true; }}
            onSyncNow={handleSyncNowFromSettings}
          />
        </div>
      </section>

      <!-- ── Section: Generator ─────────────────────────────────────────── -->
      <section aria-labelledby="generator-heading">
        <h2 id="generator-heading" class="mb-2 px-1 text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">
          Generator
        </h2>
        <div class="overflow-hidden rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface shadow-cryptiq-panel">

          <!-- Generator defaults (links to standalone generator screen) -->
          <button
            type="button"
            onclick={() => go('generator')}
            class="flex w-full items-center justify-between gap-4 px-4 py-3.5 text-left
                   transition-colors hover:bg-cryptiq-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cryptiq-ring"
            aria-label="Open generator to adjust defaults"
          >
            <div class="min-w-0">
              <p class="text-body font-medium text-cryptiq-fg">Generator defaults</p>
              <p class="mt-0.5 text-meta text-cryptiq-fg-subtle">
                Current default: <span class="font-medium text-cryptiq-fg">{generatorDefaultLabel}</span>.
                Open the generator to change defaults and save them.
              </p>
            </div>
            <!-- Chevron right -->
            <svg class="size-4 shrink-0 text-cryptiq-fg-subtle" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="m9 18 6-6-6-6" />
            </svg>
          </button>

        </div>
      </section>

      <!-- ── Section: Privacy ───────────────────────────────────────────── -->
      <section aria-labelledby="privacy-heading">
        <h2 id="privacy-heading" class="mb-2 px-1 text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">
          Privacy
        </h2>
        <div class="overflow-hidden rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface shadow-cryptiq-panel">

          <!--
            Favicon fetch toggle (UI-10 / T-04-23).
            Rendered OFF by default. No network call is made regardless
            of toggle state. Full fetch UX is a future update.
          -->
          <label class="flex cursor-pointer items-center justify-between gap-4 px-4 py-3.5">
            <div class="min-w-0">
              <p class="text-body font-medium text-cryptiq-fg">Show website icons</p>
              <p class="mt-0.5 text-meta text-cryptiq-fg-subtle">
                Fetch site favicons to show alongside entries.
                Off by default — enabling sends your stored website addresses to the site servers.
                <span class="block mt-0.5 text-cryptiq-fg-subtle">Full support available in a future update.</span>
              </p>
            </div>
            <!--
              Toggle switch. Off by default (UI-10). Visually interactive this phase;
              the state is NOT persisted — Phase 5 plan 06+ will wire vault settings.
            -->
            <button
              type="button"
              role="switch"
              aria-checked={faviconEnabled}
              aria-label="Show website icons"
              onclick={() => (faviconEnabled = !faviconEnabled)}
              class="relative h-5 w-9 shrink-0 rounded-full transition-colors
                     {faviconEnabled ? 'bg-cryptiq-accent' : 'bg-cryptiq-border-strong'}"
            >
              <span
                class="absolute top-0.5 left-0.5 size-4 rounded-full bg-white shadow-cryptiq-panel transition-transform
                       {faviconEnabled ? 'translate-x-4' : ''}"
              ></span>
            </button>
          </label>

        </div>

        <!-- Informational note about the favicon setting -->
        {#if faviconEnabled}
          <p class="mt-2 px-1 text-meta text-cryptiq-fg-subtle" role="status">
            Website icons will be available once this feature is fully wired in a future update. No network requests are made right now.
          </p>
        {/if}
      </section>

      <!-- ── Section: Audit (AUDIT-04 / Phase 6) ──────────────────────────── -->
      <section aria-labelledby="audit-heading">
        <h2 id="audit-heading" class="mb-2 px-1 text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">
          Health Audit
        </h2>
        <div class="overflow-hidden rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface shadow-cryptiq-panel">

          <!-- Stale password threshold (AUDIT-04) -->
          <div class="flex items-center justify-between gap-4 px-4 py-3.5">
            <div class="min-w-0">
              <p class="text-body font-medium text-cryptiq-fg">Stale password threshold</p>
              <p class="mt-0.5 text-meta text-cryptiq-fg-subtle">
                Passwords older than this many days are flagged as stale in the Health view.
              </p>
            </div>
            <div class="flex shrink-0 items-center gap-2">
              <input
                type="number"
                min="1"
                max="3650"
                value={currentStaleThreshold}
                onchange={handleStaleThresholdChange}
                disabled={!vaultSession.isUnlocked}
                aria-label="Stale password threshold in days"
                class="w-20 rounded-cryptiq border border-cryptiq-border-strong bg-cryptiq-surface-2 px-2 py-1.5 text-right text-meta text-cryptiq-fg focus:border-cryptiq-accent focus:outline-none focus:ring-1 focus:ring-cryptiq-ring disabled:opacity-60"
              />
              <span class="text-meta text-cryptiq-fg-subtle">days</span>
            </div>
          </div>

        </div>
      </section>

      <!-- ── Section: Backup (EXPORT-01/02 / Phase 6) ──────────────────────── -->
      <section aria-labelledby="backup-heading">
        <h2 id="backup-heading" class="mb-2 px-1 text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">
          Backup
        </h2>
        <div class="overflow-hidden rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface shadow-cryptiq-panel">

          {#if showExportConfirm}
            <!-- ConfirmMasterPassword gate (P6-09 / AUTH-11 / T-06-15) -->
            <div class="px-4 py-4">
              <ConfirmMasterPassword
                onConfirmed={handleExportConfirmed}
                onCancelled={handleExportCancelled}
              />
            </div>
          {:else}
            <!-- Export action + static reminder -->
            <div class="px-4 py-3.5 space-y-3">
              <div class="flex items-start justify-between gap-4">
                <div class="min-w-0">
                  <p class="text-body font-medium text-cryptiq-fg">Export encrypted backup</p>
                  <p class="mt-0.5 text-meta text-cryptiq-fg-subtle">
                    Copy the encrypted vault file to a location you choose. The backup uses the same encryption — it requires your master password to open.
                  </p>
                </div>
                <button
                  type="button"
                  onclick={() => { showExportConfirm = true; }}
                  disabled={!vaultSession.isUnlocked}
                  aria-label="Export an encrypted backup of your vault"
                  class="shrink-0 rounded-cryptiq border border-cryptiq-border px-3 py-1.5 text-meta font-medium text-cryptiq-fg transition-colors hover:bg-cryptiq-hover disabled:cursor-not-allowed disabled:opacity-50"
                >
                  Export…
                </button>
              </div>

              <!-- Static reminder line (P6-11 — no state, no nag, no lastExportedAt) -->
              <p class="text-meta text-cryptiq-fg-subtle">
                Back up your vault somewhere safe — a copy on another drive protects against disk failure.
              </p>
            </div>
          {/if}

        </div>
      </section>

      <!-- ── Section: About (P6-12) ─────────────────────────────────────────── -->
      <section aria-labelledby="about-heading">
        <h2 id="about-heading" class="mb-2 px-1 text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">
          App
        </h2>
        <div class="overflow-hidden rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface shadow-cryptiq-panel">

          <!-- About & Security row (P6-12) -->
          <button
            type="button"
            onclick={() => { showAbout = true; }}
            class="flex w-full items-center justify-between gap-4 px-4 py-3.5 text-left
                   transition-colors hover:bg-cryptiq-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cryptiq-ring"
            aria-label="Open About &amp; Security"
          >
            <div class="min-w-0">
              <p class="text-body font-medium text-cryptiq-fg">About &amp; Security</p>
              <p class="mt-0.5 text-meta text-cryptiq-fg-subtle">
                Threat model, differentiators, version, v1 disclosures.
              </p>
            </div>
            <!-- Chevron right -->
            <svg class="size-4 shrink-0 text-cryptiq-fg-subtle" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="m9 18 6-6-6-6" />
            </svg>
          </button>

        </div>
      </section>

    </div>
  </div>
</div>
{/if}
