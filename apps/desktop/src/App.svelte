<!--
  App.svelte — Phase 4/5 root component.

  Responsibilities:
   1. (D-03) Gate first paint on `await sodium.ready` — real libsodium-wrappers-sumo
      WASM init. No vault surface renders before the gate resolves (Pitfall 5).
      Uses getSodium() from @cryptiq/core/internal (the single WASM entry point).
   2. (P4-06) Host the rune view-state enum. Behind the gate, exactly one of the six
      view values renders: first-run | unlock | relocate | main | generator | settings.
      No router dependency — hand-rolled $state enum (P4-06).
   3. On boot: read loadConfig() AFTER sodium.ready.
      - config.vaultPath is null  → 'first-run'
      - config.vaultPath present but file MISSING → 'relocate' (P4-10)
      - config.vaultPath present and file EXISTS → 'unlock'
      Config-read failure is non-fatal — default to 'first-run'.
   4. (P5-03 / LOCK-01) Wire three Tauri lock events after sodium.ready:
      cryptiq-sleep-lock / cryptiq-window-blur / cryptiq-window-close.
   5. (P5-03 / LOCK-01 / Pitfall 7) Start the idle controller ONLY from a
      dedicated $effect that watches vaultSession.isUnlocked — never at boot
      while the vault is null (getVaultSettings must not be called on null vault).

  Token rules (P4-03): only `text-cryptiq-*` / `bg-cryptiq-*` / token utilities.
  Never a literal hex color in this file.
-->
<script lang="ts">
  import { getSodium } from '@cryptiq/core/internal';
  import { getVaultSettings } from '@cryptiq/core';
  import { exists } from '@tauri-apps/plugin-fs';
  import { listen } from '@tauri-apps/api/event';
  import { view, go, setLockReason } from './lib/state/view.svelte';
  import { vaultSession } from './lib/state/vault.svelte';
  import { startIdleController, stopIdleController } from './lib/state/idle.svelte';
  // Fix-forward (import-auto-lock regression): suppress blur-lock false-positive
  // while an app-initiated native OS file-picker dialog is open (SECURITY_INVARIANT 2).
  import { isNativeDialogOpen } from './lib/state/dialogGuard.svelte';
  // Health-audit store: cleared on vault lock to release Entry refs (plaintext) and
  // bound the score-cache memory lifetime to the session (defense-in-depth).
  import { clearHealthAudit } from './lib/state/healthAudit.svelte';
  import { loadConfig } from './lib/config/config-adapter';
  import FirstRunWizard from './lib/screens/FirstRunWizard.svelte';
  import UnlockScreen from './lib/screens/UnlockScreen.svelte';
  import RelocateScreen from './lib/screens/RelocateScreen.svelte';
  import MainView from './lib/screens/MainView.svelte';
  import GeneratorScreen from './lib/screens/GeneratorScreen.svelte';
  import SettingsShell from './lib/screens/SettingsShell.svelte';
  import ChangeMasterView from './lib/screens/ChangeMasterView.svelte';
  import ImportView from './lib/screens/ImportView.svelte';
  import HealthView from './lib/screens/HealthView.svelte';
  import Toast from './lib/components/Toast.svelte';

  let sodiumReady = $state(false);
  let showLoadingHint = $state(false);

  $effect(() => {
    const t0 = performance.now();
    const hintTimer = setTimeout(() => {
      showLoadingHint = true;
    }, 50);

    // Collect unlisten fns for the three Tauri lock events.
    // These are stored as Promises so the teardown can await and call them.
    let unlistenSleepPromise: Promise<() => void> | null = null;
    let unlistenBlurPromise: Promise<() => void> | null = null;
    let unlistenClosePromise: Promise<() => void> | null = null;

    // Real sodium.ready gate — replaces the Phase-1 Promise.resolve() stub.
    // getSodium() awaits sodium.ready exactly once and memoizes the instance.
    // Pitfall 5: vault UI must NOT render before this resolves.
    getSodium()
      .then(async () => {
        const dt = performance.now() - t0;
        // Pitfall 5 detector — surfaces a WASM MIME or bundler issue in dev.
        if (dt > 500) {
          console.warn(
            `[boot] sodium.ready took ${dt.toFixed(0)}ms (>500ms threshold — suspect Vite WASM MIME issue, see Pitfall 5)`,
          );
        }

        // Seed the initial view from config (AUTH-09 + P4-10).
        try {
          const config = await loadConfig();
          if (config.vaultPath === null || config.vaultPath === undefined || config.vaultPath === '') {
            // No vault configured → first-run wizard.
            go('first-run');
          } else {
            // Vault path is remembered. Check if the file still exists (P4-10).
            const fileExists = await exists(config.vaultPath);
            if (fileExists) {
              go('unlock');
            } else {
              // File has been moved/deleted — route to the relocate recovery screen.
              // NEVER silently fall back to first-run (T-04-09).
              go('relocate');
            }
          }
        } catch {
          // Config read failure is non-fatal — default to first-run.
          go('first-run');
        }

        sodiumReady = true;
        clearTimeout(hintTimer);

        // P5-03 / LOCK-01: Wire the three Tauri lock events now that sodium is
        // ready. Listeners are registered once on mount and cleaned up on teardown.
        //
        // Note: the idle controller is NOT started here — it is started exclusively
        // from the isUnlocked $effect below (Pitfall 7: never call getVaultSettings
        // while the vault is null / before the first unlock).

        // cryptiq-sleep-lock: system suspend/sleep → always lock.
        unlistenSleepPromise = listen('cryptiq-sleep-lock', async () => {
          setLockReason('sleep');
          await vaultSession.lock();
          go('unlock');
        });

        // cryptiq-window-blur: window loses focus → lock ONLY if lockOnMinimize
        // is enabled. Guard: only read settings when vault is unlocked (non-null).
        //
        // Fix-forward (import-auto-lock regression / SECURITY_INVARIANT 2):
        // Early-return while isNativeDialogOpen() is true — the OS file-picker
        // dialog steals webview focus momentarily during an app-initiated import;
        // this is NOT a real minimize/background event. The sleep-lock and
        // close-lock below remain UNCHANGED (always lock regardless of this guard).
        unlistenBlurPromise = listen('cryptiq-window-blur', async () => {
          if (!vaultSession.isUnlocked) return;
          // Suppress blur-lock for the brief, app-initiated OS file-picker window.
          if (isNativeDialogOpen()) return;
          const settings = getVaultSettings(vaultSession.vault!);
          // getVaultSettings guarantees lock field is filled via asInnerDoc();
          // the `?? false` guards the optional type without an unsafe assertion.
          if (settings.lock?.lockOnMinimize ?? false) {
            setLockReason('user');
            await vaultSession.lock();
            go('unlock');
          }
        });

        // cryptiq-window-close: window close request → lock before process exits.
        // No view transition — the process exits after lock() returns.
        unlistenClosePromise = listen('cryptiq-window-close', async () => {
          await vaultSession.lock();
        });
      })
      .catch(() => {
        // sodium init failure is fatal — at minimum show the hint.
        clearTimeout(hintTimer);
        showLoadingHint = true;
      });

    return () => {
      clearTimeout(hintTimer);
      // Tear down the three lock-event listeners if they were registered.
      if (unlistenSleepPromise !== null) {
        unlistenSleepPromise.then((u) => u()).catch(() => {});
      }
      if (unlistenBlurPromise !== null) {
        unlistenBlurPromise.then((u) => u()).catch(() => {});
      }
      if (unlistenClosePromise !== null) {
        unlistenClosePromise.then((u) => u()).catch(() => {});
      }
    };
  });

  // P5-03 / LOCK-01 / Pitfall 7: Start the idle controller ONLY when the vault
  // transitions from locked → unlocked. Never at boot (vault is null until a
  // successful unlock). `getVaultSettings` is only called inside the guard
  // (when isUnlocked is true), so the null-vault crash is impossible here.
  //
  // The $effect cleanup (called when isUnlocked flips back to false on lock,
  // or on component unmount) calls stopIdleController(), which tears down the
  // event listeners and cancels any pending timer.
  $effect(() => {
    if (vaultSession.isUnlocked) {
      const settings = getVaultSettings(vaultSession.vault!);
      // getVaultSettings guarantees idleMinutes via asInnerDoc(); fallback to
      // 'never' so a missing field never arms an un-configured timer.
      startIdleController(settings.lock?.idleMinutes ?? 'never');
    }

    return () => {
      stopIdleController();
      // Clear the health-audit store on vault lock: releases Entry refs (which
      // hold plaintext passwords) and resets the score cache. This bounds the
      // plaintext lifetime to the unlocked session (defense-in-depth, Pitfall 7).
      clearHealthAudit();
    };
  });
</script>

{#if !sodiumReady}
  <div class="grid h-screen place-items-center">
    {#if showLoadingHint}
      <p class="text-cryptiq-fg-muted text-sm">Loading…</p>
    {/if}
  </div>
{:else}
  <!--
    General toast renderer: mounted OUTSIDE the view switch so it overlays
    every view (main, settings, health, import, generator, first-run, etc.).
    Empty queue renders nothing and passes pointer events through (pointer-events-none
    wrapper — see Toast.svelte). Fix-forward for latent Phase-4 bug: pushToast() had
    no renderer; all "Saved", "Imported N entries", "Backup saved." toasts were
    invisible until this was added (surfaced by 06-06 export 'Backup saved.' test).
  -->
  <Toast />
  <!--
    P4-06 view-state switch. Each branch renders a real screen component.
    main / generator / settings remain placeholder until plans 04-04 through 04-07.
  -->
  {#if view.current === 'first-run'}
    <div class="h-screen">
      <FirstRunWizard />
    </div>
  {:else if view.current === 'unlock'}
    <div class="h-screen">
      <UnlockScreen />
    </div>
  {:else if view.current === 'relocate'}
    <div class="h-screen">
      <RelocateScreen />
    </div>
  {:else if view.current === 'main'}
    <MainView />
  {:else if view.current === 'generator'}
    <GeneratorScreen />
  {:else if view.current === 'settings'}
    <SettingsShell />
  {:else if view.current === 'change-master'}
    <div class="h-screen">
      <ChangeMasterView />
    </div>
  {:else if view.current === 'import'}
    <div class="h-screen">
      <ImportView />
    </div>
  {:else if view.current === 'health'}
    <HealthView />
  {/if}
{/if}
