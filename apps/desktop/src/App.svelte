<!--
  App.svelte — Phase 4 root component.

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

  Token rules (P4-03): only `text-cryptiq-*` / `bg-cryptiq-*` / token utilities.
  Never a literal hex color in this file.
-->
<script lang="ts">
  import { getSodium } from '@cryptiq/core/internal';
  import { exists } from '@tauri-apps/plugin-fs';
  import { view, go } from './lib/state/view.svelte';
  import { loadConfig } from './lib/config/config-adapter';
  import FirstRunWizard from './lib/screens/FirstRunWizard.svelte';
  import UnlockScreen from './lib/screens/UnlockScreen.svelte';
  import RelocateScreen from './lib/screens/RelocateScreen.svelte';
  import MainView from './lib/screens/MainView.svelte';
  import GeneratorScreen from './lib/screens/GeneratorScreen.svelte';
  import SettingsShell from './lib/screens/SettingsShell.svelte';

  let sodiumReady = $state(false);
  let showLoadingHint = $state(false);

  $effect(() => {
    const t0 = performance.now();
    const hintTimer = setTimeout(() => {
      showLoadingHint = true;
    }, 50);

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
      })
      .catch(() => {
        // sodium init failure is fatal — at minimum show the hint.
        clearTimeout(hintTimer);
        showLoadingHint = true;
      });

    return () => clearTimeout(hintTimer);
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
  {/if}
{/if}
