<!--
  RelocateScreen.svelte — P4-10 missing-vault recovery screen.

  Shown when config.vaultPath points to a file that no longer exists
  (moved/deleted/renamed). This MUST never silently fall back to first-run —
  that would risk the user believing their data is gone and accidentally creating
  a duplicate vault (T-04-09).

  Actions:
    - "Locate vault" → native open dialog filtered to .cryptiq → saveConfig +
      go('unlock'). No silent onboarding fallback.
    - "Start fresh" → go('first-run'). Explicitly chosen, not automatic.
-->
<script lang="ts">
  import { open as openDialog } from '@tauri-apps/plugin-dialog';
  import { go } from '../state/view.svelte';
  import { saveConfig } from '../config/config-adapter';

  let locating = $state(false);
  let error = $state<string | null>(null);

  async function handleLocate(): Promise<void> {
    if (locating) return;
    locating = true;
    error = null;

    try {
      const chosen = await openDialog({
        title: 'Find your vault file',
        multiple: false,
        filters: [{ name: 'Cryptiq Vault', extensions: ['cryptiq'] }],
      });
      if (typeof chosen === 'string' && chosen.length > 0) {
        await saveConfig({ vaultPath: chosen, schemaVersion: 1 });
        go('unlock');
      }
    } catch {
      error = 'Could not open the file picker. Please try again.';
    } finally {
      locating = false;
    }
  }

  function handleStartFresh(): void {
    go('first-run');
  }
</script>

<div class="grid h-full place-items-center bg-cryptiq-bg px-6 py-10">
  <div
    class="w-full max-w-md rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface p-8 shadow-cryptiq-panel"
  >
    <!-- Icon -->
    <div class="mb-6 flex size-12 items-center justify-center rounded-cryptiq-lg bg-cryptiq-surface-2">
      <svg
        class="size-6 text-cryptiq-fg-muted"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="1.75"
        stroke-linecap="round"
        stroke-linejoin="round"
        aria-hidden="true"
      >
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
        <polyline points="14 2 14 8 20 8" />
        <line x1="12" y1="11" x2="12" y2="17" />
        <line x1="9" y1="14" x2="15" y2="14" />
      </svg>
    </div>

    <!-- Heading -->
    <h1 class="text-display font-semibold text-cryptiq-fg">We couldn't find your vault.</h1>
    <p class="mt-3 text-body leading-relaxed text-cryptiq-fg-muted">
      Your vault file has been moved, renamed, or deleted. Choose what you'd like to do —
      we'll wait for your decision rather than make assumptions.
    </p>

    <!-- Error -->
    {#if error}
      <p
        class="mt-4 rounded-cryptiq border border-cryptiq-danger-border bg-cryptiq-danger-surface px-3 py-2 text-body text-cryptiq-danger"
        role="alert"
      >
        {error}
      </p>
    {/if}

    <!-- Actions -->
    <div class="mt-8 space-y-3">
      <!-- Primary: locate the vault -->
      <button
        type="button"
        onclick={() => void handleLocate()}
        disabled={locating}
        class="flex w-full items-center justify-center gap-2 rounded-cryptiq bg-cryptiq-accent px-5 py-3 text-body font-semibold text-cryptiq-accent-fg transition-colors hover:bg-cryptiq-accent-hover disabled:cursor-not-allowed disabled:opacity-40"
      >
        {#if locating}
          <span class="size-4 animate-spin rounded-full border-2 border-cryptiq-accent-fg/30 border-t-cryptiq-accent-fg" aria-hidden="true"></span>
          Locating…
        {:else}
          <svg class="size-4 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <circle cx="11" cy="11" r="8" />
            <line x1="21" y1="21" x2="16.65" y2="16.65" />
          </svg>
          Locate vault file
        {/if}
      </button>

      <!-- Divider -->
      <div class="relative flex items-center">
        <div class="flex-1 border-t border-cryptiq-border"></div>
        <span class="mx-3 text-meta text-cryptiq-fg-subtle">or</span>
        <div class="flex-1 border-t border-cryptiq-border"></div>
      </div>

      <!-- Secondary: start fresh (explicit choice, not a fallback) -->
      <button
        type="button"
        onclick={handleStartFresh}
        class="w-full rounded-cryptiq border border-cryptiq-border px-5 py-3 text-body font-medium text-cryptiq-fg-muted transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-fg"
      >
        Start fresh with a new vault
      </button>
    </div>

    <!-- Clarifying footnote -->
    <p class="mt-6 text-meta text-cryptiq-fg-subtle">
      Starting fresh will NOT delete or overwrite your existing vault file — it just creates a new one at a location you choose.
    </p>
  </div>
</div>
