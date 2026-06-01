<!--
  SettingsShell.svelte — Settings screen (UI-13).

  Phase 4 scope: placeholders only. Full wiring of each control lands in Phase 5.
  The favicon toggle is the one exception: it renders its OFF default state now
  (UI-10) so the Phase-5 implementer can wire it without touching the layout.

  Controls (UI-13):
    1. Auto-lock timeout     — disabled placeholder (Phase 5: LOCK-01)
    2. Clipboard auto-clear  — disabled placeholder (Phase 5: LOCK-02/06)
    3. Generator defaults    — link to the generator screen + shows current default mode
    4. Change master password — disabled placeholder (Phase 5: AUTH-10)
    5. Favicon fetch toggle  — rendered OFF by default (UI-10); no network call
                               in Phase 4 (T-04-23). Toggle is visually interactive
                               but its state does NOT persist this phase.

  Security (T-04-23):
    The favicon toggle renders OFF by default. This screen makes ZERO network calls.
    Enabling the toggle does nothing in Phase 4 — the fetch UX is Phase 5.

  Design (P4-02/P4-03):
    Sectioned layout: each group has a header and card-style rows. Disabled controls
    use text-cryptiq-fg-muted/fg-subtle to signal "not yet active" — never the accent.
    Placeholders are labeled clearly (e.g. "Available in a future update") so they
    look intentional, not abandoned.

  Token rules: cryptiq-* tokens only; no literal hex/oklch.
-->
<script lang="ts">
  import { go } from '../state/view.svelte';
  import { vaultSession } from '../state/vault.svelte';

  // ── Favicon toggle local state (UI-10) ────────────────────────────────────
  // OFF by default. NOT persisted in Phase 4 — the toggle is a preview of the
  // control shape for Phase 5. No network call is made regardless of its state.
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
</script>

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

          <!-- Auto-lock timeout (Phase 5: LOCK-01) -->
          <div class="flex items-center justify-between gap-4 px-4 py-3.5">
            <div class="min-w-0">
              <p class="text-body font-medium text-cryptiq-fg-muted">Auto-lock timeout</p>
              <p class="mt-0.5 text-meta text-cryptiq-fg-subtle">Lock the vault after a period of inactivity.</p>
            </div>
            <span
              class="shrink-0 rounded-cryptiq border border-cryptiq-border px-3 py-1.5 text-meta text-cryptiq-fg-subtle"
              aria-label="Auto-lock timeout — available in a future update"
              title="Available in a future update"
            >
              Future update
            </span>
          </div>

          <div class="mx-4 border-t border-cryptiq-border" aria-hidden="true"></div>

          <!-- Clipboard auto-clear (Phase 5: LOCK-02/06) -->
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

          <!-- Change master password (Phase 5: AUTH-10) -->
          <div class="flex items-center justify-between gap-4 px-4 py-3.5">
            <div class="min-w-0">
              <p class="text-body font-medium text-cryptiq-fg-muted">Change master password</p>
              <p class="mt-0.5 text-meta text-cryptiq-fg-subtle">Update the password used to unlock this vault.</p>
            </div>
            <button
              type="button"
              disabled
              aria-label="Change master password — available in a future update"
              title="Available in a future update"
              class="shrink-0 rounded-cryptiq border border-cryptiq-border px-3 py-1.5 text-meta font-medium text-cryptiq-fg-subtle
                     opacity-50 cursor-not-allowed"
            >
              Change…
            </button>
          </div>

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
            Rendered OFF by default. No network call is made in Phase 4 regardless
            of toggle state. Full fetch UX is Phase 5.
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
              the state is NOT persisted (Phase 5 will wire vault settings + fetch logic).
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

    </div>
  </div>
</div>
