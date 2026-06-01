<!--
  GeneratorScreen.svelte — standalone generator screen (GEN-05/06).

  Reuses GeneratorSurface with variant="standalone" — the same core-backed engine
  as the inline popover in EntryDetail. No forked logic, no Math.random (T-04-22).

  Save as default (GEN-06/GEN-04):
    Receives the current GeneratorOptions via onSaveDefault(opts), mutates the
    InnerDoc settings.generator in place, then calls vaultSession.save(). Follows
    the single-cast pattern used across MainView/EntryDetail/crud.ts.

  Save as new entry (GEN-06):
    Shows a small inline dialog prompting ONLY for title + username. On confirm,
    calls vaultSession.addEntry() + save() + focuses the new entry + returns to main.

  On mount: seeds GeneratorSurface from vault settings.generator so the screen
  reflects the user's stored defaults.

  Threat mitigations:
    T-04-22: generate prop → generateFromOptions (core CSPRNG). No Math.random.
    T-04-24: Password persisted only inside the encrypted vault; never logged.

  Token rules (P4-03): cryptiq-* tokens only; no literal hex/oklch.
-->
<script lang="ts">
  import GeneratorSurface from '../components/GeneratorSurface.svelte';
  import { vaultSession } from '../state/vault.svelte';
  import { ui, pushToast } from '../state/ui.svelte';
  import { go } from '../state/view.svelte';
  import { generateFromOptions, estimateEntropyBits } from '@cryptiq/core';
  import type { GeneratorOptions, InnerDoc } from '@cryptiq/core';

  // ── InnerDoc cast helper (mirrors the single-cast pattern in MainView/EntryDetail) ──
  // vault.entries is typed as `object` at the format layer; Phase 3 writes an InnerDoc.
  function getInnerDoc(vault: { entries: object } | null): InnerDoc | null {
    if (vault === null) return null;
    const raw = vault.entries as Record<string, unknown>;
    if (!raw['settings'] || typeof raw['settings'] !== 'object') return null;
    const settings = raw['settings'] as Record<string, unknown>;
    if (!settings['generator']) return null;
    return vault.entries as InnerDoc;
  }

  // ── Seed from vault settings.generator ───────────────────────────────────
  // $derived re-evaluates when vaultSession.vault reassigns (P3-02 pattern).
  const savedDefault = $derived(getInnerDoc(vaultSession.vault)?.settings?.generator);

  // ── Core CSPRNG callbacks (T-04-22 — never Math.random) ──────────────────
  async function coreGenerate(opts: GeneratorOptions): Promise<string> {
    return generateFromOptions(opts);
  }
  function coreEstimateBits(opts: GeneratorOptions): number {
    return estimateEntropyBits(opts);
  }

  // ── Save-as-default ───────────────────────────────────────────────────────
  // Receives opts from GeneratorSurface's onSaveDefault(opts) callback.
  async function handleSaveDefault(opts: GeneratorOptions) {
    if (!vaultSession.isUnlocked) return;
    const vault = vaultSession.vault;
    if (vault === null) return;
    try {
      // Mutate InnerDoc settings.generator in place (single-cast strategy).
      const raw = vault.entries as Record<string, unknown>;
      if (typeof raw['settings'] !== 'object' || raw['settings'] === null) {
        raw['settings'] = { generator: opts };
      } else {
        (raw['settings'] as Record<string, unknown>)['generator'] = opts;
      }
      await vaultSession.save();
      pushToast('Defaults saved');
    } catch {
      // Non-fatal — stay on screen, user can retry.
    }
  }

  // ── Save-as-new-entry state ───────────────────────────────────────────────
  let showEntryForm = $state(false);
  let newTitle = $state('');
  let newUsername = $state('');
  let pendingPassword = $state('');
  let entryFormBusy = $state(false);
  let titleError = $state(false);

  function handleSaveAsEntry(password: string) {
    pendingPassword = password;
    newTitle = '';
    newUsername = '';
    titleError = false;
    showEntryForm = true;
  }

  function cancelEntryForm() {
    showEntryForm = false;
    pendingPassword = '';
    newTitle = '';
    newUsername = '';
    titleError = false;
  }

  async function confirmNewEntry() {
    if (!newTitle.trim()) {
      titleError = true;
      return;
    }
    if (!vaultSession.isUnlocked) return;
    entryFormBusy = true;
    try {
      const entry = await vaultSession.addEntry({
        title: newTitle.trim(),
        username: newUsername.trim() || '',
        password: pendingPassword,
      });
      await vaultSession.save();
      ui.selectedEntryId = entry.id;
      showEntryForm = false;
      pendingPassword = '';
      pushToast('Entry created');
      go('main');
    } catch {
      // Non-fatal: stay in form, let user retry.
    } finally {
      entryFormBusy = false;
    }
  }

</script>

<!--
  Full-screen: bg-cryptiq-bg chrome, centered max-w-md card. Header has back nav.
  GeneratorSurface handles all option state + generation UI — not duplicated here.
-->
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
    <h1 class="text-title font-semibold text-cryptiq-fg">Password Generator</h1>
  </header>

  <!-- Centered generator surface -->
  <div class="flex flex-1 items-start justify-center overflow-y-auto px-6 py-8">
    <div class="w-full max-w-md">
      <GeneratorSurface
        variant="standalone"
        generate={coreGenerate}
        estimateBits={coreEstimateBits}
        initialOptions={savedDefault}
        onSaveDefault={handleSaveDefault}
        onSaveAsEntry={handleSaveAsEntry}
      />
    </div>
  </div>
</div>

<!-- Save-as-new-entry dialog -->
{#if showEntryForm}
  <!-- Backdrop -->
  <div class="fixed inset-0 z-30 bg-cryptiq-bg/80 backdrop-blur-sm" role="presentation" aria-hidden="true"></div>

  <!-- Dialog -->
  <div
    class="fixed inset-0 z-40 flex items-center justify-center p-4"
    role="dialog"
    aria-modal="true"
    aria-labelledby="new-entry-heading"
  >
    <div class="w-full max-w-sm rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface p-6 shadow-cryptiq-popover">
      <h2 id="new-entry-heading" class="mb-1 text-title font-semibold text-cryptiq-fg">Save as new entry</h2>
      <p class="mb-5 text-body text-cryptiq-fg-muted">The generated password will be saved to this new entry.</p>

      <!-- Title (required) -->
      <div class="mb-4">
        <label for="entry-title" class="mb-1 block text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">
          Title <span class="text-cryptiq-danger" aria-hidden="true">*</span>
        </label>
        <input
          id="entry-title"
          type="text"
          bind:value={newTitle}
          placeholder="e.g. GitHub"
          aria-required="true"
          aria-describedby={titleError ? 'title-err' : undefined}
          oninput={() => { if (titleError && newTitle.trim()) titleError = false; }}
          class="w-full rounded-cryptiq border px-3 py-2 text-body text-cryptiq-fg bg-cryptiq-surface-2
                 outline-none placeholder:text-cryptiq-fg-subtle focus:ring-2 focus:ring-cryptiq-ring
                 {titleError ? 'border-cryptiq-danger' : 'border-cryptiq-border-strong'}"
        />
        {#if titleError}
          <p id="title-err" class="mt-1 text-meta text-cryptiq-danger" role="alert">Title is required.</p>
        {/if}
      </div>

      <!-- Username (optional) -->
      <div class="mb-6">
        <label for="entry-username" class="mb-1 block text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">
          Username
          <span class="ml-1 text-cryptiq-fg-subtle font-normal normal-case">(optional)</span>
        </label>
        <input
          id="entry-username"
          type="text"
          bind:value={newUsername}
          placeholder="e.g. you@example.com"
          class="w-full rounded-cryptiq border border-cryptiq-border-strong px-3 py-2 text-body text-cryptiq-fg bg-cryptiq-surface-2
                 outline-none placeholder:text-cryptiq-fg-subtle focus:ring-2 focus:ring-cryptiq-ring"
        />
      </div>

      <!-- Actions -->
      <div class="flex items-center justify-end gap-2">
        <button
          type="button"
          onclick={cancelEntryForm}
          disabled={entryFormBusy}
          class="rounded-cryptiq border border-cryptiq-border-strong px-4 py-2 text-body font-medium text-cryptiq-fg-muted
                 transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-fg disabled:opacity-50"
        >
          Cancel
        </button>
        <button
          type="button"
          onclick={confirmNewEntry}
          disabled={entryFormBusy}
          class="rounded-cryptiq bg-cryptiq-accent px-4 py-2 text-body font-semibold text-cryptiq-accent-fg
                 transition-colors hover:bg-cryptiq-accent-hover disabled:opacity-50"
        >
          {entryFormBusy ? 'Saving…' : 'Save entry'}
        </button>
      </div>
    </div>
  </div>
{/if}
