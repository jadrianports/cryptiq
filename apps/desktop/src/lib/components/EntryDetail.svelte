<!--
  EntryDetail.svelte — the right pane of the master-detail shell (P4-05).

  WIRED: This is the LIVE version. Local-state seeds are replaced with reads
  from VaultSession. Every field mutation goes through VaultSession.updateEntry
  + debounced save() + pushToast('Saved') (P4-11/UI-12).

  Interaction contract (all locked, P4-01 design source of truth):
    • Inline edit (Bitwarden-style) — fields read as text, reveal on focus (UI-05)
    • Auto-save on blur + "Saved" toast — NO Save button (P4-11, UI-12)
    • Masked password with press-and-hold peek + a click toggle (P4-13)
    • Inline generator as a popover anchored to the password field (P4-12, UI-08)
      — generated via @cryptiq/core CSPRNG; history auto-pushed by updateEntry (ENTRY-07)
    • Per-field copy writes to clipboard (write-only, UI-06); never reads it
    • Open URL via openInBrowser (capability-scoped plugin-opener, UI-07)
    • needsSiteUpdate toggle persists (ENTRY-08)
    • Soft-delete (tombstone, ENTRY-04)
    • Permanent delete gated behind PurgeConfirm modal (ENTRY-06)
    • "+ New" blank form (P4-14): title required before first save

  Threat mitigations honored:
    T-04-17: copy = writeText only; never readText
    T-04-18: generation via @cryptiq/core; no Math.random
    T-04-19: reads from vaultSession.vault ($state.raw); never wraps in deep $state
    T-04-20: purge gated behind PurgeConfirm explicit confirm
    T-04-21: no console.* of password/notes; toast text is non-secret
-->
<script lang="ts">
  import VisualIdentity from './VisualIdentity.svelte';
  import GeneratorSurface from './GeneratorSurface.svelte';
  import PurgeConfirm from './PurgeConfirm.svelte';
  import ClipboardToast from './ClipboardToast.svelte';
  import { vaultSession } from '../state/vault.svelte';
  import { clipboardClear, armClipboardClear } from '../state/clipboardGuard.svelte';
  import { ui, pushToast } from '../state/ui.svelte';
  import { debounce } from '../util/debounce';
  import { copyField } from '../util/copyField';
  import { openInBrowser } from '../util/openUrl';
  import { invoke } from '@tauri-apps/api/core';
  import { tick } from 'svelte';
  import {
    generateFromOptions,
    estimateEntropyBits,
    getVaultSettings,
    registrableHost,
  } from '@cryptiq/core';
  import type { GeneratorOptions, Entry } from '@cryptiq/core';
  import { TYPE_ICON } from './typeIcons';

  /**
   * Cast the opaque vault.entries (typed as `object` at the vault-format layer)
   * to the InnerDoc shape that all CRUD verbs maintain. This mirrors the pattern
   * used in MainView.svelte — the single-cast strategy (asInnerDoc() in core/crud.ts).
   */
  function getEntries(vault: { entries: object } | null): Entry[] {
    if (vault === null) return [];
    const inner = vault.entries as { entries?: Entry[] };
    return Array.isArray(inner.entries) ? inner.entries : [];
  }

  // ── Props ──────────────────────────────────────────────────────────────
  // entryId drives the wired mode (existing entry). When null, a blank "+New"
  // form is rendered (P4-14): the consumer (MainView) sets this to null to
  // open a blank form, then sets it to the new entry's id after addEntry.
  type Props = {
    entryId: string | null;
    onSoftDelete?: (id: string) => void;
    onPurge?: (id: string) => void;
  };
  let { entryId, onSoftDelete, onPurge }: Props = $props();

  // ── Live entry read (T-04-19: read from $state.raw, never re-wrap) ─────
  // $derived reads re-run whenever vaultSession.vault changes (reassign pattern, P3-02).
  // getEntries() casts the opaque vault.entries object to Entry[] (same pattern as MainView).
  const entry = $derived(
    entryId !== null
      ? (getEntries(vaultSession.vault).find((e) => e.id === entryId) ?? null)
      : null,
  );

  // ── Editable field mirrors ─────────────────────────────────────────────
  // These hold the current value of the input while the user is typing.
  // We seed them from `entry` whenever the entry changes (entryId swap).
  // $state.raw is used for the live values — they hold no secret data longer
  // than the field-edit session and are never deep-proxied.
  let title = $state('');
  let username = $state('');
  let email = $state('');
  let password = $state('');
  let url = $state('');
  let equivalentUrls = $state<string[]>([]);
  let notes = $state('');
  let favorite = $state(false);
  let needsUpdate = $state(false);

  // Identity form mirrors (D-07/TYPES-02). All four subfields are required
  // strings on EntryIdentity — sent as a whole object on every persist (no
  // deep-merge; caller-sends-full-object contract per 23-01 updateEntry).
  let idName = $state('');
  let idEmail = $state('');
  let idPhone = $state('');
  let idAddress = $state('');

  // Equivalent-URL chip editor draft state (URLS-01, D-09/D-10).
  let newUrlDraft = $state('');
  let urlHint = $state<string | null>(null);

  // Type-aware header identity (D-11): non-login entries show their type
  // icon in place of the letter-gradient tile; login is unchanged.
  const headerIcon = $derived(
    entry !== null && entry.type !== 'login' ? TYPE_ICON[entry.type] : undefined,
  );

  // Seed field mirrors whenever the entry identity changes.
  $effect(() => {
    if (entry !== null) {
      title = entry.title;
      username = entry.username ?? '';
      email = entry.email ?? '';
      password = entry.password ?? '';
      url = entry.url ?? '';
      equivalentUrls = entry.equivalentUrls ?? [];
      notes = entry.notes ?? '';
      favorite = entry.favorite ?? false;
      needsUpdate = entry.needsSiteUpdate ?? false;
      idName = entry.identity?.name ?? '';
      idEmail = entry.identity?.email ?? '';
      idPhone = entry.identity?.phone ?? '';
      idAddress = entry.identity?.address ?? '';
    } else {
      // Blank "+New" form (P4-14)
      title = '';
      username = '';
      email = '';
      password = '';
      url = '';
      equivalentUrls = [];
      notes = '';
      favorite = false;
      needsUpdate = false;
      idName = '';
      idEmail = '';
      idPhone = '';
      idAddress = '';
    }
    // Reset the chip-editor draft state on every entry-identity change.
    newUrlDraft = '';
    urlHint = null;
  });

  // ── Jump-to-fix one-shot signals (AUDIT-06 / P6-07) ──────────────────
  // When HealthView sets ui.openGeneratorFor to this entry's id, auto-open
  // the inline generator. When ui.openNeedsSiteUpdateFor is set, focus the
  // needsSiteUpdate toggle. Both signals are cleared immediately after use
  // (one-shot — EntryDetail is remounted via {#key ui.selectedEntryId} so
  // this $effect fires once per selection). An id is NOT secret — plain $state.
  let needsUpdateButtonEl: HTMLButtonElement | null = $state(null);

  $effect(() => {
    if (entry === null) return;
    if (ui.openGeneratorFor === entry.id) {
      ui.openGeneratorFor = null; // consume immediately
      showGen = true;
    }
  });

  $effect(() => {
    if (entry === null) return;
    if (ui.openNeedsSiteUpdateFor === entry.id) {
      ui.openNeedsSiteUpdateFor = null; // consume immediately
      // Focus the needsSiteUpdate toggle after the DOM has settled.
      tick().then(() => {
        needsUpdateButtonEl?.focus();
      }).catch(() => {});
    }
  });

  // ── Reveal state (P4-13) ──────────────────────────────────────────────
  let toggledReveal = $state(false);
  let heldReveal = $state(false);
  const revealed = $derived(toggledReveal || heldReveal);

  // ── Generator popover ─────────────────────────────────────────────────
  let showGen = $state(false);

  // ── Copy feedback ─────────────────────────────────────────────────────
  let copiedField = $state<string | null>(null);

  // ── Purge confirm modal ───────────────────────────────────────────────
  let showPurgeConfirm = $state(false);

  // ── Clipboard auto-clear (P5-08 / LOCK-02/06) ─────────────────────────
  // The authoritative auto-clear lives in the module-level guard
  // (state/clipboardGuard.svelte.ts), NOT in this component — so the copied
  // password's clipboard lifetime survives this component unmounting on
  // navigation (EntryDetail is remounted via {#key ui.selectedEntryId}, and
  // navigating to Settings/Generator unmounts it entirely). This component
  // only ARMS the guard on a password copy and renders the value-free toast
  // while the guard is active. The value NEVER flows to the guard or toast —
  // only the duration does (T-5-TOAST invariant).

  // ── Auto-save (P4-11, D-TIMING 500ms) ─────────────────────────────────
  // Debounced — chains onto save-mutex + FNV-1a dedup in the adapter.
  const scheduleSave = debounce(async () => {
    if (!vaultSession.isUnlocked) return;
    try {
      await vaultSession.save();
      pushToast('Saved'); // UI-12
    } catch {
      // Save errors are non-fatal from the component's perspective;
      // the adapter will surface typed errors to the session if needed.
    }
  }, 500);

  // ── Field blur handlers (auto-save path) ──────────────────────────────
  function handleTitleBlur() {
    if (entryId === null) return; // blank form — no save until first addEntry
    if (!title.trim()) return; // P4-14: title required
    vaultSession.updateEntry(entryId, { title });
    scheduleSave();
  }

  function handleUsernameBlur() {
    if (entryId === null) return;
    vaultSession.updateEntry(entryId, { username });
    scheduleSave();
  }

  // Email is orthogonal to Username — never derived/split from it (IDENT-03).
  function handleEmailBlur() {
    if (entryId === null) return;
    vaultSession.updateEntry(entryId, { email });
    scheduleSave();
  }

  function handlePasswordBlur() {
    if (entryId === null) return;
    // updateEntry pushes old password to history automatically (ENTRY-07 core change path).
    vaultSession.updateEntry(entryId, { password });
    scheduleSave();
  }

  function handleUrlBlur() {
    if (entryId === null) return;
    vaultSession.updateEntry(entryId, { url });
    scheduleSave();
  }

  // ── Equivalent-URL chip editor (D-09/D-10, URLS-01) ───────────────────
  // Chips store the RAW user-entered string — no normalization/canonical-
  // ization. Reduction to eTLD+1 happens only at match time in core's
  // matchByOrigin. Validation here is only a UX guard against obvious
  // garbage/duplicates, never a transformation of the stored value.
  function persistEquivalentUrls() {
    if (entryId === null) return; // blank form — held in the mirror until first save
    vaultSession.updateEntry(entryId, { equivalentUrls: [...equivalentUrls] });
    scheduleSave();
  }

  function addEquivalentUrl(raw: string) {
    const value = raw.trim();
    if (!value) return;
    if (value === url || equivalentUrls.includes(value)) {
      urlHint = 'Already added';
      return;
    }
    if (registrableHost(value) === null) {
      urlHint = 'Enter a valid URL';
      return;
    }
    equivalentUrls = [...equivalentUrls, value];
    newUrlDraft = '';
    urlHint = null;
    persistEquivalentUrls();
  }

  function removeEquivalentUrl(index: number) {
    equivalentUrls = equivalentUrls.filter((_, i) => i !== index);
    persistEquivalentUrls();
  }

  function handleUrlDraftKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter') {
      e.preventDefault();
      addEquivalentUrl(newUrlDraft);
    } else if (e.key === 'Escape') {
      newUrlDraft = '';
      urlHint = null;
    }
  }

  function handleUrlDraftPaste(e: ClipboardEvent) {
    const pasted = e.clipboardData?.getData('text');
    if (!pasted) return;
    e.preventDefault();
    addEquivalentUrl(pasted);
  }

  function handleUrlDraftInput() {
    urlHint = null;
  }

  function handleNotesBlur() {
    if (entryId === null) return;
    vaultSession.updateEntry(entryId, { notes });
    scheduleSave();
  }

  // ── Identity form persist (D-07/TYPES-02) ─────────────────────────────
  // EntryIdentity's four subfields are all required strings — send the whole
  // reconstructed object (wholesale-replace, no deep-merge, per 23-01).
  function persistIdentity() {
    if (entryId === null) return; // blank form — held in mirrors until first save
    vaultSession.updateEntry(entryId, {
      identity: { name: idName, email: idEmail, phone: idPhone, address: idAddress },
    });
    scheduleSave();
  }

  // ── Favorite toggle ────────────────────────────────────────────────────
  function toggleFavorite() {
    if (entryId === null) return;
    const next = !favorite;
    favorite = next;
    vaultSession.updateEntry(entryId, { favorite: next });
    scheduleSave();
  }

  // ── needsSiteUpdate toggle (ENTRY-08) ──────────────────────────────────
  function toggleNeedsUpdate() {
    if (entryId === null) return;
    const next = !needsUpdate;
    needsUpdate = next;
    vaultSession.updateEntry(entryId, { needsSiteUpdate: next });
    scheduleSave();
  }

  // ── Copy (UI-06, T-04-17: write-only; P5-08/09 password path) ─────────
  async function handleCopy(field: string, value: string) {
    if (field === 'password') {
      // Password path: route through Rust (markers + stash) and arm the
      // module-level auto-clear guard (NOT a component-owned timer).
      //
      // Cancel-on-re-copy: if a clear is already armed, clear the prior clipboard
      // value (still-ours check in Rust) before the new write below. armClipboardClear
      // then resets the timer (it cancels the prior guard timer on re-arm).
      if (clipboardClear.active) {
        try {
          await invoke('clipboard_clear_if_ours');
        } catch {
          // Clear failure is non-fatal — the new write below replaces the clipboard anyway.
        }
      }

      // Write to clipboard via Rust (markers + stash). Value never flows to the guard.
      await copyField(value, 'password');

      // Arm the authoritative auto-clear with the vault-configured clearSeconds
      // (never raw settings). getVaultSettings guarantees the default (25s) when
      // clipboard settings are absent. The guard's setTimeout survives this
      // component unmounting — the unmount fix (LOCK-02).
      const vault = vaultSession.vault;
      const clearSeconds =
        vault !== null ? (getVaultSettings(vault).clipboard?.clearSeconds ?? 25) : 25;
      armClipboardClear(clearSeconds);

      // Show the brief checkmark on the copy button (same as other fields).
      copiedField = field;
      setTimeout(() => (copiedField = copiedField === field ? null : copiedField), 1500);
    } else {
      // Non-password fields: plain writeText path (username, URL, notes) — no toast.
      await copyField(value, 'other');
      copiedField = field;
      setTimeout(() => (copiedField = copiedField === field ? null : copiedField), 1500);
    }
  }

  // ── Generator "Use" callback ───────────────────────────────────────────
  // updateEntry's core change path auto-pushes old password to history (ENTRY-07).
  // Do NOT push manually — that would double-push.
  async function useGenerated(value: string) {
    if (entryId === null) {
      // Blank form: just set the local field mirror.
      password = value;
      showGen = false;
      return;
    }
    password = value;
    showGen = false;
    vaultSession.updateEntry(entryId, { password: value });
    await vaultSession.save();
    pushToast('Password updated');
  }

  // ── Core CSPRNG generate + entropy (T-04-18) ──────────────────────────
  // Callbacks injected into GeneratorSurface — never Math.random.
  async function coreGenerate(opts: GeneratorOptions): Promise<string> {
    return generateFromOptions(opts);
  }
  function coreEstimateBits(opts: GeneratorOptions): number {
    return estimateEntropyBits(opts);
  }

  // ── Open URL (UI-07) ──────────────────────────────────────────────────
  async function handleOpenUrl() {
    if (!url) return;
    await openInBrowser(url);
  }

  // ── Soft-delete (ENTRY-04) ────────────────────────────────────────────
  async function handleSoftDelete() {
    if (entryId === null) return;
    vaultSession.softDeleteEntry(entryId);
    await vaultSession.save();
    pushToast('Moved to Recently Deleted');
    onSoftDelete?.(entryId);
    ui.selectedEntryId = null;
  }

  // ── Purge (ENTRY-06) — gated behind PurgeConfirm ─────────────────────
  async function handlePurgeConfirmed() {
    if (entryId === null) return;
    const id = entryId;
    showPurgeConfirm = false;
    vaultSession.purgeEntry(id);
    await vaultSession.save();
    pushToast('Entry deleted permanently');
    onPurge?.(id);
    ui.selectedEntryId = null;
  }
</script>

{#if showPurgeConfirm}
  <PurgeConfirm
    title={title || 'this entry'}
    onConfirm={handlePurgeConfirmed}
    onCancel={() => (showPurgeConfirm = false)}
  />
{/if}

{#if clipboardClear.active}
  <ClipboardToast />
{/if}

{#snippet copyButton(field: string, value: string)}
  <button
    type="button"
    onclick={() => handleCopy(field, value)}
    title="Copy"
    aria-label="Copy {field}"
    class="grid size-8 shrink-0 place-items-center rounded-cryptiq transition-colors hover:bg-cryptiq-hover
           {copiedField === field ? 'text-cryptiq-success' : 'text-cryptiq-fg-subtle hover:text-cryptiq-fg'}"
  >
    {#if copiedField === field}
      <svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5" /></svg>
    {:else}
      <svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15V5a2 2 0 0 1 2-2h10" /></svg>
    {/if}
  </button>
{/snippet}

<section class="relative flex h-full flex-col bg-cryptiq-surface text-cryptiq-fg">
  <!-- Header -->
  <header class="flex items-center gap-3.5 border-b border-cryptiq-border px-6 py-4">
    <VisualIdentity label={title} size={44} {...(headerIcon ? { icon: headerIcon } : {})} />
    <input
      bind:value={title}
      onblur={handleTitleBlur}
      placeholder="Title"
      aria-label="Title"
      class="min-w-0 flex-1 rounded-cryptiq bg-transparent px-1.5 py-0.5 text-title font-semibold text-cryptiq-fg
             outline-none placeholder:text-cryptiq-fg-subtle focus:bg-cryptiq-surface-2 focus:ring-2 focus:ring-cryptiq-ring"
    />
    <!-- Favorite toggle -->
    <button
      type="button"
      onclick={toggleFavorite}
      title={favorite ? 'Unfavorite' : 'Favorite'}
      aria-pressed={favorite}
      class="grid size-9 place-items-center rounded-cryptiq transition-colors hover:bg-cryptiq-hover
             {favorite ? 'text-cryptiq-accent' : 'text-cryptiq-fg-subtle hover:text-cryptiq-fg'}"
    >
      <svg class="size-5" viewBox="0 0 24 24" fill={favorite ? 'currentColor' : 'none'} stroke="currentColor" stroke-width="1.75" stroke-linejoin="round">
        <path d="M12 2.6l2.6 5.55 6.02.78-4.45 4.16 1.16 5.96L12 16.98 6.67 19.81l1.16-5.96L3.38 9.69l6.02-.78L12 2.6z" />
      </svg>
    </button>
    <!-- Soft-delete (ENTRY-04) -->
    <button
      type="button"
      onclick={handleSoftDelete}
      title="Move to Recently Deleted"
      aria-label="Move to Recently Deleted"
      class="grid size-9 place-items-center rounded-cryptiq text-cryptiq-fg-subtle transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-danger"
    >
      <svg class="size-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18" /><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" /><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" /></svg>
    </button>
    <!-- Permanent delete (ENTRY-06, gated behind PurgeConfirm) -->
    <button
      type="button"
      onclick={() => (showPurgeConfirm = true)}
      title="Delete permanently"
      aria-label="Delete entry permanently"
      class="grid size-9 place-items-center rounded-cryptiq text-cryptiq-fg-subtle transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-danger"
    >
      <svg class="size-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
        <path d="M3 6h18" /><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" /><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" />
        <path d="M10 11v6" /><path d="M14 11v6" />
      </svg>
    </button>
  </header>

  <!-- Fields — one dynamic form, swapped by entry.type (D-04). Header + Notes are
       universal (rendered for every type); everything else lives inside a type branch. -->
  <div class="flex-1 space-y-5 overflow-y-auto px-6 py-5">
    {#if entry === null || entry.type === 'login'}
      <!-- Username -->
      <div>
        <span class="mb-1 block text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">Username</span>
        <div class="flex items-center gap-1">
          <input
            bind:value={username}
            onblur={handleUsernameBlur}
            placeholder="—"
            aria-label="Username"
            class="min-w-0 flex-1 rounded-cryptiq bg-transparent px-2 py-1.5 text-body text-cryptiq-fg
                   outline-none placeholder:text-cryptiq-fg-subtle focus:bg-cryptiq-surface-2 focus:ring-2 focus:ring-cryptiq-ring"
          />
          {@render copyButton('username', username)}
        </div>
      </div>

      <!-- Email (IDENT-01) — orthogonal to Username, never derived/split from it (IDENT-03) -->
      <div>
        <span class="mb-1 block text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">Email</span>
        <div class="flex items-center gap-1">
          <input
            bind:value={email}
            onblur={handleEmailBlur}
            placeholder="—"
            aria-label="Email"
            class="min-w-0 flex-1 rounded-cryptiq bg-transparent px-2 py-1.5 text-body text-cryptiq-fg
                   outline-none placeholder:text-cryptiq-fg-subtle focus:bg-cryptiq-surface-2 focus:ring-2 focus:ring-cryptiq-ring"
          />
          {@render copyButton('email', email)}
        </div>
      </div>

      <!-- Password (P4-13 reveal, P4-12 generator) -->
      <div class="relative">
        <span class="mb-1 block text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">Password</span>
        <div class="flex items-center gap-1">
          <!-- Hold anywhere on the value to peek; release re-masks (P4-13). -->
          <div
            class="flex min-w-0 flex-1 items-center rounded-cryptiq bg-cryptiq-surface-2 px-2 py-1.5"
            onpointerdown={() => (heldReveal = true)}
            onpointerup={() => (heldReveal = false)}
            onpointerleave={() => (heldReveal = false)}
            onpointercancel={() => (heldReveal = false)}
            role="presentation"
          >
            <!-- Password edit input — visible when held or toggled -->
            {#if revealed}
              <input
                type="text"
                bind:value={password}
                onblur={handlePasswordBlur}
                placeholder="—"
                aria-label="Password"
                class="min-w-0 flex-1 bg-transparent font-mono text-body text-cryptiq-fg outline-none"
              />
            {:else}
              <span class="min-w-0 flex-1 truncate font-mono text-body text-cryptiq-fg select-none">
                {'•'.repeat(Math.min(12, password.length || 12))}
              </span>
              <span class="ml-2 text-meta text-cryptiq-fg-subtle select-none">hold to peek</span>
            {/if}
          </div>

          <!-- Click toggle (accessibility fallback for press-and-hold). -->
          <button
            type="button"
            onclick={() => (toggledReveal = !toggledReveal)}
            aria-pressed={toggledReveal}
            title={toggledReveal ? 'Hide password' : 'Show password'}
            class="grid size-8 shrink-0 place-items-center rounded-cryptiq text-cryptiq-fg-subtle transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-fg"
          >
            {#if revealed}
              <svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M9.9 4.24A9.1 9.1 0 0 1 12 4c7 0 10 8 10 8a18 18 0 0 1-2.16 3.19M6.6 6.6A18 18 0 0 0 2 12s3 8 10 8a9.3 9.3 0 0 0 5.4-1.6" /><path d="m2 2 20 20" /><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2" /></svg>
            {:else}
              <svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3-8 10-8 10 8 10 8-3 8-10 8-10-8-10-8Z" /><circle cx="12" cy="12" r="3" /></svg>
            {/if}
          </button>

          <!-- Inline generator trigger (popover, P4-12). -->
          <button
            type="button"
            onclick={() => (showGen = !showGen)}
            aria-expanded={showGen}
            title="Generate password"
            class="grid size-8 shrink-0 place-items-center rounded-cryptiq transition-colors hover:bg-cryptiq-hover
                   {showGen ? 'text-cryptiq-accent' : 'text-cryptiq-fg-subtle hover:text-cryptiq-fg'}"
          >
            <svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="m3 21 6-6" /><path d="M14 4l6 6" /><path d="M16.5 2.5 21.5 7.5l-3 3-5-5z" /><circle cx="8" cy="16" r="0.5" fill="currentColor" /><circle cx="6" cy="6" r="0.5" fill="currentColor" /><circle cx="18" cy="16" r="0.5" fill="currentColor" /></svg>
          </button>
          {@render copyButton('password', password)}
        </div>

        {#if showGen}
          <!-- Click-away closer + anchored popover. -->
          <button
            type="button"
            class="fixed inset-0 z-10 cursor-default"
            aria-label="Close generator"
            onclick={() => (showGen = false)}
          ></button>
          <div class="absolute top-full right-0 z-20 mt-2">
            <GeneratorSurface
              variant="popover"
              generate={coreGenerate}
              estimateBits={coreEstimateBits}
              onUse={useGenerated}
            />
          </div>
        {/if}
      </div>

      <!-- URL -->
      <div>
        <span class="mb-1 block text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">Website</span>
        <div class="flex items-center gap-1">
          <input
            bind:value={url}
            onblur={handleUrlBlur}
            placeholder="https://"
            aria-label="Website URL"
            class="min-w-0 flex-1 rounded-cryptiq bg-transparent px-2 py-1.5 text-body text-cryptiq-accent
                   outline-none placeholder:text-cryptiq-fg-subtle focus:bg-cryptiq-surface-2 focus:ring-2 focus:ring-cryptiq-ring"
          />
          <!-- Open URL (UI-07) -->
          <button
            type="button"
            onclick={handleOpenUrl}
            disabled={!url}
            title="Open URL"
            aria-label="Open URL in browser"
            class="grid size-8 shrink-0 place-items-center rounded-cryptiq text-cryptiq-fg-subtle transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-fg disabled:opacity-40 disabled:hover:bg-transparent"
          >
            <svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h6v6" /><path d="M10 14 21 3" /><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" /></svg>
          </button>
          {@render copyButton('url', url)}
        </div>

        <!-- Equivalent-URL chip editor (D-09/D-10, URLS-01) -->
        <div class="mt-2">
          {#if equivalentUrls.length > 0}
            <div class="mb-1.5 flex flex-wrap gap-1.5">
              {#each equivalentUrls as chip, i (chip + i)}
                <span class="flex items-center gap-1 rounded bg-cryptiq-surface-2 px-1 text-xs text-cryptiq-fg">
                  {chip}
                  <button
                    type="button"
                    onclick={() => removeEquivalentUrl(i)}
                    title="Remove"
                    aria-label="Remove equivalent URL {chip}"
                    class="grid size-3.5 place-items-center rounded-full text-cryptiq-fg-subtle hover:text-cryptiq-danger"
                  >
                    <svg class="size-2.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round"><path d="m6 6 12 12M18 6 6 18" /></svg>
                  </button>
                </span>
              {/each}
            </div>
          {/if}
          <input
            bind:value={newUrlDraft}
            onkeydown={handleUrlDraftKeydown}
            onpaste={handleUrlDraftPaste}
            oninput={handleUrlDraftInput}
            placeholder="Add equivalent URL…"
            aria-label="Add equivalent URL"
            class="w-full min-w-0 rounded-cryptiq bg-transparent px-2 py-1 text-meta text-cryptiq-fg
                   outline-none placeholder:text-cryptiq-fg-subtle focus:bg-cryptiq-surface-2 focus:ring-2 focus:ring-cryptiq-ring"
          />
          {#if urlHint}
            <span class="mt-0.5 block text-meta text-cryptiq-danger">{urlHint}</span>
          {/if}
        </div>
      </div>
    {:else if entry.type === 'identity'}
      <!-- Identity form (D-07/TYPES-02): name/email/phone + single free-text address. -->
      <div>
        <span class="mb-1 block text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">Name</span>
        <div class="flex items-center gap-1">
          <input
            bind:value={idName}
            onblur={persistIdentity}
            placeholder="—"
            aria-label="Name"
            class="min-w-0 flex-1 rounded-cryptiq bg-transparent px-2 py-1.5 text-body text-cryptiq-fg
                   outline-none placeholder:text-cryptiq-fg-subtle focus:bg-cryptiq-surface-2 focus:ring-2 focus:ring-cryptiq-ring"
          />
          {@render copyButton('idName', idName)}
        </div>
      </div>

      <div>
        <span class="mb-1 block text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">Email</span>
        <div class="flex items-center gap-1">
          <input
            bind:value={idEmail}
            onblur={persistIdentity}
            placeholder="—"
            aria-label="Identity email"
            class="min-w-0 flex-1 rounded-cryptiq bg-transparent px-2 py-1.5 text-body text-cryptiq-fg
                   outline-none placeholder:text-cryptiq-fg-subtle focus:bg-cryptiq-surface-2 focus:ring-2 focus:ring-cryptiq-ring"
          />
          {@render copyButton('idEmail', idEmail)}
        </div>
      </div>

      <div>
        <span class="mb-1 block text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">Phone</span>
        <div class="flex items-center gap-1">
          <input
            bind:value={idPhone}
            onblur={persistIdentity}
            placeholder="—"
            aria-label="Phone"
            class="min-w-0 flex-1 rounded-cryptiq bg-transparent px-2 py-1.5 text-body text-cryptiq-fg
                   outline-none placeholder:text-cryptiq-fg-subtle focus:bg-cryptiq-surface-2 focus:ring-2 focus:ring-cryptiq-ring"
          />
          {@render copyButton('idPhone', idPhone)}
        </div>
      </div>

      <div>
        <span class="mb-1 block text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">Address</span>
        <textarea
          bind:value={idAddress}
          onblur={persistIdentity}
          rows="3"
          placeholder="Add an address…"
          aria-label="Address"
          class="w-full resize-none rounded-cryptiq bg-transparent px-2 py-1.5 text-body leading-relaxed text-cryptiq-fg
                 outline-none placeholder:text-cryptiq-fg-subtle focus:bg-cryptiq-surface-2 focus:ring-2 focus:ring-cryptiq-ring"
        ></textarea>
      </div>
    {:else if entry.type === 'secure-note'}
      <!-- Secure-note (D-07/TYPES-03): title + free-text body only — the universal
           Notes field below IS the body. Zero autofill surface: no username/password/url. -->
    {/if}
    <!-- {:else if entry.type === 'card'} branch is added by plan 23-06. -->

    <!-- Notes — universal (also doubles as the secure-note body, D-07) -->
    <div>
      <span class="mb-1 block text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">
        {entry?.type === 'secure-note' ? 'Note' : 'Notes'}
      </span>
      <textarea
        bind:value={notes}
        onblur={handleNotesBlur}
        rows="3"
        placeholder="Add a note…"
        aria-label={entry?.type === 'secure-note' ? 'Note' : 'Notes'}
        class="w-full resize-none rounded-cryptiq bg-transparent px-2 py-1.5 text-body leading-relaxed text-cryptiq-fg
               outline-none placeholder:text-cryptiq-fg-subtle focus:bg-cryptiq-surface-2 focus:ring-2 focus:ring-cryptiq-ring"
      ></textarea>
    </div>

    {#if entry === null || entry.type === 'login'}
      <!-- Needs-site-update toggle (ENTRY-08, UI-09) -->
      <label class="flex items-center justify-between gap-3 rounded-cryptiq border border-cryptiq-border bg-cryptiq-surface-2 px-3 py-2.5">
        <span class="min-w-0">
          <span class="block text-body font-medium text-cryptiq-fg">Needs site update</span>
          <span class="block text-meta text-cryptiq-fg-subtle">Flag this login to revisit and rotate later.</span>
        </span>
        <button
          bind:this={needsUpdateButtonEl}
          type="button"
          role="switch"
          aria-checked={needsUpdate}
          aria-label="Needs site update"
          onclick={toggleNeedsUpdate}
          class="relative h-5 w-9 shrink-0 rounded-full transition-colors {needsUpdate ? 'bg-cryptiq-attention' : 'bg-cryptiq-border-strong'}"
        >
          <span class="absolute top-0.5 left-0.5 size-4 rounded-full bg-white shadow-cryptiq-panel transition-transform {needsUpdate ? 'translate-x-4' : ''}"></span>
        </button>
      </label>
    {/if}
  </div>
</section>
