<!--
  EntryDetail.svelte — the right pane of the master-detail shell (P4-05).

  Canonical reference for the entry detail/edit surface. Demonstrates the locked
  interaction contract:
    • Inline edit (Bitwarden-style) — fields read as text, reveal a frame on focus (UI-05)
    • Auto-save on blur + a "Saved" toast — no Save button (P4-11, UI-12)
    • Masked password with press-and-hold peek + a click toggle (P4-13)
    • Inline generator as a popover anchored to the password field (P4-12, UI-08)
    • Per-field copy with confirmation (UI-06)
    • Open URL, per-entry needs-site-update toggle (UI-09), soft-delete (ENTRY-04)

  Presentation-only. Local $state seeds from props so the reference feels live;
  the planner replaces these with VaultSession CRUD → save() (mutex + dedup
  already handle correctness). Filling a new password MUST push the old value to
  passwordHistory via the core change path (ENTRY-07) — wired by the planner.
-->
<script lang="ts">
  import VisualIdentity from './VisualIdentity.svelte';
  import GeneratorSurface from './GeneratorSurface.svelte';

  type Props = {
    title?: string;
    username?: string;
    password?: string;
    url?: string;
    notes?: string;
    favorite?: boolean;
    needsUpdate?: boolean;
    onOpenUrl?: (url: string) => void;
    onDelete?: () => void;
    onCopy?: (field: string, value: string) => void;
  };
  let {
    title: initialTitle = '',
    username: initialUsername = '',
    password: initialPassword = '',
    url: initialUrl = '',
    notes: initialNotes = '',
    favorite: initialFavorite = false,
    needsUpdate: initialNeedsUpdate = false,
    onOpenUrl,
    onDelete,
    onCopy,
  }: Props = $props();

  // Seed editable local state once from props (the gallery remounts via {#key}
  // to reseed). Intentional snapshot — the planner replaces these with live
  // VaultSession state, so prop-resync is a non-goal here.
  /* svelte-ignore state_referenced_locally */
  let title = $state(initialTitle);
  /* svelte-ignore state_referenced_locally */
  let username = $state(initialUsername);
  /* svelte-ignore state_referenced_locally */
  let password = $state(initialPassword);
  /* svelte-ignore state_referenced_locally */
  let url = $state(initialUrl);
  /* svelte-ignore state_referenced_locally */
  let notes = $state(initialNotes);
  /* svelte-ignore state_referenced_locally */
  let favorite = $state(initialFavorite);
  /* svelte-ignore state_referenced_locally */
  let needsUpdate = $state(initialNeedsUpdate);

  // Two independent reveal affordances (P4-13): sticky toggle OR transient hold.
  let toggledReveal = $state(false);
  let heldReveal = $state(false);
  const revealed = $derived(toggledReveal || heldReveal);

  let showGen = $state(false);
  let copiedField = $state<string | null>(null);
  let toast = $state<string | null>(null);

  function touchSaved(msg = 'Saved') {
    // Stand-in for VaultSession.save() → the toast confirms every persist (UI-12).
    toast = msg;
    setTimeout(() => (toast = null), 1800);
  }
  function copyField(field: string, value: string) {
    onCopy?.(field, value);
    copiedField = field;
    setTimeout(() => (copiedField = copiedField === field ? null : copiedField), 1500);
  }
  function useGenerated(value: string) {
    password = value;
    showGen = false;
    touchSaved('Password updated');
  }
</script>

{#snippet copyButton(field: string, value: string)}
  <button
    type="button"
    onclick={() => copyField(field, value)}
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
    <VisualIdentity label={title} size={44} />
    <input
      bind:value={title}
      onblur={() => touchSaved()}
      placeholder="Title"
      aria-label="Title"
      class="min-w-0 flex-1 rounded-cryptiq bg-transparent px-1.5 py-0.5 text-title font-semibold text-cryptiq-fg
             outline-none placeholder:text-cryptiq-fg-subtle focus:bg-cryptiq-surface-2 focus:ring-2 focus:ring-cryptiq-ring"
    />
    <button
      type="button"
      onclick={() => { favorite = !favorite; touchSaved(favorite ? 'Added to favorites' : 'Removed from favorites'); }}
      title={favorite ? 'Unfavorite' : 'Favorite'}
      aria-pressed={favorite}
      class="grid size-9 place-items-center rounded-cryptiq transition-colors hover:bg-cryptiq-hover
             {favorite ? 'text-cryptiq-accent' : 'text-cryptiq-fg-subtle hover:text-cryptiq-fg'}"
    >
      <svg class="size-5" viewBox="0 0 24 24" fill={favorite ? 'currentColor' : 'none'} stroke="currentColor" stroke-width="1.75" stroke-linejoin="round">
        <path d="M12 2.6l2.6 5.55 6.02.78-4.45 4.16 1.16 5.96L12 16.98 6.67 19.81l1.16-5.96L3.38 9.69l6.02-.78L12 2.6z" />
      </svg>
    </button>
    <button
      type="button"
      onclick={() => { onDelete?.(); touchSaved('Moved to Recently Deleted'); }}
      title="Delete"
      aria-label="Delete entry"
      class="grid size-9 place-items-center rounded-cryptiq text-cryptiq-fg-subtle transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-danger"
    >
      <svg class="size-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18" /><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" /><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" /></svg>
    </button>
  </header>

  <!-- Fields -->
  <div class="flex-1 space-y-5 overflow-y-auto px-6 py-5">
    <!-- Username -->
    <div>
      <span class="mb-1 block text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">Username</span>
      <div class="flex items-center gap-1">
        <input
          bind:value={username}
          onblur={() => touchSaved()}
          placeholder="—"
          aria-label="Username"
          class="min-w-0 flex-1 rounded-cryptiq bg-transparent px-2 py-1.5 text-body text-cryptiq-fg
                 outline-none placeholder:text-cryptiq-fg-subtle focus:bg-cryptiq-surface-2 focus:ring-2 focus:ring-cryptiq-ring"
        />
        {@render copyButton('username', username)}
      </div>
    </div>

    <!-- Password -->
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
          <span class="min-w-0 flex-1 truncate font-mono text-body text-cryptiq-fg select-none">
            {revealed ? password : '•'.repeat(12)}
          </span>
          <span class="ml-2 text-meta text-cryptiq-fg-subtle select-none">hold to peek</span>
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
        <button type="button" class="fixed inset-0 z-10 cursor-default" aria-label="Close generator" onclick={() => (showGen = false)}></button>
        <div class="absolute top-full right-0 z-20 mt-2">
          <GeneratorSurface variant="popover" onUse={useGenerated} />
        </div>
      {/if}
    </div>

    <!-- URL -->
    <div>
      <span class="mb-1 block text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">Website</span>
      <div class="flex items-center gap-1">
        <input
          bind:value={url}
          onblur={() => touchSaved()}
          placeholder="https://"
          aria-label="Website URL"
          class="min-w-0 flex-1 rounded-cryptiq bg-transparent px-2 py-1.5 text-body text-cryptiq-accent
                 outline-none placeholder:text-cryptiq-fg-subtle focus:bg-cryptiq-surface-2 focus:ring-2 focus:ring-cryptiq-ring"
        />
        <button
          type="button"
          onclick={() => onOpenUrl?.(url)}
          disabled={!url}
          title="Open URL"
          aria-label="Open URL in browser"
          class="grid size-8 shrink-0 place-items-center rounded-cryptiq text-cryptiq-fg-subtle transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-fg disabled:opacity-40 disabled:hover:bg-transparent"
        >
          <svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h6v6" /><path d="M10 14 21 3" /><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" /></svg>
        </button>
        {@render copyButton('url', url)}
      </div>
    </div>

    <!-- Notes -->
    <div>
      <span class="mb-1 block text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">Notes</span>
      <textarea
        bind:value={notes}
        onblur={() => touchSaved()}
        rows="3"
        placeholder="Add a note…"
        aria-label="Notes"
        class="w-full resize-none rounded-cryptiq bg-transparent px-2 py-1.5 text-body leading-relaxed text-cryptiq-fg
               outline-none placeholder:text-cryptiq-fg-subtle focus:bg-cryptiq-surface-2 focus:ring-2 focus:ring-cryptiq-ring"
      ></textarea>
    </div>

    <!-- Needs-site-update toggle (UI-09) -->
    <label class="flex items-center justify-between gap-3 rounded-cryptiq border border-cryptiq-border bg-cryptiq-surface-2 px-3 py-2.5">
      <span class="min-w-0">
        <span class="block text-body font-medium text-cryptiq-fg">Needs site update</span>
        <span class="block text-meta text-cryptiq-fg-subtle">Flag this login to revisit and rotate later.</span>
      </span>
      <button
        type="button"
        role="switch"
        aria-checked={needsUpdate}
        aria-label="Needs site update"
        onclick={() => { needsUpdate = !needsUpdate; touchSaved(); }}
        class="relative h-5 w-9 shrink-0 rounded-full transition-colors {needsUpdate ? 'bg-cryptiq-attention' : 'bg-cryptiq-border-strong'}"
      >
        <span class="absolute top-0.5 left-0.5 size-4 rounded-full bg-white shadow-cryptiq-panel transition-transform {needsUpdate ? 'translate-x-4' : ''}"></span>
      </button>
    </label>
  </div>

  <!-- Saved toast -->
  {#if toast}
    <div class="pointer-events-none absolute right-5 bottom-5 z-30">
      <span class="flex items-center gap-1.5 rounded-cryptiq bg-cryptiq-fg px-3 py-1.5 text-meta font-medium text-cryptiq-bg shadow-cryptiq-popover">
        <svg class="size-3.5 text-cryptiq-success" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5" /></svg>
        {toast}
      </span>
    </div>
  {/if}
</section>
