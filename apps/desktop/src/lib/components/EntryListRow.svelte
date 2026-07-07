<!--
  EntryListRow.svelte — one row in the center entry list (UI-02).

  Reference contract for the virtualized list (UI-03 virtualization technique is
  the planner's call). Presentation-only: it takes plain props and emits a
  select callback; data wiring (VaultSession, sorting, favourites-pinned order)
  is the planner's job.

  States shown: default · hover · selected (accent left-marker + tint) · favorite
  (pinned star) · needs-site-update (UI-09 attention dot). Title + username
  truncate; the row never reflows. Density target: ~56px tall.
-->
<script lang="ts">
  import type { Entry } from '@cryptiq/core';
  import VisualIdentity from './VisualIdentity.svelte';
  import { TYPE_ICON } from './typeIcons';

  type Props = {
    title: string;
    username?: string;
    /** Pinned to the top of the list and marked with the accent star. */
    favorite?: boolean;
    /** UI-09 — site changed its password rules; surfaced as the attention dot. */
    needsUpdate?: boolean;
    selected?: boolean;
    /** Entry type — drives the per-type icon (D-11); login keeps the letter tile. */
    type?: Entry['type'];
    onSelect?: () => void;
  };
  let {
    title,
    username = '',
    favorite = false,
    needsUpdate = false,
    selected = false,
    type = 'login',
    onSelect,
  }: Props = $props();

  /** Login entries keep the letter/gradient tile; all other types show TYPE_ICON. */
  const icon = $derived(type === 'login' ? undefined : TYPE_ICON[type]);
</script>

<button
  type="button"
  onclick={onSelect}
  aria-pressed={selected}
  class="group relative flex w-full items-center gap-3 rounded-cryptiq py-2.5 pr-3 pl-3.5 text-left
         transition-colors duration-150 outline-none
         focus-visible:ring-2 focus-visible:ring-cryptiq-ring
         {selected ? 'bg-cryptiq-selected' : 'hover:bg-cryptiq-hover'}"
>
  <!-- Selected marker: a quiet 2px accent bar, not a heavy fill. -->
  {#if selected}
    <span class="absolute inset-y-2 left-0 w-0.5 rounded-full bg-cryptiq-accent" aria-hidden="true"
    ></span>
  {/if}

  <VisualIdentity label={title} size={36} {...(icon ? { icon } : {})} />

  <span class="min-w-0 flex-1">
    <span class="flex items-center gap-1.5">
      <span class="truncate text-body font-medium text-cryptiq-fg">{title}</span>
      {#if needsUpdate}
        <span
          class="size-1.5 shrink-0 rounded-full bg-cryptiq-attention"
          title="Needs site update"
          aria-label="Needs site update"
        ></span>
      {/if}
    </span>
    <span class="block truncate text-meta text-cryptiq-fg-subtle">
      {username || 'No username'}
    </span>
  </span>

  {#if favorite}
    <!-- Favorite = pinned. Accent is reserved; the star earns it. -->
    <svg
      class="size-3.5 shrink-0 text-cryptiq-accent"
      viewBox="0 0 24 24"
      fill="currentColor"
      aria-label="Favorite"
    >
      <path
        d="M12 2.6l2.6 5.55 6.02.78-4.45 4.16 1.16 5.96L12 16.98 6.67 19.81l1.16-5.96L3.38 9.69l6.02-.78L12 2.6z"
      />
    </svg>
  {/if}
</button>
