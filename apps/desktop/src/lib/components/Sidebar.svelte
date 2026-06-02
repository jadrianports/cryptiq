<!--
  Sidebar.svelte — persistent navigation rail (P4-04).

  Items (in order):
    All items       — sets ui.listFilter = 'all'
    Favorites       — sets ui.listFilter = 'favorites'
    Needs update    — sets ui.listFilter = 'needs-update'  (UI-09)
    Recently Deleted — sets ui.listFilter = 'recently-deleted' (ENTRY-05)
    ── divider ──
    Generator       — go('generator')
    Settings        — go('settings')

  Phase 4 scope: "Recently Deleted" is a READ-ONLY tombstone filter entry point.
  The Restore/Purge view is Phase 5 (ENTRY-05 Phase-4 scope). Selecting the item
  shows deleted entries in the list with no restore/purge actions here.

  Active state:
    List filters (All/Favorites/Needs update/Recently Deleted) use
    ui.listFilter to determine the active item — accent marker on the left.
    Generator/Settings use view.current for their active state.
    Accent earns ONLY the active-item marker (bg-cryptiq-accent left bar +
    bg-cryptiq-selected row bg). Nothing else uses the accent token.

  Token rules (P4-03): bg-cryptiq-bg for the sidebar surface (distinct from
  bg-cryptiq-surface used in the list + detail panes).
-->
<script lang="ts">
  import { ui } from '../state/ui.svelte';
  import { view, go } from '../state/view.svelte';
  import type { ListFilter } from '../state/ui.svelte';

  // ── Icon helpers ──────────────────────────────────────────────────────────
  // SVG paths for the six nav items, kept as inline constants (no external icon
  // dep — consistent with the minimal-deps ethos).

  type NavFilter = {
    kind: 'filter';
    label: string;
    filter: ListFilter;
    icon: string;
  };
  type NavAction = {
    kind: 'action';
    label: string;
    view: 'generator' | 'settings' | 'health' | 'import';
    icon: string;
  };

  const filterItems: NavFilter[] = [
    {
      kind: 'filter',
      label: 'All items',
      filter: 'all',
      // Grid / list icon
      icon: 'M3 4h18v2H3V4zm0 7h18v2H3v-2zm0 7h18v2H3v-2z',
    },
    {
      kind: 'filter',
      label: 'Favorites',
      filter: 'favorites',
      // Star icon
      icon: 'M12 2.6l2.6 5.55 6.02.78-4.45 4.16 1.16 5.96L12 16.98 6.67 19.81l1.16-5.96L3.38 9.69l6.02-.78L12 2.6z',
    },
    {
      kind: 'filter',
      label: 'Needs update',
      filter: 'needs-update',
      // Refresh / update circle icon
      icon: 'M12 4V1L8 5l4 4V6c3.31 0 6 2.69 6 6a5.96 5.96 0 0 1-1.12 3.52l1.46 1.46A7.93 7.93 0 0 0 20 12c0-4.42-3.58-8-8-8zm0 14c-3.31 0-6-2.69-6-6a5.96 5.96 0 0 1 1.12-3.52L5.66 7.02A7.93 7.93 0 0 0 4 12c0 4.42 3.58 8 8 8v3l4-4-4-4v3z',
    },
    {
      kind: 'filter',
      label: 'Recently Deleted',
      filter: 'recently-deleted',
      // Trash icon
      icon: 'M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z',
    },
  ];

  const actionItems: NavAction[] = [
    {
      kind: 'action',
      label: 'Health',
      view: 'health',
      // Shield / heart icon — represents vault health
      icon: 'M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z',
    },
    {
      kind: 'action',
      label: 'Import',
      view: 'import',
      // Upload / import arrow icon
      icon: 'M9 16h6v-6h4l-7-7-7 7h4v6zm-4 2h14v2H5v-2z',
    },
    {
      kind: 'action',
      label: 'Generator',
      view: 'generator',
      // Dice / generate icon
      icon: 'M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zM7 7c.55 0 1 .45 1 1s-.45 1-1 1-1-.45-1-1 .45-1 1-1zm0 4c.55 0 1 .45 1 1s-.45 1-1 1-1-.45-1-1 .45-1 1-1zm0 4c.55 0 1 .45 1 1s-.45 1-1 1-1-.45-1-1 .45-1 1-1zm5-8c.55 0 1 .45 1 1s-.45 1-1 1-1-.45-1-1 .45-1 1-1zm0 4c.55 0 1 .45 1 1s-.45 1-1 1-1-.45-1-1 .45-1 1-1zm5 4c.55 0 1 .45 1 1s-.45 1-1 1-1-.45-1-1 .45-1 1-1zm0-4c.55 0 1 .45 1 1s-.45 1-1 1-1-.45-1-1 .45-1 1-1zm0-4c.55 0 1 .45 1 1s-.45 1-1 1-1-.45-1-1 .45-1 1-1z',
    },
    {
      kind: 'action',
      label: 'Settings',
      view: 'settings',
      // Gear icon
      icon: 'M19.14 12.94c.04-.3.06-.61.06-.94s-.02-.64-.07-.94l2.03-1.58c.18-.14.23-.41.12-.61l-1.92-3.32c-.12-.22-.37-.29-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54c-.04-.24-.24-.41-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.09.63-.09.94s.02.64.07.94l-2.03 1.58c-.18.14-.23.41-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z',
    },
  ];

  function isFilterActive(item: NavFilter): boolean {
    // A filter item is active when the list filter matches AND we are in the main view.
    return view.current === 'main' && ui.listFilter === item.filter;
  }

  function isActionActive(item: NavAction): boolean {
    return view.current === item.view;
  }

  function handleFilter(item: NavFilter): void {
    ui.listFilter = item.filter;
    // Return to the main list view when a list filter is selected (in case the user
    // was on generator/settings and taps a filter — returns them to the list).
    go('main');
  }

  function handleAction(item: NavAction): void {
    go(item.view);
  }
</script>

<!--
  ~220px wide persistent rail. Uses bg-cryptiq-bg to contrast with the
  bg-cryptiq-surface of the center list and detail pane (60/30 surface split).
  A hairline right border provides the column separator.
-->
<aside
  class="flex w-[220px] shrink-0 flex-col border-r border-cryptiq-border bg-cryptiq-bg py-3"
  aria-label="Navigation"
>
  <!-- App name / brand mark -->
  <div class="px-4 pb-3">
    <span class="text-title font-semibold text-cryptiq-fg tracking-tight">Cryptiq</span>
  </div>

  <!-- List filter nav items -->
  <nav class="flex flex-col gap-0.5 px-2">
    {#each filterItems as item (item.filter)}
      {@const active = isFilterActive(item)}
      <button
        type="button"
        onclick={() => handleFilter(item)}
        class="group relative flex w-full items-center gap-2.5 rounded-cryptiq px-3 py-2 text-left text-body
               transition-colors duration-150 outline-none
               focus-visible:ring-2 focus-visible:ring-cryptiq-ring
               {active ? 'bg-cryptiq-selected text-cryptiq-fg' : 'text-cryptiq-fg-muted hover:bg-cryptiq-hover hover:text-cryptiq-fg'}"
        aria-current={active ? 'page' : undefined}
      >
        <!-- Active marker: a quiet 2px accent bar — mirrors EntryListRow selected treatment -->
        {#if active}
          <span
            class="absolute inset-y-1.5 left-0 w-0.5 rounded-full bg-cryptiq-accent"
            aria-hidden="true"
          ></span>
        {/if}

        <!-- Item icon -->
        <svg
          class="size-4 shrink-0 {active ? 'text-cryptiq-accent' : 'text-cryptiq-fg-subtle group-hover:text-cryptiq-fg-muted'}"
          viewBox="0 0 24 24"
          fill="currentColor"
          aria-hidden="true"
        >
          <path d={item.icon} />
        </svg>

        <span class="truncate">{item.label}</span>
      </button>
    {/each}
  </nav>

  <!-- Divider between list filters and app navigation -->
  <div class="mx-4 my-2 border-t border-cryptiq-border" aria-hidden="true"></div>

  <!-- App action nav items (Generator / Settings) -->
  <nav class="flex flex-col gap-0.5 px-2">
    {#each actionItems as item (item.view)}
      {@const active = isActionActive(item)}
      <button
        type="button"
        onclick={() => handleAction(item)}
        class="group relative flex w-full items-center gap-2.5 rounded-cryptiq px-3 py-2 text-left text-body
               transition-colors duration-150 outline-none
               focus-visible:ring-2 focus-visible:ring-cryptiq-ring
               {active ? 'bg-cryptiq-selected text-cryptiq-fg' : 'text-cryptiq-fg-muted hover:bg-cryptiq-hover hover:text-cryptiq-fg'}"
        aria-current={active ? 'page' : undefined}
      >
        {#if active}
          <span
            class="absolute inset-y-1.5 left-0 w-0.5 rounded-full bg-cryptiq-accent"
            aria-hidden="true"
          ></span>
        {/if}

        <svg
          class="size-4 shrink-0 {active ? 'text-cryptiq-accent' : 'text-cryptiq-fg-subtle group-hover:text-cryptiq-fg-muted'}"
          viewBox="0 0 24 24"
          fill="currentColor"
          aria-hidden="true"
        >
          <path d={item.icon} />
        </svg>

        <span class="truncate">{item.label}</span>
      </button>
    {/each}
  </nav>
</aside>
