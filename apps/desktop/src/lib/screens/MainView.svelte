<!--
  MainView.svelte — the three-column unlocked home screen (P4-04/05).

  Layout: Sidebar (~220px) | EntryList (~320px flex-fixed) | Detail pane (remainder)

  Security (T-04-12, Pitfall 7):
    Decrypted entries are read via $derived(vaultSession.vault?.entries ?? []).
    They are NEVER copied into local $state — that would re-introduce the
    deep-reactive-proxy DevTools secret-leak (Pitfall 7 / CLAUDE.md §Crypto rules).
    The vault key stays entirely out of this file — it's non-reactive on VaultSession.

  Search (UI-04):
    The input → query assignment is debounced at ~100ms (D-TIMING).
    The $derived filter chain over the in-memory entries is NOT debounced —
    it re-runs synchronously after the debounce fires, which is correct and fast.

  Filter chain (in order, UI-02/09/11):
    1. Apply ui.listFilter (active vs tombstone; favorites/needs-update sub-filters)
    2. Apply debounced multi-field search across title/username/url/notes/tags
    3. Sort: favorites pinned to top, then ascending localeCompare on title (UI-11)

  Ctrl+F / Cmd+F (UI-04):
    A window keydown handler preventDefault()s and focuses the search input.
    The handler is added in $effect and cleaned up on component unmount.

  Empty/no-results states (UI-11):
    - No entries in vault at all → "empty vault" state
    - Entries exist but filter/search matches nothing → "no results" state
-->
<script lang="ts">
  import type { Entry } from '@cryptiq/core';
  import { vaultSession } from '../state/vault.svelte';
  import { ui } from '../state/ui.svelte';
  import { debounce } from '../util/debounce';
  import Sidebar from '../components/Sidebar.svelte';
  import EntryList from '../components/EntryList.svelte';
  import EntryDetail from '../components/EntryDetail.svelte';
  import RecentlyDeletedList from './RecentlyDeletedList.svelte';

  /**
   * Helper to extract the typed Entry array from the vault's opaque `entries` field.
   * `UnlockedVault.entries` is typed as `object` in Phase 2 (opaque to vault format
   * layer); Phase 3 writes an `InnerDoc` into it. This cast is safe — all CRUD verbs
   * maintain the InnerDoc shape. This mirrors the asInnerDoc() pattern in core/crud.ts
   * (single-cast strategy — keep it here to avoid importing internal core functions).
   */
  function getEntries(vault: { entries: object } | null): Entry[] {
    if (vault === null) return [];
    const inner = vault.entries as { entries?: Entry[] };
    return Array.isArray(inner.entries) ? inner.entries : [];
  }

  // ── Search ────────────────────────────────────────────────────────────────

  /**
   * The committed search query that $derived uses.
   * Only assigned via the debounced setter below — never directly.
   */
  let committedQuery = $state('');

  /**
   * Debounced setter: the input fires this; it commits after 100ms of silence.
   * The $derived filter chain re-evaluates after committedQuery changes.
   * D-TIMING: 100ms (UI-04).
   */
  const setQuery = debounce((v: string) => {
    committedQuery = v;
  }, 100);

  /** Reference to the search <input> element for Ctrl+F focus (UI-04). */
  let searchInput: HTMLInputElement | null = null;

  // ── Entry derivation (Pitfall 7) ──────────────────────────────────────────

  /**
   * All entries from the in-memory vault.
   * $derived — reads from $state.raw on VaultSession; never a local deep $state.
   * (T-04-12 mitigation: proxy-free read path.)
   *
   * Returns a FRESH array (spread) on every run: the session mutates the inner entries
   * array in place and reassigns #vault via a shallow `{...vault}`, so getEntries() yields
   * the SAME array reference after add/edit/delete. Svelte 5 $derived short-circuits on
   * reference equality, so without the spread the downstream filter chain would not
   * propagate and the list would not repaint until a remount (UAT T8).
   */
  const allEntries = $derived([...getEntries(vaultSession.vault)]);

  /**
   * Step 1 — Apply the active list filter:
   *   all              → active entries (deletedAt === null)
   *   favorites        → active entries with favorite flag
   *   needs-update     → active entries with needsSiteUpdate flag (UI-09)
   *   recently-deleted → tombstones (deletedAt !== null); read-only in Phase 4
   */
  const filteredByCategory = $derived(
    (() => {
      const filter = ui.listFilter;
      if (filter === 'recently-deleted') {
        return allEntries.filter((e) => e.deletedAt !== null);
      }
      const active = allEntries.filter((e) => e.deletedAt === null);
      if (filter === 'favorites') {
        return active.filter((e) => e.favorite);
      }
      if (filter === 'needs-update') {
        return active.filter((e) => e.needsSiteUpdate);
      }
      // 'all'
      return active;
    })(),
  );

  /**
   * Step 2 — Apply debounced multi-field search.
   * An empty or whitespace-only query passes through without filtering.
   * Search is case-insensitive; tags is a string array — joined per element.
   */
  const filteredBySearch = $derived(
    (() => {
      const q = committedQuery.trim().toLowerCase();
      if (q === '') return filteredByCategory;
      return filteredByCategory.filter((e) => {
        const fields = [e.title, e.username, e.url, e.notes, ...e.tags];
        return fields.some((f) => f.toLowerCase().includes(q));
      });
    })(),
  );

  /**
   * Step 3 — Sort: favorites pinned first, then ascending localeCompare on title.
   * UI-11: favorites are always at the top of the list regardless of other sort.
   * Spread first to avoid mutating the $derived source array in place.
   */
  const visibleRows = $derived(
    [...filteredBySearch].sort((a, b) => {
      if (a.favorite !== b.favorite) return a.favorite ? -1 : 1;
      return a.title.localeCompare(b.title);
    }),
  );

  // ── Keyboard shortcut — Ctrl+F / Cmd+F (UI-04) ────────────────────────────

  $effect(() => {
    function handleKeydown(e: KeyboardEvent) {
      if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
        e.preventDefault();
        searchInput?.focus();
      }
    }
    window.addEventListener('keydown', handleKeydown);
    return () => window.removeEventListener('keydown', handleKeydown);
  });

  // ── "+ New" affordance (P4-14) ─────────────────────────────────────────────

  /**
   * Create a blank entry and select it so the detail pane opens in edit mode.
   * Title is empty — EntryDetail enforces non-empty title before the first save (P4-14).
   * Uses addEntry (async) → set selectedEntryId synchronously after await.
   */
  async function handleNewEntry(): Promise<void> {
    const entry = await vaultSession.addEntry({ title: 'New Entry' });
    ui.selectedEntryId = entry.id;
  }

  // ── Derived helpers for the detail / empty states ─────────────────────────

  /** True if the vault has been unlocked but has zero active entries (empty-vault state). */
  const hasNoEntriesAtAll = $derived(
    vaultSession.vault !== null &&
      allEntries.filter((e) => e.deletedAt === null).length === 0 &&
      ui.listFilter === 'all' &&
      committedQuery.trim() === '',
  );

  /** True if entries exist but the current filter+search yields nothing. */
  const hasNoResults = $derived(!hasNoEntriesAtAll && visibleRows.length === 0);
</script>

<!--
  Three-column flex shell. h-screen + overflow-hidden lets each column manage
  its own scroll independently (the sidebar and detail pane scroll within
  themselves; the entry list handles its own overflow via EntryList.svelte).
-->
<div class="flex h-screen overflow-hidden bg-cryptiq-bg">
  <!-- ── Column 1: Sidebar (~220px) ──────────────────────────────────────── -->
  <Sidebar />

  <!-- ── Column 2: Entry list (~320px) ────────────────────────────────────── -->
  <div class="flex w-[320px] shrink-0 flex-col border-r border-cryptiq-border bg-cryptiq-surface">
    <!-- Search bar + New button header -->
    <div class="flex items-center gap-2 border-b border-cryptiq-border px-3 py-2.5">
      <div class="relative flex-1">
        <!-- Search icon -->
        <svg
          class="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-cryptiq-fg-subtle"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="2"
          aria-hidden="true"
        >
          <circle cx="11" cy="11" r="8" />
          <path d="m21 21-4.35-4.35" />
        </svg>
        <input
          bind:this={searchInput}
          type="search"
          placeholder="Search…"
          autocomplete="off"
          spellcheck={false}
          oninput={(e) => setQuery(e.currentTarget.value)}
          class="w-full rounded-cryptiq border border-cryptiq-border bg-cryptiq-surface-2 py-1.5 pr-3 pl-8
                 text-body text-cryptiq-fg placeholder:text-cryptiq-fg-subtle
                 outline-none transition-colors
                 focus:border-cryptiq-accent focus:ring-1 focus:ring-cryptiq-ring"
          aria-label="Search entries (Ctrl+F)"
        />
      </div>

      <!-- "+ New" button (P4-14) -->
      <button
        type="button"
        onclick={handleNewEntry}
        class="grid size-8 shrink-0 place-items-center rounded-cryptiq bg-cryptiq-accent text-cryptiq-accent-fg
               transition-colors hover:bg-cryptiq-accent-hover outline-none
               focus-visible:ring-2 focus-visible:ring-cryptiq-ring"
        aria-label="New entry"
        title="New entry"
      >
        <svg class="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
          <path d="M12 5v14M5 12h14" />
        </svg>
      </button>
    </div>

    <!-- Entry list or empty/no-results states -->
    {#if ui.listFilter === 'recently-deleted'}
      <!--
        Recently Deleted branch (ENTRY-05, P5-11): RecentlyDeletedList owns its own
        empty state and tombstone rows. The active-list empty/no-results states must
        NOT show for tombstones — RecentlyDeletedList handles that internally.
      -->
      <RecentlyDeletedList />
    {:else if hasNoEntriesAtAll}
      <!-- Empty vault state (UI-11) -->
      <div class="flex flex-1 flex-col items-center justify-center gap-3 px-6 text-center">
        <svg
          class="size-10 text-cryptiq-fg-subtle"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="1.5"
          aria-hidden="true"
        >
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
          <path d="M7 11V7a5 5 0 0 1 10 0v4" />
        </svg>
        <p class="text-body font-medium text-cryptiq-fg">Your vault is empty</p>
        <p class="text-meta text-cryptiq-fg-subtle">
          Press the + button to add your first entry.
        </p>
      </div>
    {:else if hasNoResults}
      <!-- No-results state (UI-11) -->
      <div class="flex flex-1 flex-col items-center justify-center gap-3 px-6 text-center">
        <svg
          class="size-10 text-cryptiq-fg-subtle"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="1.5"
          aria-hidden="true"
        >
          <circle cx="11" cy="11" r="8" />
          <path d="m21 21-4.35-4.35" />
          <path d="M8 11h6" />
        </svg>
        <p class="text-body font-medium text-cryptiq-fg">No results</p>
        <p class="text-meta text-cryptiq-fg-subtle">
          Try different keywords or clear the search.
        </p>
      </div>
    {:else}
      <!-- Virtualized entry list — D-VIRT, UI-03 -->
      <EntryList rows={visibleRows} />
    {/if}
  </div>

  <!-- ── Column 3: Detail pane (remainder) ───────────────────────────────── -->
  <div class="flex flex-1 flex-col overflow-hidden bg-cryptiq-surface">
    {#if ui.listFilter === 'recently-deleted'}
      <!--
        Recently Deleted detail pane (UI-SPEC Surface 5, T-5-RD-READONLY mitigated).

        V1 design choice: tombstone rows carry their own Restore/Purge buttons inline
        (RecentlyDeletedList renders them per-row). The detail pane shows a neutral
        placeholder explaining that the user must Restore before making changes.
        This is the simpler approach explicitly sanctioned by UI-SPEC Surface 5 and the
        plan architecture note — it avoids touching EntryDetail.svelte (Plan 04 scope).
      -->
      <div class="flex flex-1 flex-col items-center justify-center gap-2 px-8 text-center">
        <svg
          class="size-10 text-cryptiq-fg-subtle"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="1.5"
          stroke-linecap="round"
          stroke-linejoin="round"
          aria-hidden="true"
        >
          <path d="M3 6h18" />
          <path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
          <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" />
        </svg>
        <p class="text-body font-medium text-cryptiq-fg">Recently Deleted</p>
        <p class="text-meta text-cryptiq-fg-muted">
          This entry is in Recently Deleted. Restore it to make changes.
        </p>
      </div>
    {:else if ui.selectedEntryId !== null}
      <!--
        Detail pane — EntryDetail is the canonical reference component (04-05).
        This plan wires the selection; the full CRUD wiring is completed in 04-05.
        The key={} re-mounts EntryDetail when the selection changes (ensures
        field state is fresh for the new entry).
      -->
      {#key ui.selectedEntryId}
        <EntryDetail
          entryId={ui.selectedEntryId}
          onSoftDelete={() => { ui.selectedEntryId = null; }}
          onPurge={() => { ui.selectedEntryId = null; }}
        />
      {/key}
    {:else}
      <!-- Empty detail pane — no selection -->
      <div class="flex flex-1 flex-col items-center justify-center gap-2 px-8 text-center">
        <svg
          class="size-10 text-cryptiq-fg-subtle"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="1.5"
          aria-hidden="true"
        >
          <path d="M9 5H7a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-2" />
          <rect x="9" y="3" width="6" height="4" rx="1" />
        </svg>
        <p class="text-body font-medium text-cryptiq-fg">Select an entry</p>
        <p class="text-meta text-cryptiq-fg-subtle">
          Choose an entry from the list to view or edit it.
        </p>
      </div>
    {/if}
  </div>
</div>
