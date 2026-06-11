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

  Sync UI (Phase 12 — 12-04):
    - D-04: SyncNowButton mounted beside Search / +New, hidden when unpaired.
    - D-11: entry list + detail pane dim + pointer-events-none while syncInProgress
            (driven by the tested isSyncInProgress predicate).
    - D-14: counts-only success toast on A-initiated 'done' via formatSyncSummary.
    - D-15: SyncErrorAlert mounted OUTSIDE the dim container (Pitfall 6).
    - D-20: "Updated by sync" note when open entry changes; tombstone → back to list.
-->
<script lang="ts">
  import type { Entry } from '@cryptiq/core';
  import { vaultSession } from '../state/vault.svelte';
  import { ui, pushToast } from '../state/ui.svelte';
  import { debounce } from '../util/debounce';
  import Sidebar from '../components/Sidebar.svelte';
  import EntryList from '../components/EntryList.svelte';
  import EntryDetail from '../components/EntryDetail.svelte';
  import RecentlyDeletedList from './RecentlyDeletedList.svelte';
  import SyncNowButton from '../components/SyncNowButton.svelte';
  import SyncErrorAlert from '../sync/SyncErrorAlert.svelte';
  import { syncStore } from '../sync/SyncStore.svelte';
  import { isSyncInProgress } from '../sync/syncLockState';
  import { formatSyncSummary } from '../sync/syncFormat';

  /**
   * Props contract for Phase 12 (Plan 12-01 Task 3).
   * configDir and vaultPath are threaded from App.svelte so Plan 12-04 can
   * mount SyncNowButton + D-11 lock predicate without prop-drilling at that stage.
   */
  type Props = {
    /** Tauri app config directory (passed to sync/pairing Rust commands). */
    configDir: string;
    /** Filesystem path to the vault file (passed to Rust sync listener). */
    vaultPath: string;
  };
  let { configDir, vaultPath }: Props = $props();

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

  // ── Phase 12 sync wiring (D-04/D-11/D-14/D-15/D-20) ─────────────────────

  /**
   * D-11: true while a sync is in-flight (connecting/syncing/merging/saving).
   * Drives the `pointer-events-none opacity-60` lock on the entry list + detail pane.
   * Uses the tested `isSyncInProgress` predicate — NOT an inline status list.
   */
  const syncInProgress = $derived(isSyncInProgress(syncStore.status));

  /**
   * D-20: local state for the "Updated by sync" note on the open entry detail.
   * - updatedBySyncNote: whether to show the subtle note (true while the flag is set).
   * Cleared on next navigation or after 8 s.
   * The note is static text — no entry fields interpolated (UI-18 fence).
   */
  let updatedBySyncNote = $state(false);
  let _updatedBySyncNoteTimer: ReturnType<typeof setTimeout> | null = null;

  /**
   * D-20: track the open entry's modifiedAt before/during sync so we can detect
   * whether it changed when 'done' fires.
   * Stored as a plain string (ISO timestamp or '') — no entry field data.
   */
  let _preSync_selectedId = $state<string | null>(null);
  let _preSync_modifiedAt = $state<string | null>(null);

  /**
   * D-14 double-fire guard: track the last status+counts key we toasted for, so
   * a re-render of the $effect does not push a duplicate toast.
   */
  let _lastToastedKey = $state('');

  /**
   * D-14 / D-20 success effect:
   *   - D-14: when status becomes 'done' with lastCounts AND isInitiatorMode, push
   *     the counts-only summary toast (A-side only — B-side is App.svelte's).
   *   - D-20: check whether the open entry was tombstoned or modified by the sync
   *     and surface the appropriate notice.
   *
   * SECURITY (UI-18): toast uses formatSyncSummary over integer MergeCounts only.
   * No entry title/username/password/url interpolated.
   */
  $effect(() => {
    if (syncStore.status !== 'done') {
      // Capture the open entry's modifiedAt whenever we enter an in-flight state
      // so we can compare on 'done'. This runs when status is non-done (idle/connecting/etc.).
      if (isSyncInProgress(syncStore.status)) {
        _preSync_selectedId = ui.selectedEntryId;
        const currentEntry =
          ui.selectedEntryId !== null
            ? allEntries.find((e) => e.id === ui.selectedEntryId) ?? null
            : null;
        _preSync_modifiedAt = currentEntry?.modifiedAt ?? null;
      }
      return;
    }

    // Status is 'done' ─────────────────────────────────────────────────────

    const counts = syncStore.lastCounts;

    // D-14: push A-side counts-only success toast (only for initiator, not B-side).
    // formatSyncSummary returns "Already up to date." when added+updated+deleted === 0,
    // or "Synced — N added, M updated, ..." for non-zero-change syncs (UI-18 fence).
    if (syncStore.isInitiatorMode && counts !== null) {
      const toastKey = `done:${String(counts.added)}:${String(counts.updated)}:${String(counts.deleted)}:${String(counts.unchanged)}`;
      if (_lastToastedKey !== toastKey) {
        _lastToastedKey = toastKey;
        // Zero-change sync: formatSyncSummary returns "Already up to date."
        // Non-zero sync: "Synced — N added, M updated, D deleted, U unchanged"
        pushToast(formatSyncSummary(counts));
      }
    }

    // D-20: check whether the open entry changed or was tombstoned during the sync.
    const postSyncId = _preSync_selectedId;
    if (postSyncId !== null) {
      const postEntry = allEntries.find((e) => e.id === postSyncId) ?? null;

      if (postEntry === null || postEntry.deletedAt !== null) {
        // Entry was tombstoned by sync — fall back to list.
        ui.selectedEntryId = null;
        pushToast('The entry you were viewing was deleted by sync.');
      } else if (_preSync_modifiedAt !== null && postEntry.modifiedAt !== _preSync_modifiedAt) {
        // Entry was modified by sync — show the subtle "Updated by sync" note.
        updatedBySyncNote = true;
        if (_updatedBySyncNoteTimer !== null) clearTimeout(_updatedBySyncNoteTimer);
        _updatedBySyncNoteTimer = setTimeout(() => {
          updatedBySyncNote = false;
          _updatedBySyncNoteTimer = null;
        }, 8000);
      }
    }

    // Clear pre-sync captures after processing.
    _preSync_selectedId = null;
    _preSync_modifiedAt = null;
  });

  // Clear the "Updated by sync" note on navigation to a different entry.
  $effect(() => {
    // Reading ui.selectedEntryId makes this reactive to navigation.
    const _id = ui.selectedEntryId;
    if (_id !== null) {
      updatedBySyncNote = false;
      if (_updatedBySyncNoteTimer !== null) {
        clearTimeout(_updatedBySyncNoteTimer);
        _updatedBySyncNoteTimer = null;
      }
    }
  });
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
    <!-- Search bar + Sync Now button + New button header -->
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

      <!-- Sync Now header button (D-04) — self-hides when unpaired -->
      <SyncNowButton {configDir} {vaultPath} />

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

    <!--
      D-15: SyncErrorAlert mounted OUTSIDE the D-11 pointer-events-none locked container
      (Pitfall 6) so "Try Again" is always clickable after a mid-merge error.
      onRetry / onDismiss = syncStore.reset() which clears the error + re-enables Sync Now.
    -->
    {#if syncStore.status === 'error'}
      <SyncErrorAlert
        onRetry={() => syncStore.reset()}
        onDismiss={() => syncStore.reset()}
      />
    {/if}

    <!--
      D-11: entry list content container.
      While syncInProgress: pointer-events-none opacity-60 + a small spinner overlay.
      Lock clears the instant status leaves the in-flight set ('done' or 'error').
    -->
    <div class="relative flex flex-1 flex-col {syncInProgress ? 'pointer-events-none opacity-60' : ''}">
      {#if syncInProgress}
        <!-- Small spinner overlay — visual indicator while list is locked (D-11) -->
        <div class="pointer-events-none absolute inset-0 z-10 flex items-center justify-center">
          <svg
            class="size-4 animate-spin sync-spinner text-cryptiq-fg-subtle"
            viewBox="0 0 24 24"
            fill="none"
            aria-hidden="true"
          >
            <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2.5" class="opacity-20" />
            <path
              d="M22 12a10 10 0 0 0-10-10"
              stroke="currentColor"
              stroke-width="2.5"
              stroke-linecap="round"
            />
          </svg>
        </div>
      {/if}

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
      <div class="relative flex flex-1 flex-col overflow-hidden">
        <!--
          D-20: "Updated by sync" note — subtle caption at the top of the detail pane.
          Static text only — no entry fields interpolated (UI-18 fence / T-12-24).
          text-meta text-cryptiq-fg-subtle per CONTEXT.md D-20.
          Cleared on next navigation (see $effect above) or after 8 s.
        -->
        {#if updatedBySyncNote}
          <p class="border-b border-cryptiq-border px-4 py-1.5 text-meta text-cryptiq-fg-subtle">
            Updated by sync
          </p>
        {/if}
        {#key ui.selectedEntryId}
          <EntryDetail
            entryId={ui.selectedEntryId}
            onSoftDelete={() => { ui.selectedEntryId = null; }}
            onPurge={() => { ui.selectedEntryId = null; }}
          />
        {/key}
      </div>
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

<style>
  @media (prefers-reduced-motion: reduce) {
    .sync-spinner {
      animation: none;
      opacity: 0.5;
    }
  }
</style>
