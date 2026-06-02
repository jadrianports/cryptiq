<!--
  RecentlyDeletedList.svelte — the Recently Deleted view (ENTRY-05, P5-11).

  Renders tombstoned entries (deletedAt !== null) newest-deleted-first.
  Each row shows:
    [VisualIdentity 36px] [title + "Deleted MMM D, YYYY"] [Restore] [Delete forever]

  Per-row actions:
    Restore  → restoreEntry(id) + save(). No confirmation (reversible).
    Delete forever → opens PurgeConfirm → purgeEntry(id) + save(). Irreversible.

  No bulk "empty all" — per-row only (P5-11, T-5-NOBULK mitigated).
  Read-only: tombstones cannot be edited here; user must Restore first (T-5-RD-READONLY).

  Tokens: cryptiq-* only. Danger tokens for Purge; neutral tokens for Restore.
-->
<script lang="ts">
  import { listEntries } from '@cryptiq/core';
  import { vaultSession } from '../state/vault.svelte';
  import { pushToast } from '../state/ui.svelte';
  import VisualIdentity from '../components/VisualIdentity.svelte';
  import PurgeConfirm from '../components/PurgeConfirm.svelte';

  // ── Tombstone list (P5-11, ENTRY-05) ─────────────────────────────────────
  // listEntries(vault, true) returns ALL entries including tombstones.
  // We filter to deletedAt !== null then sort newest-deleted-first.
  const deleted = $derived(
    vaultSession.vault
      ? listEntries(vaultSession.vault, true)
          .filter((e) => e.deletedAt !== null)
          .sort((a, b) => Date.parse(b.deletedAt!) - Date.parse(a.deletedAt!))
      : [],
  );

  // ── Purge gate (T-5-PURGE mitigated via PurgeConfirm) ────────────────────
  let purgeTargetId = $state<string | null>(null);

  // ── Date formatter ────────────────────────────────────────────────────────
  // Absolute "MMM D, YYYY" (e.g. "Jun 1, 2026"). No new dependency — uses
  // Intl.DateTimeFormat which is available in all modern runtimes.
  const dateFormatter = new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });

  function formatDeletedAt(iso: string): string {
    const d = new Date(iso);
    return dateFormatter.format(d);
  }

  // ── Restore (reversible — no confirmation required, P5-11) ───────────────
  // Uses the core `restoreEntry` verb (NOT updateEntry — which refuses
  // tombstones by design, finding entries by deletedAt === null). restoreEntry
  // targets deletedAt !== null and clears the tombstone. Wrapped in try/catch so
  // a save failure surfaces a toast instead of an unhandled rejection.
  async function handleRestore(id: string): Promise<void> {
    try {
      vaultSession.restoreEntry(id);
      await vaultSession.save();
      pushToast('Entry restored');
    } catch {
      pushToast('Could not restore entry');
    }
  }

  // ── Purge (irreversible — routed through PurgeConfirm, T-5-PURGE) ────────
  function openPurge(id: string): void {
    purgeTargetId = id;
  }

  async function handlePurge(): Promise<void> {
    if (purgeTargetId === null) return;
    const id = purgeTargetId;
    purgeTargetId = null; // Clear the dialog immediately (optimistic).
    vaultSession.purgeEntry(id);
    await vaultSession.save();
  }
</script>

<!--
  PurgeConfirm: rendered at the top level so it sits above the list in stacking
  order. The backdrop (z-50) covers the full screen.
-->
{#if purgeTargetId !== null}
  {@const target = deleted.find((e) => e.id === purgeTargetId)}
  <PurgeConfirm
    title={target?.title ?? ''}
    onConfirm={handlePurge}
    onCancel={() => (purgeTargetId = null)}
  />
{/if}

{#if deleted.length === 0}
  <!-- ── Empty state (UI-SPEC Surface 5) ──────────────────────────────────── -->
  <!--
    Canonical icon-tile + heading + body pattern.
    No CTA — the empty state of Recently Deleted has no call to action.
  -->
  <div class="flex flex-1 flex-col items-center justify-center gap-3 px-6 text-center">
    <!-- Icon tile -->
    <div
      class="mx-auto grid size-12 place-items-center rounded-cryptiq-lg bg-cryptiq-surface-2 text-cryptiq-fg-subtle"
      aria-hidden="true"
    >
      <!-- Trash icon (same path as Sidebar item) — stroke 1.5, 24px viewBox -->
      <svg
        class="size-6"
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
    </div>

    <!-- Heading -->
    <p class="text-emphasis font-medium text-cryptiq-fg">Nothing here yet.</p>

    <!-- Body — no CTA -->
    <p class="text-body text-cryptiq-fg-muted">
      Entries you delete will appear here. You can restore them or remove them permanently.
    </p>
  </div>
{:else}
  <!-- ── Tombstone list ─────────────────────────────────────────────────────── -->
  <div class="flex flex-1 flex-col overflow-y-auto">
    <ul class="flex flex-col gap-0.5 px-2 py-2" aria-label="Recently deleted entries">
      {#each deleted as entry (entry.id)}
        <li>
          <!--
            Row layout: [VisualIdentity 36px] [title + date] [Restore] [Delete forever]
            56px row target — py-2.5 + single-line title + meta line achieves ~56px.
            Neutral bg on hover; no selected state (tombstones are not selectable for edit).
          -->
          <div
            class="group flex w-full items-center gap-3 rounded-cryptiq py-2.5 pr-3 pl-3.5
                   transition-colors duration-150 hover:bg-cryptiq-hover"
          >
            <!-- Visual identity tile (36px) -->
            <VisualIdentity label={entry.title} size={36} />

            <!-- Title + date -->
            <div class="min-w-0 flex-1">
              <span class="block truncate text-body font-medium text-cryptiq-fg">
                {entry.title}
              </span>
              <span class="block text-meta text-cryptiq-fg-subtle">
                Deleted {formatDeletedAt(entry.deletedAt!)}
              </span>
            </div>

            <!-- Restore button (neutral tokens, no confirm — reversible) -->
            <button
              type="button"
              onclick={() => handleRestore(entry.id)}
              class="shrink-0 rounded-cryptiq border border-cryptiq-border px-2.5 py-1.5
                     text-meta font-medium text-cryptiq-fg-muted
                     transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-fg
                     focus:outline-none focus-visible:ring-2 focus-visible:ring-cryptiq-ring"
              aria-label={`Restore ${entry.title}`}
            >
              Restore
            </button>

            <!-- Delete forever button (danger tokens — opens PurgeConfirm, T-5-PURGE) -->
            <button
              type="button"
              onclick={() => openPurge(entry.id)}
              class="shrink-0 rounded-cryptiq px-2.5 py-1.5 text-meta font-medium
                     text-cryptiq-danger transition-colors hover:opacity-80
                     focus:outline-none focus-visible:ring-2 focus-visible:ring-cryptiq-ring"
              aria-label={`Delete ${entry.title} forever`}
            >
              Delete forever
            </button>
          </div>
        </li>
      {/each}
    </ul>
  </div>
{/if}
