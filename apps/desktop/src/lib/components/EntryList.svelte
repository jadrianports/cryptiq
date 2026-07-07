<!--
  EntryList.svelte — virtualized center-list (D-VIRT, UI-03).

  Hand-rolled fixed-row-height windowing so the list scales to 5,000+ entries
  without a third-party virtualization library (minimal-deps ethos, P4-06).

  Algorithm (D-VIRT):
    ROW = 56 px — aligned with EntryListRow.svelte density target.
    scrollTop + viewportH drive a $derived window [start, start+count).
    An overscan of ±5 rows above and +10 rows below keeps fast scrolling smooth.
    Each visible row is absolutely-positioned inside a spacer of total height
    rows.length * ROW — so the scrollbar reflects the full list length.

  Security (T-04-12, Pitfall 7):
    `rows` is passed in from MainView as a prop that is ALREADY a $derived slice
    of vaultSession.vault.entries. EntryList NEVER wraps entries in local $state —
    doing so would re-introduce the deep-reactive-proxy DevTools leak.

  Selection:
    selected / onSelect are threaded through to EntryListRow via ui.selectedEntryId.
    The import of `ui` is safe: ui holds only IDs (strings), never decrypted bytes.
-->
<script lang="ts">
  import type { Entry } from '@cryptiq/core';
  import EntryListRow from './EntryListRow.svelte';
  import { ui } from '../state/ui.svelte';

  type Props = {
    rows: Entry[];
  };
  let { rows }: Props = $props();

  /** Fixed row height in px — aligns with EntryListRow density target (~56px). */
  const ROW = 56;

  /** Current scroll offset from the top of the container. */
  let scrollTop = $state(0);

  /** Measured height of the scroll container viewport. */
  let viewportH = $state(0);

  /**
   * First row index to render (with overscan above).
   * T-04-14: renders only a windowed slice, not all rows.
   */
  const start = $derived(Math.max(0, Math.floor(scrollTop / ROW) - 5));

  /**
   * Number of rows to render (visible + overscan below).
   * Derived from viewportH so it tracks resize automatically.
   */
  const count = $derived(Math.ceil(viewportH / ROW) + 10);

  /** The visible + overscan slice of the full `rows` array. */
  const slice = $derived(rows.slice(start, start + count));
</script>

<!--
  The scroll container must have a fixed height so overflow-auto works.
  flex-1 + min-h-0 lets it fill the column without pushing past it.
  bg-cryptiq-surface — entry list surface (distinct from sidebar bg-cryptiq-bg).
-->
<div
  class="relative flex-1 overflow-auto bg-cryptiq-surface"
  bind:clientHeight={viewportH}
  onscroll={(e) => (scrollTop = e.currentTarget.scrollTop)}
>
  <!--
    Spacer: height = full list height so the scrollbar is proportional.
    position:relative so each row can be absolutely positioned within it.
  -->
  <div style="height:{rows.length * ROW}px; position:relative;">
    {#each slice as row, i (row.id)}
      <!--
        Each row absolutely positioned at its logical offset.
        (start + i) * ROW = pixel top for this item.
        width:100% keeps rows full-width despite absolute positioning.
      -->
      <div style="position:absolute; top:{(start + i) * ROW}px; left:0; right:0; height:{ROW}px;">
        <EntryListRow
          title={row.title}
          username={row.username}
          favorite={row.favorite}
          needsUpdate={row.needsSiteUpdate}
          type={row.type}
          selected={row.id === ui.selectedEntryId}
          onSelect={() => { ui.selectedEntryId = row.id; }}
        />
      </div>
    {/each}
  </div>
</div>
