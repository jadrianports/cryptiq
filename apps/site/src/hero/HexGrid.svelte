<!--
  HexGrid.svelte — full clickable hex byte grid over a ciphertext Uint8Array
  (D-03). Every byte is its own independently-clickable button; clicking one
  reports its index to the parent, which flips it in a LOCAL copy and
  re-decrypts (DemoPanel.svelte owns the actual tamper/decrypt call — this
  component only renders + emits clicks, per the "hand-authored {#each}, not a
  data-grid problem" pattern, 39-PATTERNS.md).

  Color contract (39-UI-SPEC.md Color, reserved-accent list item 5): the
  just-clicked cell gets a brief accent highlight; once the parent confirms
  the tamper-fail state for that specific byte, `tamperedIndex` switches it to
  danger — accent never lingers once the real fail-state has landed.
-->
<script lang="ts">
  type Props = {
    bytes: Uint8Array;
    /** Index of the byte the parent has confirmed a tamper-fail result for, or null. */
    tamperedIndex: number | null;
    onCellClick: (byteIndex: number) => void;
  };
  let { bytes, tamperedIndex, onCellClick }: Props = $props();

  let justClicked = $state<number | null>(null);

  function handleClick(index: number): void {
    justClicked = index;
    onCellClick(index);
  }

  function cellClass(index: number): string {
    if (tamperedIndex === index) {
      return 'border-cryptiq-danger-border bg-cryptiq-danger-surface text-cryptiq-danger';
    }
    if (justClicked === index) {
      return 'border-cryptiq-accent bg-cryptiq-accent/10 text-cryptiq-accent';
    }
    return 'border-cryptiq-border bg-cryptiq-surface-2 text-cryptiq-fg-muted hover:border-cryptiq-border-strong hover:text-cryptiq-fg';
  }
</script>

<div
  class="grid grid-cols-8 gap-1 sm:grid-cols-12"
  role="group"
  aria-label="Ciphertext bytes — click any to tamper"
>
  {#each Array.from(bytes) as byte, index (index)}
    <button
      type="button"
      onclick={() => handleClick(index)}
      aria-label={`Byte ${index}: ${byte.toString(16).padStart(2, '0')}`}
      class="rounded-cryptiq border px-1 py-1 font-mono text-meta transition-colors {cellClass(
        index,
      )}"
    >{byte.toString(16).padStart(2, '0')}</button>
  {/each}
</div>
