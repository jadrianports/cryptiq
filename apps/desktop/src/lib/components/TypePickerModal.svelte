<!--
  TypePickerModal.svelte — centered 4-card type picker (D-01, TYPES-04).

  Replaces the old one-click "quick-login" fast path (D-02): the `+` button in
  MainView now opens this modal instead of instantly creating a login entry.

  Security note: this component renders only static type labels + non-secret
  inline-SVG icons (TYPE_ICON, 23-02) — no vault/entry data is read or shown
  here (T-23-09).
-->
<script lang="ts">
  import { tick } from 'svelte';
  import type { Entry } from '@cryptiq/core';
  import { TYPE_ICON } from './typeIcons';

  type Props = {
    /** Fired with the chosen type when a card is clicked. */
    onSelect: (type: Entry['type']) => void;
    /** Fired on backdrop click or Escape — dismiss without creating anything. */
    onCancel: () => void;
  };
  let { onSelect, onCancel }: Props = $props();

  const TYPE_CARDS: { type: Entry['type']; label: string }[] = [
    { type: 'login', label: 'Login' },
    { type: 'card', label: 'Card' },
    { type: 'identity', label: 'Identity' },
    { type: 'secure-note', label: 'Secure Note' },
  ];

  let panel: HTMLDivElement | null = null;

  $effect(() => {
    tick().then(() => {
      panel?.querySelector<HTMLButtonElement>('button')?.focus();
    });
  });

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      e.preventDefault();
      onCancel();
    }
  }
</script>

<svelte:window onkeydown={handleKeydown} />

<!-- Backdrop — click anywhere outside the panel to dismiss (T-23-10). -->
<button
  type="button"
  class="fixed inset-0 z-40 cursor-default bg-black/40"
  aria-label="Close type picker"
  onclick={onCancel}
></button>

<!-- Centered panel. -->
<div
  role="dialog"
  aria-label="Choose entry type"
  aria-modal="true"
  bind:this={panel}
  class="fixed top-1/2 left-1/2 z-50 w-[360px] -translate-x-1/2 -translate-y-1/2
         rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface p-4 shadow-cryptiq-panel"
>
  <p class="mb-3 text-body font-medium text-cryptiq-fg">Choose entry type</p>
  <div class="grid grid-cols-2 gap-2.5">
    {#each TYPE_CARDS as card (card.type)}
      <button
        type="button"
        onclick={() => onSelect(card.type)}
        class="flex flex-col items-center justify-center gap-2 rounded-cryptiq border border-cryptiq-border
               bg-cryptiq-surface-2 px-3 py-5 text-cryptiq-fg outline-none transition-colors
               hover:bg-cryptiq-hover focus-visible:ring-2 focus-visible:ring-cryptiq-ring"
      >
        <svg class="size-7 text-cryptiq-accent" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
          <path d={TYPE_ICON[card.type]} />
        </svg>
        <span class="text-body font-medium">{card.label}</span>
      </button>
    {/each}
  </div>
</div>
