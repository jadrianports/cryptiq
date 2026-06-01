<!--
  PurgeConfirm.svelte — explicit permanent-delete confirmation modal (ENTRY-06).

  Guards the irreversible `purgeEntry` action behind an in-app confirmation dialog.
  Uses the danger semantic tokens (T-04-20 mitigating soft-delete reversal opportunity).

  This is an IN-APP modal, NOT a native browser dialog — native confirm() bypasses
  the P4-02/P4-03 token styling and the production CSP blocks it anyway.

  Props:
    title    — the entry title shown in the warning copy.
    onConfirm — called when the user clicks "Delete Permanently". Caller handles purgeEntry + save.
    onCancel  — called when the user clicks Cancel or presses Escape.
-->
<script lang="ts">
  type Props = {
    title: string;
    onConfirm: () => void;
    onCancel: () => void;
  };
  let { title, onConfirm, onCancel }: Props = $props();

  // Trap Escape key to cancel.
  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      e.preventDefault();
      onCancel();
    }
  }
</script>

<svelte:window onkeydown={handleKeydown} />

<!-- Backdrop -->
<div
  class="fixed inset-0 z-50 flex items-center justify-center bg-black/40"
  role="presentation"
  onclick={(e) => { if (e.target === e.currentTarget) onCancel(); }}
>
  <!-- Dialog -->
  <div
    role="alertdialog"
    aria-modal="true"
    aria-labelledby="purge-title"
    aria-describedby="purge-desc"
    class="w-full max-w-sm rounded-cryptiq-lg border border-cryptiq-danger-border bg-cryptiq-surface p-6 shadow-cryptiq-popover"
  >
    <!-- Icon + heading -->
    <div class="mb-4 flex items-start gap-3">
      <div class="mt-0.5 flex size-9 shrink-0 items-center justify-center rounded-cryptiq bg-cryptiq-danger-surface">
        <svg class="size-5 text-cryptiq-danger" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M3 6h18" />
          <path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
          <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" />
        </svg>
      </div>
      <div>
        <h2 id="purge-title" class="text-emphasis font-semibold text-cryptiq-fg">
          Delete permanently?
        </h2>
        <p id="purge-desc" class="mt-1 text-body text-cryptiq-fg-muted">
          <strong class="font-medium text-cryptiq-fg">{title || 'This entry'}</strong>
          will be removed forever. This cannot be undone.
        </p>
      </div>
    </div>

    <!-- Actions -->
    <div class="flex justify-end gap-2">
      <button
        type="button"
        onclick={onCancel}
        class="rounded-cryptiq border border-cryptiq-border px-4 py-2 text-body font-medium text-cryptiq-fg-muted
               transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-fg focus:outline-none focus:ring-2 focus:ring-cryptiq-ring"
      >
        Cancel
      </button>
      <button
        type="button"
        onclick={onConfirm}
        class="rounded-cryptiq bg-cryptiq-danger px-4 py-2 text-body font-semibold text-cryptiq-danger-fg
               transition-colors hover:opacity-90 focus:outline-none focus:ring-2 focus:ring-cryptiq-ring"
      >
        Delete permanently
      </button>
    </div>
  </div>
</div>
