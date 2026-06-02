<!--
  Toast.svelte — general toast notification renderer (UI-12 / P4-11 fix-forward).

  Renders the ui.toasts queue populated by pushToast(). Each toast auto-dismisses
  after 2000ms (D-TIMING) by calling clearToast(id) from an $effect tied to the
  inner ToastItem component's lifecycle — no timer leaks on unmount.

  This component was MISSING in Phase 4 delivery, causing every pushToast() call
  ("Saved", "Password updated", "Entry created", "Imported N entries",
  "Backup saved.", etc.) to be silently invisible. Fixed in the Phase-6 audit.

  Mount point: App.svelte top-level, outside the view switch — overlays ALL views.

  Security: toast.msg is a non-secret status label only. Never log or render secrets
  here (T-04-21). toast.id comes from the monotonic counter in ui.svelte.ts — no
  Math.random (T-04-02).

  Positioning: fixed bottom-right, stacked above ClipboardToast (z-[70] vs z-[60]).
  Stacking: newest toast at bottom (push order), gap-2 between items.
  Accessibility: container aria-live="polite" role="status" — screen readers announce
  each new toast without interrupting current speech.
  Pointer events: when queue is empty the container collapses to zero size and passes
  pointer events through (pointer-events-none on wrapper; each item restores them).
-->
<script lang="ts">
  import { ui, clearToast } from '../state/ui.svelte';

  // D-TIMING: 2000ms auto-dismiss (matches the comment in ui.svelte.ts).
  const DISMISS_MS = 2000;

  // Svelte 5 child component: one instance per toast, owns the dismiss timer.
  // Defined inline as a snippet-style sub-component via class-style rune pattern.
  // Using a separate sub-component ensures each toast gets its own $effect with
  // a stable closure over `id`, avoiding a single shared timer that could drift
  // when toasts are added/removed rapidly.
  //
  // NOTE: Svelte 5 does not support defining components inline in the same file.
  // The auto-dismiss timer is implemented with a keyed {#each} and a per-toast
  // $effect via the ToastItem component in the markup below via the sub-component
  // approach — see ToastItem.svelte. To keep this self-contained (single file),
  // we use an `{#each}` keyed block where each item mounts its own auto-dismiss
  // via a Svelte 5 `$effect` inside a snippet callback. Because Svelte 5 doesn't
  // allow $effect inside snippets, we create the effect via an action.

  /**
   * Svelte action: schedules clearToast(id) after DISMISS_MS.
   * Cleans up the timer if the element is removed before the timer fires
   * (e.g. another toast was manually dismissed first).
   */
  function autoDismiss(_node: HTMLElement, id: string) {
    const timer = setTimeout(() => clearToast(id), DISMISS_MS);
    return {
      destroy() {
        clearTimeout(timer);
      },
    };
  }
</script>

<style>
  /* Entrance animation — respects prefers-reduced-motion. */
  @media (prefers-reduced-motion: no-preference) {
    @keyframes toast-enter {
      from {
        opacity: 0;
        transform: translateY(8px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    .toast-item {
      animation: toast-enter 150ms ease-out both;
    }
  }
</style>

<!--
  Fixed bottom-right stack.
  z-[70]: above ClipboardToast (z-[60]) and PurgeConfirm backdrop (z-50).
  pointer-events-none on wrapper so an empty queue passes clicks through.
  Each toast item restores pointer-events-auto so it is clickable.
  max-w-xs = 320px, matching ClipboardToast's w-64 feel but with text wrapping room.
-->
<div
  class="pointer-events-none fixed bottom-6 right-6 z-[70] flex flex-col-reverse gap-2"
  role="status"
  aria-live="polite"
  aria-atomic="false"
>
  {#each ui.toasts as toast (toast.id)}
    <!--
      Each toast is keyed by toast.id (monotonic counter — no Math.random).
      The `use:autoDismiss` action starts a 2000ms timer when the element mounts
      and cancels it automatically if the element is removed before it fires.
      pointer-events-auto restores interactivity on the card itself.
    -->
    <div
      class="toast-item pointer-events-auto w-64 overflow-hidden rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface shadow-cryptiq-popover"
      use:autoDismiss={toast.id}
      role="none"
    >
      <div class="flex items-center gap-2.5 px-4 py-3">
        <!-- Check-circle icon: size-4, stroke 1.75, 24px viewBox (Phase 4 standard). -->
        <svg
          class="size-4 shrink-0 text-cryptiq-fg-subtle"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="1.75"
          stroke-linecap="round"
          stroke-linejoin="round"
          aria-hidden="true"
        >
          <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
          <path d="m9 11 3 3L22 4" />
        </svg>

        <!-- Toast message: non-secret status label only (T-04-21). -->
        <span class="text-body text-cryptiq-fg-muted">{toast.msg}</span>
      </div>
    </div>
  {/each}
</div>
