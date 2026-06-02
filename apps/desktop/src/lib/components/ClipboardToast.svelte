<!--
  ClipboardToast.svelte — clipboard auto-clear countdown toast (P5-08 / Surface 3).

  VISUAL-ONLY (LOCK-02 hardening): this component owns NO clear timer. The authoritative
  25s clipboard auto-clear lives in the module-level guard (state/clipboardGuard.svelte.ts)
  so the secret's clipboard lifetime survives any component unmount (selecting another
  entry, navigating to Settings/Generator, advancing past the recovery-key wizard step).
  This component is purely the visual reflection of that guard's state.

  SECURITY: This component NEVER receives the copied password value (T-5-TOAST).
  It takes NO props at all — it reads the guard's `clipboardClear` display state
  ({ active, remaining, total }), which carries only countdown integers, never a secret.
  The component renders the literal word "Copied" only, never the secret value.

  Position: fixed bottom-right (bottom: 24px; right: 24px; z-index: 60).
  The depleting progress bar fill uses cryptiq-fg-subtle (not the accent token — deliberate).
  Entrance: toast-enter 150ms ease-out (respects prefers-reduced-motion).
-->
<script lang="ts">
  import { clipboardClear } from '../state/clipboardGuard.svelte';

  // Live countdown number read straight from the module-level guard — the source of
  // truth for "clears in {N}s". No local interval; the guard's 1s tick drives this.
  const remaining = $derived(clipboardClear.remaining);

  // Total the clear was armed with — drives the depleting-bar CSS animation duration.
  // Read once into a local so the CSS custom property stays stable for the bar's
  // animation (re-arming replaces the whole toast via the {#key} the parent uses,
  // so a fresh `total` lands with a fresh entrance).
  const total = $derived(clipboardClear.total);
</script>

<style>
  /* Entrance animation — only fires when user has not requested reduced motion. */
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

    .toast-card {
      animation: toast-enter 150ms ease-out both;
    }
  }

  /* Depleting progress bar: CSS animation drives width 100% → 0% over the total duration. */
  @media (prefers-reduced-motion: no-preference) {
    @keyframes depleting-bar {
      from {
        width: 100%;
      }
      to {
        width: 0%;
      }
    }

    .progress-fill {
      animation: depleting-bar var(--bar-duration) linear both;
    }
  }

  /* Reduced-motion fallback: instant full-width bar (no animation). */
  @media (prefers-reduced-motion: reduce) {
    .progress-fill {
      width: 100%;
    }
  }
</style>

<!--
  Fixed bottom-right card. z-index 60 places it above PurgeConfirm backdrop (z-50).
  w-64 = 256px; rounded-cryptiq-lg = 14px radius (consistent with popovers).
-->
<div
  class="toast-card fixed bottom-6 right-6 z-[60] w-64 overflow-hidden rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface shadow-cryptiq-popover"
  role="status"
  aria-live="off"
  aria-atomic="true"
>
  <!-- Depleting progress bar — informational, not interactive. aria-hidden so screen
       readers rely on the countdown number in the copy text instead. -->
  <div class="h-1 w-full bg-cryptiq-surface-2" aria-hidden="true">
    <div
      class="progress-fill h-full bg-cryptiq-fg-subtle"
      style="--bar-duration: {total}s"
    ></div>
  </div>

  <!-- Toast body -->
  <div class="flex items-center gap-2.5 px-4 pb-4 pt-3">
    <!-- Clipboard-check icon: size-4, stroke 1.75, 24px viewBox (Phase 4 standard). -->
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
      <path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2" />
      <rect x="8" y="2" width="8" height="4" rx="1" ry="1" />
      <path d="m9 12 2 2 4-4" />
    </svg>

    <!-- Copy text: static portion in fg-muted; live countdown number in fg + font-medium.
         aria-live="off" on the parent — the initial announcement is sufficient;
         per-second updates would be too noisy for screen readers. -->
    <span class="text-body text-cryptiq-fg-muted">
      Copied — clears in <span class="font-medium text-cryptiq-fg">{remaining}s</span>
    </span>
  </div>
</div>
