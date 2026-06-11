<!--
  MasterRePromptModal.svelte — Generic dialog CHROME for the D-19 master re-prompt modal.

  ARCHITECTURE NOTE (D-19 / SECURITY RATIONALE):
    This modal is pure dialog chrome: backdrop + card + title + body copy + focus trap +
    Escape-cancel. It holds NO password bytes and performs NO crypto.

    Why this is NOT a ConfirmMasterPassword wrapper:
      `ConfirmMasterPassword` has the contract `onConfirmed: () => Promise<void>` —
      it verifies internally and zeroes its own bytes in `finally` before calling
      `onConfirmed()` with NO arguments. Because `runSyncNow(configDir, passwordBytes)`
      needs the live password bytes for the SYNC-05 peer auth check, `ConfirmMasterPassword`
      cannot supply them — its verify-then-discard contract explicitly prevents byte hand-back.

    The D-19 always-re-derive + no-caching + zeroing invariant is satisfied by
    `SyncNowButton.handleConfirmSync`:
      1. TextEncoder → passwordBytes
      2. vaultSession.verifyMasterPassword(passwordBytes) — Argon2id re-derive
      3. runSyncNow(configDir, passwordBytes)
      4. passwordBytes.fill(0) in `finally` on EVERY exit path

    This modal provides ONLY the accessible dialog shell (role="dialog", aria-modal, focus
    trap, Escape routing). SyncNowButton passes its password form as the `children` snippet.

  Props:
    onCancelled — called when the user presses Escape, clicks the backdrop (not implemented
                  for accessibility), or the children snippet invokes cancel.
    children    — the password form body (Svelte 5 Snippet; supplied by SyncNowButton).

  Source: 12-04-PLAN.md Task 1, 12-UI-SPEC.md §"Sync Progress Copy" + "Modal Focus Trap (D-19)",
    12-PATTERNS.md §"MasterRePromptModal.svelte (NEW)", 12-CONTEXT.md D-19.
-->
<script lang="ts">
  import type { Snippet } from 'svelte';

  type Props = {
    /** Called when the user cancels (Escape key or children invokes cancel). */
    onCancelled: () => void;
    /** The password form body — rendered inside the card via {@render children()}. */
    children: Snippet;
  };

  let { onCancelled, children }: Props = $props();

  // ── Focus trap via $effect ───────────────────────────────────────────────────
  // On mount: focus the first focusable element inside the dialog.
  // While open: trap Tab within the dialog; route Escape to onCancelled.
  // Clean up the keydown listener on unmount.

  let dialogEl: HTMLDivElement | null = null;

  const FOCUSABLE_SELECTORS =
    'a[href], button:not([disabled]), textarea:not([disabled]), ' +
    'input:not([disabled]), select:not([disabled]), ' +
    '[tabindex]:not([tabindex="-1"])';

  $effect(() => {
    if (dialogEl === null) return;

    // Focus the first focusable element inside the dialog on mount.
    const firstFocusable = dialogEl.querySelector<HTMLElement>(FOCUSABLE_SELECTORS);
    firstFocusable?.focus();

    function handleKeydown(e: KeyboardEvent): void {
      if (e.key === 'Escape') {
        e.preventDefault();
        onCancelled();
        return;
      }

      if (e.key !== 'Tab') return;

      // Trap focus within the dialog on Tab / Shift+Tab.
      const focusableEls = Array.from(
        dialogEl!.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTORS),
      );
      if (focusableEls.length === 0) {
        e.preventDefault();
        return;
      }

      const first = focusableEls[0] ?? null;
      const last = focusableEls[focusableEls.length - 1] ?? null;

      if (first === null || last === null) {
        e.preventDefault();
        return;
      }

      if (e.shiftKey) {
        // Shift+Tab: if focus is on the first element, wrap to last.
        if (document.activeElement === first) {
          e.preventDefault();
          last.focus();
        }
      } else {
        // Tab: if focus is on the last element, wrap to first.
        if (document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    }

    document.addEventListener('keydown', handleKeydown);
    return () => {
      document.removeEventListener('keydown', handleKeydown);
    };
  });
</script>

<!--
  Full-screen backdrop with centered card.
  role="dialog" aria-modal="true" on the CARD (not the backdrop) — the card IS the dialog.
  The backdrop is presentational; clicking it does not dismiss (keeps the user in the flow).
-->
<div
  class="fixed inset-0 z-50 flex items-center justify-center bg-black/40"
  aria-hidden="true"
>
  <!-- The dialog card — role/aria-modal/aria-label on the card, NOT the outer backdrop div -->
  <div
    bind:this={dialogEl}
    role="dialog"
    aria-modal="true"
    aria-label="Enter master password to sync"
    class="w-full max-w-sm rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface p-6 shadow-cryptiq-popover"
  >
    <!-- UI-SPEC title + body copy (12-UI-SPEC.md §"Sync Progress Copy") -->
    <h2 class="mb-1 text-emphasis font-medium text-cryptiq-fg">Enter master password</h2>
    <p class="mb-4 text-meta text-cryptiq-fg-subtle">
      Your password is verified locally before connecting to any other device.
    </p>

    <!-- Children snippet: the password form body supplied by SyncNowButton -->
    {@render children()}
  </div>
</div>
