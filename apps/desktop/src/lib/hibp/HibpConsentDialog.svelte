<!--
  HibpConsentDialog.svelte — one-time disclosure modal gating HIBP network-egress
  consent (D-03/D-16, HIBP-01/HIBP-06).

  Two copy variants selected via `kind`, both LOCKED verbatim in 31-UI-SPEC.md's
  Copywriting Contract:
    - 'entry-scan'   — gates hibpEntryScanEnabled (stored-password breach scanning,
                        HibpSettingsSection.svelte, this plan).
    - 'master-check' — gates hibpMasterCheckEnabled (master-password breach check,
                        wired by a later plan into FirstRunWizard/ChangeMasterView).
  Same component, different locked copy — do NOT fork a second dialog (31-PLAN Task 1).

  Structure mirrors TypePickerModal.svelte's overlay (backdrop button + role="dialog"
  + aria-modal + Escape-to-cancel + focus-on-mount via tick()), sized to FirstRunStep's
  p-8 dialog padding per UI-SPEC's Spacing Scale. Content is INFORMATIVE, never
  tone="danger" — this is a consent gate, not an alarm (UI-SPEC "READ THIS FIRST").

  Security: renders only static locked copy — no vault/entry data, no secret material.
  Neither the toggle nor this dialog persists anything on its own; only onConfirm
  (wired by the caller) writes hibpEntryScanEnabled/hibpMasterCheckEnabled — the
  toggle never self-consents (D-03).

  Source: 31-03-PLAN.md Task 1; 31-UI-SPEC.md "Component Inventory" +
          "Copywriting Contract"; 31-PATTERNS.md HibpConsentDialog section;
          31-CONTEXT.md D-03/D-16.
-->
<script lang="ts">
  import { tick } from 'svelte';

  type ConsentKind = 'entry-scan' | 'master-check';

  type Props = {
    /** Which locked disclosure copy to render — see the Copywriting Contract. */
    kind: ConsentKind;
    /** Fired when the user explicitly confirms ("Enable breach checking" / "Check this password"). */
    onConfirm: () => void;
    /** Fired on "Not now", Escape, or backdrop click — consent stays OFF, nothing persisted. */
    onCancel: () => void;
  };
  let { kind, onConfirm, onCancel }: Props = $props();

  // ---------------------------------------------------------------------------
  // Locked copy (31-UI-SPEC.md Copywriting Contract) — do not paraphrase.
  // ---------------------------------------------------------------------------
  const eyebrow = $derived(kind === 'entry-scan' ? 'FIRST NETWORK CALL' : undefined);
  const title = $derived(
    kind === 'entry-scan'
      ? 'Enable breach checking?'
      : 'Check your master password against breaches?',
  );
  const affirmativeLabel = $derived(
    kind === 'entry-scan' ? 'Enable breach checking' : 'Check this password',
  );

  let panel: HTMLDivElement | null = null;

  // WR-02: focus a NEUTRAL target by default — never the affirmative (consent-
  // granting) button. This is the sole disclosure gate authorizing the app's
  // first-ever network egress; auto-focusing "Enable"/"Check this password"
  // risks a keyboard double-activation footgun (Enter/Space on the triggering
  // control immediately followed by a stray keyup on the newly-focused affirm
  // button) and lets a habitual double-Enter grant consent unread. A deliberate
  // Tab/click is required to reach the affirmative action.
  $effect(() => {
    tick().then(() => {
      panel?.querySelector<HTMLButtonElement>('[data-hibp-cancel]')?.focus();
    });
  });

  function handleKeydown(e: KeyboardEvent): void {
    if (e.key === 'Escape') {
      e.preventDefault();
      onCancel();
    }
  }
</script>

<svelte:window onkeydown={handleKeydown} />

<!-- Backdrop — click anywhere outside the panel to cancel. -->
<button
  type="button"
  class="fixed inset-0 z-40 cursor-default bg-black/40"
  aria-label="Close dialog"
  onclick={onCancel}
></button>

<!-- Centered panel — p-8 per UI-SPEC's Spacing Scale (matches FirstRunStep.svelte). -->
<div
  role="dialog"
  aria-label={title}
  aria-modal="true"
  bind:this={panel}
  class="fixed top-1/2 left-1/2 z-50 w-[420px] -translate-x-1/2 -translate-y-1/2
         rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface p-8 shadow-cryptiq-panel"
>
  <!-- Eyebrow (entry-scan only) + title — informative, NOT danger-toned. -->
  {#if eyebrow}
    <p class="mb-1.5 text-meta font-semibold tracking-wide uppercase text-cryptiq-accent">
      {eyebrow}
    </p>
  {/if}
  <h2 class="text-title font-semibold text-cryptiq-fg">{title}</h2>

  <!-- Body copy — exact locked disclosure facts, no danger-surface panel. -->
  <div class="mt-3 text-body leading-relaxed text-cryptiq-fg-muted">
    {#if kind === 'entry-scan'}
      <p>
        Cryptiq is offline by design — this is the first network call it will ever make. To
        check a password, only a 5-character prefix of its SHA-1 hash is sent to
        <span class="font-medium text-cryptiq-fg">api.pwnedpasswords.com</span>. Your actual
        password, and its full hash, never leave this device.
      </p>
    {:else}
      <p>
        This sends a 5-character prefix of your password's hash to
        <span class="font-medium text-cryptiq-fg">api.pwnedpasswords.com</span> — the same
        one-way check used for stored passwords. Your master password and its full hash never
        leave this device. This is a separate setting from stored-password breach checking.
      </p>
    {/if}
  </div>

  <!-- Footer — affirmative + plain "Not now", matching FirstRunStep's button pair shape. -->
  <div class="mt-8 flex items-center justify-end gap-3">
    <button
      type="button"
      data-hibp-cancel
      onclick={onCancel}
      class="rounded-cryptiq px-3 py-2 text-body font-medium text-cryptiq-fg-muted transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-fg"
    >
      Not now
    </button>
    <button
      type="button"
      data-hibp-affirm
      onclick={onConfirm}
      class="rounded-cryptiq bg-cryptiq-accent px-5 py-2 text-body font-semibold text-cryptiq-accent-fg transition-colors hover:bg-cryptiq-accent-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cryptiq-ring"
    >
      {affirmativeLabel}
    </button>
  </div>
</div>
