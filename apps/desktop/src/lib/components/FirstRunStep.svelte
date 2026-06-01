<!--
  FirstRunStep.svelte — the first-run wizard shell (P4-07).

  One coherent stepped flow: explainer → unrecoverable-password warning →
  vault location → master password (×2 + meter) → recovery-key opt-in → done.
  A progress indicator means the user always sees how much remains and can't
  accidentally skip the warning.

  tone="danger" + ackLabel renders the signature unrecoverable-password panel
  (P4-08): a visually dominant danger panel whose required acknowledgment
  checkbox ARMS the Continue button. Not type-to-confirm, not a timed modal —
  one honest gate on the happy path.

  Body content is passed as children, so each concrete step (password fields +
  zxcvbn meter, recovery-key display, etc.) composes its own inputs while the
  shell owns chrome, progress, gating, and navigation.
-->
<script lang="ts">
  import type { Snippet } from 'svelte';

  type Props = {
    step: number;
    total: number;
    eyebrow?: string;
    title: string;
    tone?: 'default' | 'danger';
    /** If set, a required checkbox with this label gates Continue (P4-08). */
    ackLabel?: string;
    /** Extra gate beyond ack — e.g. passwords match, length met. */
    canContinue?: boolean;
    /** When false, the footer Continue button is not rendered at all (e.g. when the
     *  slotted content owns its own gated Continue, as on the recovery-key step). */
    showContinue?: boolean;
    continueLabel?: string;
    backLabel?: string;
    onBack?: () => void;
    onContinue?: () => void;
    children?: Snippet;
  };
  let {
    step,
    total,
    eyebrow,
    title,
    tone = 'default',
    ackLabel,
    canContinue = true,
    showContinue = true,
    continueLabel = 'Continue',
    backLabel = 'Back',
    onBack,
    onContinue,
    children,
  }: Props = $props();

  let acked = $state(false);
  const continueEnabled = $derived((!ackLabel || acked) && canContinue);
</script>

<div class="grid h-full place-items-center bg-cryptiq-bg px-6 py-10">
  <div
    class="w-full max-w-lg rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface p-8 shadow-cryptiq-panel"
  >
    <!-- Progress -->
    <div class="mb-7">
      <div class="flex gap-1.5" aria-hidden="true">
        {#each Array.from({ length: total }) as _, i (i)}
          <span class="h-1 flex-1 rounded-full transition-colors {i < step ? 'bg-cryptiq-accent' : 'bg-cryptiq-border'}"></span>
        {/each}
      </div>
      <p class="mt-2 text-meta font-medium text-cryptiq-fg-subtle">Step {step} of {total}</p>
    </div>

    <!-- Heading -->
    {#if eyebrow}
      <p class="mb-1.5 text-meta font-semibold tracking-wide uppercase {tone === 'danger' ? 'text-cryptiq-danger' : 'text-cryptiq-accent'}">
        {eyebrow}
      </p>
    {/if}
    <h1 class="text-display font-semibold text-balance {tone === 'danger' ? 'text-cryptiq-danger' : 'text-cryptiq-fg'}">
      {title}
    </h1>

    <!-- Body -->
    <div class="mt-5">
      {#if tone === 'danger'}
        <div class="flex gap-3.5 rounded-cryptiq border border-cryptiq-danger-border bg-cryptiq-danger-surface p-4">
          <svg class="mt-0.5 size-5 shrink-0 text-cryptiq-danger" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
            <path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z" /><path d="M12 9v4" /><path d="M12 17h.01" />
          </svg>
          <div class="text-body leading-relaxed text-cryptiq-fg">
            {@render children?.()}
          </div>
        </div>
      {:else}
        <div class="text-body leading-relaxed text-cryptiq-fg-muted">
          {@render children?.()}
        </div>
      {/if}
    </div>

    <!-- Required acknowledgment -->
    {#if ackLabel}
      <label class="mt-5 flex cursor-pointer items-start gap-2.5 text-body text-cryptiq-fg">
        <input
          type="checkbox"
          bind:checked={acked}
          class="mt-0.5 size-4 shrink-0 rounded-[0.25rem]"
          style="accent-color: var(--color-cryptiq-danger)"
        />
        <span>{ackLabel}</span>
      </label>
    {/if}

    <!-- Footer -->
    <div class="mt-8 flex items-center justify-between gap-3">
      {#if onBack}
        <button
          type="button"
          onclick={onBack}
          class="rounded-cryptiq px-3 py-2 text-body font-medium text-cryptiq-fg-muted transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-fg"
        >
          {backLabel}
        </button>
      {:else}
        <span></span>
      {/if}
      {#if showContinue}
        <button
          type="button"
          onclick={onContinue}
          disabled={!continueEnabled}
          class="rounded-cryptiq px-5 py-2 text-body font-semibold text-cryptiq-accent-fg transition-colors
                 {tone === 'danger' ? 'bg-cryptiq-danger hover:brightness-110' : 'bg-cryptiq-accent hover:bg-cryptiq-accent-hover'}
                 disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:brightness-100"
        >
          {continueLabel}
        </button>
      {:else}
        <span></span>
      {/if}
    </div>
  </div>
</div>
