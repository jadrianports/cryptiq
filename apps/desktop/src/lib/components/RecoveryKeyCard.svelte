<!--
  RecoveryKeyCard.svelte — once-shown recovery key display (AUTH-04/05/06).

  Security contract:
    - The recovery key is shown ONCE here; it is never persisted raw (AUTH-06 / core-enforced).
    - The key renders in font-mono (secret material — app.css convention).
    - The "I have saved my recovery key" required checkbox gates the Continue button (AUTH-04).
    - Print button calls window.print() — no server, no upload, no logs.
    - NEVER console.log the recovery key.

  Used inside FirstRunWizard.svelte when the user opts into recovery-key generation.
-->
<script lang="ts">
  import { copyField } from '../util/copyField';

  type Props = {
    /** The Crockford Base32 recovery key string (54 chars, returned once from createVault). */
    recoveryKey: string;
    /** Called when the user has acknowledged saving the key and clicks Continue. */
    onDone: () => void;
  };
  let { recoveryKey, onDone }: Props = $props();

  let saved = $state(false);
  let copied = $state(false);
  let copyTimer: ReturnType<typeof setTimeout> | undefined;

  async function handleCopy(): Promise<void> {
    // Write-only clipboard (copyField never reads back — T-04-17).
    await copyField(recoveryKey);
    copied = true;
    clearTimeout(copyTimer);
    copyTimer = setTimeout(() => {
      copied = false;
    }, 1500);
  }

  function handlePrint(): void {
    window.print();
  }
</script>

<div class="space-y-5">
  <!-- Recovery key display — single-line, truncated; Copy grabs the full value -->
  <div>
    <p class="mb-2 text-body font-medium text-cryptiq-fg">Your recovery key</p>
    <div class="flex items-center gap-2">
      <code
        class="min-w-0 flex-1 select-all truncate rounded-cryptiq border border-cryptiq-border-strong bg-cryptiq-surface-2 px-3 py-2.5 font-mono text-body text-cryptiq-fg"
        aria-label="Recovery key"
      >{recoveryKey}</code>
      <button
        type="button"
        onclick={() => void handleCopy()}
        aria-label="Copy recovery key"
        class="flex shrink-0 items-center gap-1.5 rounded-cryptiq border border-cryptiq-border px-3 py-2.5 text-body font-medium text-cryptiq-fg-muted transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-fg"
      >
        {#if copied}
          <svg class="size-4 shrink-0 text-cryptiq-success" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M20 6 9 17l-5-5" />
          </svg>
          Copied
        {:else}
          <svg class="size-4 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <rect x="9" y="9" width="13" height="13" rx="2" />
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
          </svg>
          Copy
        {/if}
      </button>
    </div>
    <p class="mt-2 text-meta text-cryptiq-fg-subtle">
      Copy, write down, or print this. It is the only way to recover your vault if you forget your master password.
    </p>
  </div>

  <!-- Print button -->
  <button
    type="button"
    onclick={handlePrint}
    class="flex items-center gap-2 rounded-cryptiq border border-cryptiq-border px-4 py-2 text-body font-medium text-cryptiq-fg-muted transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-fg"
  >
    <svg
      class="size-4 shrink-0"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="1.75"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      <path d="M6 9V2h12v7" />
      <path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2" />
      <rect x="6" y="14" width="12" height="8" rx="1" />
    </svg>
    Print recovery key
  </button>

  <!-- Required "I have saved this" checkbox — gates Continue (AUTH-04) -->
  <label class="flex cursor-pointer items-start gap-2.5 text-body text-cryptiq-fg">
    <input
      type="checkbox"
      bind:checked={saved}
      class="mt-0.5 size-4 shrink-0 rounded-[0.25rem]"
      style="accent-color: var(--color-cryptiq-accent)"
    />
    <span>I have saved my recovery key in a safe place.</span>
  </label>

  <!-- Continue button — disabled until checkbox is ticked -->
  <button
    type="button"
    onclick={onDone}
    disabled={!saved}
    class="w-full rounded-cryptiq bg-cryptiq-accent px-5 py-2.5 text-body font-semibold text-cryptiq-accent-fg transition-colors hover:bg-cryptiq-accent-hover disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:brightness-100"
  >
    Continue
  </button>
</div>
