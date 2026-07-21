<!--
  Verify.svelte — the falsifiability handrail (DEMO-13, D-13, D-10).

  Security contract:
    - NO hardcoded SHA-256 hex digest anywhere in this file. A static,
      connect-src 'none' page structurally cannot know the CURRENT release's
      real checksum at any point after its own last build (39-RESEARCH.md
      Pitfall 5) — baking one in would go stale the instant a new version is
      tagged without a corresponding main push. This section shows a
      copy-ready VERIFICATION PROCEDURE plus a plain <a> to the LIVE
      releases/latest/download/SHA256SUMS asset: the visitor's own browser
      navigates to github.com — this site never fetches it.
    - Copy-button UX mirrors RecoveryKeyCard.svelte's icon-swap pattern
      (apps/desktop/src/lib/components/RecoveryKeyCard.svelte) using
      navigator.clipboard.writeText — a native browser API, not a network
      call, not on lint-demo-containment.mjs's forbidden list.
-->
<script lang="ts">
  const verifyCommand = 'gh attestation verify <downloaded-file> --repo jadrianports/cryptiq';
  const hashCommand = 'Get-FileHash <downloaded-file> -Algorithm SHA256';

  let copiedVerify = $state(false);
  let copiedHash = $state(false);
  let verifyTimer: ReturnType<typeof setTimeout> | undefined;
  let hashTimer: ReturnType<typeof setTimeout> | undefined;

  async function copyVerify(): Promise<void> {
    await navigator.clipboard.writeText(verifyCommand);
    copiedVerify = true;
    clearTimeout(verifyTimer);
    verifyTimer = setTimeout(() => {
      copiedVerify = false;
    }, 1500);
  }

  async function copyHash(): Promise<void> {
    await navigator.clipboard.writeText(hashCommand);
    copiedHash = true;
    clearTimeout(hashTimer);
    hashTimer = setTimeout(() => {
      copiedHash = false;
    }, 1500);
  }
</script>

<section id="verify" class="mx-auto w-full max-w-3xl">
  <div
    class="rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface p-6 shadow-cryptiq-panel sm:p-8"
  >
    <h2 class="text-title font-semibold text-cryptiq-fg">Verify it yourself</h2>

    <!-- Zero-network claim (D-10) — falsifiable, not a marketing assertion. -->
    <p class="mt-2 text-body text-cryptiq-fg-muted">
      Nothing you type leaves your browser — there's no server to leave to. Open DevTools →
      Network and watch: zero requests.
    </p>

    <!-- gh attestation verify — copy-ready procedure, not a baked hash (D-13). -->
    <div class="mt-5 flex items-center gap-2">
      <code
        class="min-w-0 flex-1 select-all truncate rounded-cryptiq border border-cryptiq-border-strong bg-cryptiq-surface-2 px-3 py-2.5 font-mono text-body text-cryptiq-fg"
        >{verifyCommand}</code
      >
      <button
        type="button"
        onclick={() => void copyVerify()}
        aria-label="Copy attestation verify command"
        class="flex shrink-0 items-center gap-1.5 rounded-cryptiq border border-cryptiq-border px-3 py-2.5 text-body font-medium text-cryptiq-fg-muted transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-fg"
      >
        {#if copiedVerify}
          <svg
            class="size-4 shrink-0 text-cryptiq-success"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="1.75"
            stroke-linecap="round"
            stroke-linejoin="round"
            aria-hidden="true"
          >
            <path d="M20 6 9 17l-5-5" />
          </svg>
          Copied
        {:else}
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
            <rect x="9" y="9" width="13" height="13" rx="2" />
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
          </svg>
          Copy
        {/if}
      </button>
    </div>

    <!-- Windows SHA-256 checksum template — same copy-ready treatment. -->
    <div class="mt-3 flex items-center gap-2">
      <code
        class="min-w-0 flex-1 select-all truncate rounded-cryptiq border border-cryptiq-border-strong bg-cryptiq-surface-2 px-3 py-2.5 font-mono text-body text-cryptiq-fg"
        >{hashCommand}</code
      >
      <button
        type="button"
        onclick={() => void copyHash()}
        aria-label="Copy checksum command"
        class="flex shrink-0 items-center gap-1.5 rounded-cryptiq border border-cryptiq-border px-3 py-2.5 text-body font-medium text-cryptiq-fg-muted transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-fg"
      >
        {#if copiedHash}
          <svg
            class="size-4 shrink-0 text-cryptiq-success"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="1.75"
            stroke-linecap="round"
            stroke-linejoin="round"
            aria-hidden="true"
          >
            <path d="M20 6 9 17l-5-5" />
          </svg>
          Copied
        {:else}
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
            <rect x="9" y="9" width="13" height="13" rx="2" />
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
          </svg>
          Copy
        {/if}
      </button>
    </div>

    <!-- Live-linked SHA256SUMS — the visitor's browser navigates to github.com,
         this site never fetches it (D-13, Pitfall 5). -->
    <p class="mt-4 text-body text-cryptiq-fg-muted">
      Match either against the live checksum file:
      <a
        href="https://github.com/jadrianports/cryptiq/releases/latest/download/SHA256SUMS"
        class="font-mono underline hover:text-cryptiq-fg"
      >
        releases/latest/download/SHA256SUMS
      </a>
    </p>
  </div>
</section>
