<!--
  Stopwatch.svelte — live ticking readout for the real Argon2id derivation
  (DEMO-04). Starts ticking the instant `running` goes true (Derive click),
  freezes at the authoritative worker-measured `finalMs` once it arrives
  (never trusts its own tick as the "real" number — that number comes from
  the Worker's own performance.now() delta, DEMO-03).

  aria-live discipline mirrors ClipboardToast.svelte's convention: a 50ms tick
  would spam a screen reader if announced live, so this renders as a plain
  (non-live) status — the settled final value is read normally once derive
  completes, exactly like ClipboardToast's own "no per-tick announcement" rule.
-->
<script lang="ts">
  type Props = {
    /** True from the Derive click until the real derive-complete/derive-error resolves. */
    running: boolean;
    /** The authoritative elapsed time (ms) once the Worker's derive-complete arrives. */
    finalMs: number | null;
  };
  let { running, finalMs }: Props = $props();

  let displayMs = $state(0);

  $effect(() => {
    if (!running) return;
    const start = performance.now();
    displayMs = 0;
    const id = setInterval(() => {
      displayMs = performance.now() - start;
    }, 50);
    return () => clearInterval(id);
  });

  const shownMs = $derived(finalMs ?? displayMs);
  const shownSeconds = $derived((shownMs / 1000).toFixed(2));
</script>

<p class="font-mono text-emphasis text-cryptiq-fg" role="status" aria-live="off">
  {shownSeconds}s
</p>
