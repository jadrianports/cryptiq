<!--
  App.svelte — Phase 1 root component.

  Two responsibilities:
   1. (D-01) Render the branded Cryptiq placeholder — proves Svelte 5 + Tailwind v4 + Vite are wired.
   2. (D-03) Gate the first paint on `await sodium.ready` — Phase 2 will populate the actual
      sodium import; Phase 1 ships the gate pattern so crypto-before-ready (Pitfall 3) is
      structurally impossible.

  D-14: single root component, no router. Phase 4 introduces routing when there are
  multiple screens. Avoids premature abstraction.
-->
<script lang="ts">
  // Phase 1: NO sodium import yet. The gate pattern is here so Phase 2 just adds the import.
  // Replace this stub Promise with `(await import('libsodium-wrappers-sumo')).default.ready` in Phase 2.
  let sodiumReady = $state(false);
  let showLoadingHint = $state(false);

  $effect(() => {
    const t0 = performance.now();
    const hintTimer = setTimeout(() => {
      showLoadingHint = true;
    }, 50);

    // Phase 1 stub: resolves immediately. Phase 2 replaces with real sodium.ready.
    Promise.resolve().then(() => {
      const dt = performance.now() - t0;
      // Pitfall 5 detector — re-armed in Phase 2 against real WASM init.
      if (dt > 500) {
        console.warn(
          `[boot] sodium.ready took ${dt.toFixed(0)}ms (>500ms threshold — suspect Vite WASM MIME issue, see Pitfall 5)`,
        );
      }
      sodiumReady = true;
      clearTimeout(hintTimer);
    });

    return () => clearTimeout(hintTimer);
  });
</script>

{#if !sodiumReady}
  <div class="grid h-screen place-items-center">
    {#if showLoadingHint}
      <p class="text-cryptiq-fg-muted text-sm">Loading…</p>
    {/if}
  </div>
{:else}
  <main class="grid h-screen place-items-center">
    <div class="text-center">
      <h1 class="text-cryptiq-fg text-5xl font-semibold tracking-tight">Cryptiq</h1>
      <p class="text-cryptiq-fg-muted mt-3 text-base">Local-first password manager</p>
    </div>
  </main>
{/if}
