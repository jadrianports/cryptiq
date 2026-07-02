<script lang="ts">
  // apps/extension/entrypoints/popup/Popup.svelte
  //
  // Minimal popup (D-17: background SW + popup only, zero content script).
  // Real popup UX (search/copy/lock state) lands in Phase 18 — this phase
  // only needs a shell to host the DEV-only echo trigger (D-18/D-20).
  //
  // D-18: the dev echo section is loaded via a DYNAMIC import gated on
  // import.meta.env.DEV, mirroring apps/desktop/src/main.ts's boot-self-test
  // gating exactly, so Vite/WXT's build-time DEV replacement + dead-code
  // elimination strips the entire DevEcho.svelte chunk (including the
  // "send echo" button string) from production builds.
  import type { Component } from 'svelte';

  let DevEchoComponent: Component | null = $state(null);

  if (import.meta.env.DEV) {
    import('./DevEcho.svelte').then((mod) => {
      DevEchoComponent = mod.default;
    });
  }
</script>

<main>
  <h1 style="font-size: 14px; margin: 0 0 8px;">Cryptiq</h1>
  <p style="font-size: 12px; color: #666; margin: 0;">Native-messaging bridge skeleton.</p>

  {#if import.meta.env.DEV && DevEchoComponent}
    <DevEchoComponent />
  {/if}
</main>
