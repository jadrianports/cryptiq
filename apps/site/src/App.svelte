<script lang="ts">
  import DemoPanel from './hero/DemoPanel.svelte';

  // D-06/D-19/DEMO-10 (39-CONTEXT.md): this is now a long-scroll PAGE — the
  // Phase-38 centered max-w-md single-card "contained shell" composition is
  // GONE. The LOCKED anti-phishing structural contract (type="text" only, no
  // <form> anywhere, no submit control, autocomplete="off", credential-token-
  // free name/id, no "Unlock" verb, no unlock-screen chrome) now lives inside
  // DemoPanel.svelte's passphrase input — this file must never reintroduce
  // any of that structure itself. containment.spec.ts's field-detector test
  // and lint-demo-containment.mjs both re-run against this fuller page.
</script>

<main class="min-h-screen bg-cryptiq-bg">
  <!-- Persistent sticky Download-jump affordance (D-06) — a same-origin
       in-page anchor navigation, not a fetch (containment-safe). -->
  <a
    href="#download"
    class="fixed right-5 top-5 z-10 rounded-cryptiq bg-cryptiq-accent px-4 py-2 text-body font-semibold text-cryptiq-accent-fg shadow-cryptiq-panel transition-colors hover:bg-cryptiq-accent-hover"
  >
    Download ↓
  </a>

  <div class="mx-auto max-w-3xl px-6 py-16 sm:py-24">
    <!-- Hook line (D-07) — no marketing preamble, straight into the demo. -->
    <h1 class="text-display font-semibold text-balance text-cryptiq-fg">
      Don't trust it. Break it.
    </h1>
    <p class="mt-3 max-w-xl text-body text-cryptiq-fg-muted">
      Nothing you type leaves your browser — there's no server to leave to. Open DevTools →
      Network and watch: zero requests.
    </p>

    <div class="mt-10">
      <DemoPanel />
    </div>

    <!-- TODO(39-03): annotated real-app screenshots (D-16) fill this slot. -->
    <section id="real-app" class="mt-24"></section>

    <!-- TODO(39-03): GitHub-Releases download links, checksum + attestation
         verify block, SmartScreen explainer (D-11..D-15) fill this slot. -->
    <section id="download" class="mt-24"></section>

    <!-- Core commit SHA credit (DEMO-07/D-18) — font-mono, Label/Meta size,
         fg-subtle, a real <a> to the source tree at the exact build SHA. -->
    <footer class="mt-24 border-t border-cryptiq-border pt-6">
      <p class="text-meta text-cryptiq-fg-subtle">
        Running <a
          href={`https://github.com/jadrianports/cryptiq/tree/${__CORE_COMMIT_SHA__}/packages/core`}
          class="font-mono underline hover:text-cryptiq-fg"
        >@cryptiq/core @ {__CORE_COMMIT_SHA__.slice(0, 12)}</a>
      </p>
    </footer>
  </div>
</main>
