<!--
  FrontDoor.svelte — the honest GitHub-Releases-only download front door
  (DEMO-09, DEMO-11..DEMO-15, D-11..D-15).

  Security contract:
    - The Windows download is the ONLY <a href> on the page pointing at a real
      installer binary, built entirely from __RELEASE_TAG__/__INSTALLER_ASSET__
      (39-01's Vite `define` block — single source of truth, never re-derived
      here) — GitHub Releases ONLY, matching
      github.com/jadrianports/cryptiq/releases/download/<tag>/<asset>. Never a
      re-hosted binary (D-12): two sources of truth for "where the binary comes
      from" is how supply-chain attacks start.
    - macOS is a non-interactive labeled "coming soon" slot — never an <a>/
      <button> that looks clickable (D-11). The extension companion is a
      "coming" slot, never a live-but-broken link (D-15). Mobile gets one
      honest "desktop-only, by design" line.
    - The SmartScreen explainer (D-14) + its labeled screenshot placeholder
      render BEFORE the download button, so the warning reads as expected
      honesty rather than a scare.
    - Draft-publish 404 window (39-RESEARCH.md Pitfall 7): if `main` redeploys
      with a version bump before the corresponding tag's release is published
      (REL-06's human-gated ritual), this link 404s until the human publishes.
      Bounded and self-healing — do NOT add a runtime existence check here
      (would violate connect-src 'none').
-->
<script lang="ts">
  const downloadUrl = `https://github.com/jadrianports/cryptiq/releases/download/${__RELEASE_TAG__}/${__INSTALLER_ASSET__}`;
</script>

<section id="download" class="mx-auto w-full max-w-3xl">
  <div
    class="rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface p-6 shadow-cryptiq-panel sm:p-8"
  >
    <h2 class="text-title font-semibold text-cryptiq-fg">Get the desktop app</h2>

    <!-- SmartScreen explainer (D-14) — appears before the click. -->
    <div class="mt-4 rounded-cryptiq border border-cryptiq-border bg-cryptiq-surface-2 p-4">
      <p class="text-body text-cryptiq-fg">
        Windows will warn "unidentified developer." That's expected — Cryptiq isn't
        code-signed yet (see why: SignPath application pending, $0 always). Verify the
        download instead: match the SHA-256 below, or run the one-line
        <code class="font-mono">gh attestation verify</code> command.
      </p>
      <!-- Labeled screenshot placeholder slot (Pitfall 9, 39-RESEARCH.md) — a
           framed div, NOT a broken <img src>. Real asset dropped in later,
           non-blocking.
           Capture spec: the actual Windows SmartScreen "Windows protected your
           PC" dialog, triggered by running the real unsigned installer; full
           dialog visible; no personal file paths/usernames/other windows in
           frame. -->
      <div
        class="mt-3 flex h-32 items-center justify-center rounded-cryptiq border border-dashed border-cryptiq-border bg-cryptiq-bg text-meta text-cryptiq-fg-subtle"
      >
        [Screenshot: Windows SmartScreen "unidentified developer" warning — coming soon]
      </div>
    </div>

    <!-- Primary CTA (D-12) — GitHub Releases only, built from the tag so it cannot drift. -->
    <a
      href={downloadUrl}
      class="mt-5 inline-block w-full rounded-cryptiq bg-cryptiq-accent px-5 py-2.5 text-center text-body font-semibold text-cryptiq-accent-fg transition-colors hover:bg-cryptiq-accent-hover sm:w-auto"
    >
      Download for Windows
    </a>

    <!-- Honest per-platform slots (D-11/D-15) — never a live-but-broken link. -->
    <div class="mt-6 grid grid-cols-1 gap-3 sm:grid-cols-2">
      <!-- macOS: non-interactive, labeled "coming soon" — a plain div, not an
           <a>/<button>, so it can never be mistaken for a working link. -->
      <div
        class="rounded-cryptiq border border-cryptiq-border bg-cryptiq-surface-2 px-4 py-3 text-body text-cryptiq-fg-muted"
        aria-disabled="true"
      >
        macOS — coming soon
      </div>
      <!-- Extension companion: "coming", never live-but-broken (D-15). -->
      <div
        class="rounded-cryptiq border border-cryptiq-border bg-cryptiq-surface-2 px-4 py-3 text-body text-cryptiq-fg-muted"
        aria-disabled="true"
      >
        Browser extension — click-to-fill via a local bridge, never the network.
        Standalone install: coming soon.
      </div>
    </div>

    <!-- Mobile line (D-11) — desktop-only, by design; the demo above still runs on phones. -->
    <p class="mt-4 text-meta text-cryptiq-fg-subtle">
      Desktop-only today, by design — the live demo above still runs on your phone.
    </p>
  </div>
</section>
