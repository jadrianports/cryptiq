<!--
  RealAppProof.svelte — labeled real-app screenshot placeholder slots (DEMO-12, D-16).

  2-4 placeholder slots for the everyday-use flow (unlock -> vault list ->
  generate -> copy). Real assets are same-origin img-src 'self' images the
  user drops in later (non-blocking, D-16) — framed cryptiq-* divs, NEVER a
  broken <img src>, until then.

  Capture spec (for the user, when ready to replace these slots):
    - "Unlock": the real master-password unlock screen. The password field
      itself must be visually masked/obscured in the capture — never show a
      real password on screen.
    - "Vault list": a vault populated with a FEW realistic-looking but FAKE
      entries (no real personal accounts); stored passwords collapsed/hidden.
    - "Generate": the password generator panel mid-generation, strength meter
      visible.
    - "Copy": the copy-to-clipboard confirmation/toast after copying a
      generated password.
    - Redaction rules: no real usernames/emails/URLs tied to the capturer's
      actual accounts; crop out OS taskbar/notification chrome where possible.
-->
<script lang="ts">
  const slots = [
    { caption: 'Unlock — the real master-password screen' },
    { caption: 'Vault list — entries at a glance' },
    { caption: 'Generate — a strong password, on demand' },
    { caption: 'Copy — one click, auto-clearing clipboard' },
  ];
</script>

<section id="real-app" class="mx-auto w-full max-w-3xl">
  <h2 class="text-title font-semibold text-cryptiq-fg">The real app</h2>
  <p class="mt-2 text-body text-cryptiq-fg-muted">
    The crypto above is real. So is the app it protects — everyday use, four screens.
  </p>
  <div class="mt-5 grid grid-cols-1 gap-4 sm:grid-cols-2">
    {#each slots as slot (slot.caption)}
      <div>
        <div
          class="flex h-40 items-center justify-center rounded-cryptiq border border-dashed border-cryptiq-border bg-cryptiq-surface-2 text-meta text-cryptiq-fg-subtle"
        >
          [Screenshot coming soon]
        </div>
        <p class="mt-1.5 text-meta text-cryptiq-fg-subtle">{slot.caption}</p>
      </div>
    {/each}
  </div>
</section>
