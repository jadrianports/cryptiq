<script lang="ts">
  // D-03/D-04 (LOCKED structural contract — 38-CONTEXT.md): the minimal
  // contained shell this GATE-let phase must render. Exact copy/label/visual
  // polish is Phase 39's job; what is LOCKED here is the STRUCTURE:
  //
  //   - type="text" ONLY — never type="password", anywhere on this page.
  //   - NO <form> element wrapping this (or anything else on the page).
  //   - NO submit control (button[type=submit] / input[type=submit] / a bare
  //     <button> with no type, which findUsernameOnlyCandidate() also treats
  //     as a submit signal).
  //   - autocomplete="off" — no credential autocomplete token.
  //   - name/id are free of every credential token
  //     (user/email/pass/login/secret/identifier) AND do not match
  //     apps/extension/src/lib/fieldDetection.ts's STRONG_USERNAME_PATTERN
  //     (/user(name)?|e-?mail|login|identifier/i) — "demo-vault-value"
  //     contains none of those substrings.
  //   - The value is PRE-FILLED and VISIBLE (a demo passphrase), never empty.
  //
  // This is what makes Cryptiq's OWN extension field-detector (the DEMO-01
  // test oracle wired in 38-02) find NOTHING here — no <form> means
  // findUsernameOnlyCandidate()'s hasFormContext check fails even before the
  // name/id check is reached, and the credential-token-free name/id is a
  // second, independent lock (38-RESEARCH.md Pattern 3).
  let demoValue = $state('correct horse battery staple');
</script>

<main class="flex min-h-screen items-center justify-center bg-cryptiq-bg p-8">
  <div class="w-full max-w-md rounded-cryptiq-lg bg-cryptiq-surface p-8 shadow-cryptiq-panel">
    <p class="mb-4 text-body text-cryptiq-fg-muted">Cryptiq demo — contained shell (Phase 38)</p>
    <input
      type="text"
      name="demo-vault-value"
      id="demo-vault-value"
      autocomplete="off"
      class="w-full rounded-cryptiq border border-cryptiq-border-strong bg-cryptiq-surface-2 px-3 py-2 font-mono text-body text-cryptiq-fg"
      bind:value={demoValue}
    />
  </div>
</main>
