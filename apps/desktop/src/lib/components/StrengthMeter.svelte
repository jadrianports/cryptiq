<!--
  StrengthMeter.svelte — master-password strength indicator (AUTH-02).

  Drives a segmented bar from a zxcvbn-ts score (0–4). Displays a warning message
  for weak passwords, but NEVER disables the Continue button — weak-warned-not-blocked
  is the locked product decision (AUTH-02).

  Score → color mapping (token-only — no literal hex):
    0–1  danger   (very weak / too short)
    2    attention (weak)
    3    success  (fair — no accent reserved for score < 4)
    4    accent   (excellent — the ONLY use of accent on the meter per design rules)

  zxcvbn-ts is configured at the module level (lazy singleton) so the language packs
  are registered exactly once regardless of how many StrengthMeter instances render.
-->
<script lang="ts" module>
  // zxcvbn-ts configuration is now shared via zxcvbnSetup.ts (Phase 17 Plan 02 /
  // HEALTH-02 extraction) — `ensureZxcvbnConfigured()` is idempotent, so calling
  // it here still configures the language packs exactly once across the module
  // boundary. `zxcvbn` itself is still imported directly here (not via
  // `scorePassword`) because this component needs the full result object
  // (score + feedback text), not just the score number.
  import { zxcvbn } from '@zxcvbn-ts/core';
  import { ensureZxcvbnConfigured } from '../zxcvbnSetup';
</script>

<script lang="ts">
  type Props = {
    /** The plaintext password to evaluate. Empty string → no score shown. */
    password: string;
  };
  let { password }: Props = $props();

  ensureZxcvbnConfigured();

  const result = $derived(password.length > 0 ? zxcvbn(password) : null);
  const score = $derived(result?.score ?? 0);

  // Segment fill classes (4 segments; segment i fills when score >= i+1).
  // Score 4 only earns accent; lower scores use semantic tokens.
  function segmentClass(i: number): string {
    if (score < i + 1) return 'bg-cryptiq-border';
    if (score === 4) return 'bg-cryptiq-accent';
    if (score === 3) return 'bg-cryptiq-success';
    if (score === 2) return 'bg-cryptiq-attention';
    return 'bg-cryptiq-danger';
  }

  // Warning text shown below the bar when the password is weak (AUTH-02 warn-not-block).
  const warningText = $derived((): string | null => {
    if (!result || password.length === 0) return null;
    if (score >= 3) return null;
    const feedback = result.feedback?.warning;
    if (feedback) return feedback;
    if (score === 0) return 'Password is too weak. Try a longer phrase.';
    if (score === 1) return 'Password is weak. Consider adding more variety.';
    return 'Password could be stronger.';
  });

  const labelText = $derived((): string => {
    if (!result || password.length === 0) return '';
    const labels = ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong'];
    return labels[score] ?? '';
  });
</script>

<div class="mt-1.5 space-y-1.5">
  <!-- 4-segment strength bar -->
  <div class="flex gap-1" aria-hidden="true">
    {#each [0, 1, 2, 3] as i (i)}
      <div
        class="h-1 flex-1 rounded-full transition-colors duration-200 {segmentClass(i)}"
      ></div>
    {/each}
  </div>

  <!-- Label row -->
  {#if password.length > 0}
    <div class="flex items-center justify-between">
      <span
        class="text-meta font-medium transition-colors duration-150
          {score === 4 ? 'text-cryptiq-accent' :
           score === 3 ? 'text-cryptiq-success' :
           score === 2 ? 'text-cryptiq-attention' :
           'text-cryptiq-danger'}"
      >
        {labelText()}
      </span>
    </div>
  {/if}

  <!-- Warn text (AUTH-02: warn but never block) -->
  {#if warningText()}
    <p class="text-meta text-cryptiq-attention leading-snug" role="alert" aria-live="polite">
      {warningText()}
    </p>
  {/if}
</div>
