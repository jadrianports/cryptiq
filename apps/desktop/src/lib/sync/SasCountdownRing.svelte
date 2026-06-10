<!--
  SasCountdownRing.svelte — 60-second depleting arc around the SAS digits (D-07).

  Pure SVG + CSS keyframe ring. The visual animation is entirely CSS-driven
  (starts at mount, runs for exactly 60 s). The JS-side countdown only fires
  onExpired and exposes the seconds remaining for the parent to disable Confirm.

  Accessibility:
    - SVG: role="img" aria-label="60-second confirmation window"
    - SAS digits: role="status" aria-label="Short Authentication String: {sasDisplay}"

  Design tokens: cryptiq-* only (no literal hex/oklch).
  Reduced-motion: ring is static half-drained (stroke-dashoffset: 113).

  Source: 12-RESEARCH.md lines 297-414, 12-PATTERNS.md "SasCountdownRing.svelte",
          12-UI-SPEC.md Accessibility Contract rows.
-->
<script lang="ts">
  import { createSasCountdown } from './sasCountdown';

  type Props = {
    /** The 6-digit SAS string, e.g. "042 318". Displayed inside the ring. */
    sasDisplay: string;
    /** Called exactly once when the 60 s countdown reaches 0. */
    onExpired?: () => void;
  };

  let { sasDisplay, onExpired }: Props = $props();

  $effect(() => {
    // JS-side countdown: fires onExpired at 60 s. The visual ring is purely CSS-driven.
    const countdown = createSasCountdown({
      onExpired: () => {
        onExpired?.();
      },
    });

    return () => {
      countdown.destroy();
    };
  });
</script>

<style>
  /* Circumference = 2π × 36 ≈ 226.2 px. Ring depletes counter-clockwise.
     stroke-dasharray sets the total dash length = full circumference.
     stroke-dashoffset animates from 0 (full ring) to 226.2 (empty ring) over 60 s. */
  @media (prefers-reduced-motion: no-preference) {
    @keyframes ring-drain {
      from { stroke-dashoffset: 0; }
      to   { stroke-dashoffset: 226.2; }
    }

    .ring-progress {
      animation: ring-drain 60s linear forwards;
    }
  }

  /* Reduced motion: static half-filled ring. Signals "time is limited" without motion. */
  @media (prefers-reduced-motion: reduce) {
    .ring-progress {
      stroke-dashoffset: 113; /* half-drained: 226.2 / 2 ≈ 113 */
    }
  }
</style>

<!-- 80×80 canvas; ring r=36; circumference ≈ 226.2. -->
<div class="relative size-20">
  <svg
    class="absolute inset-0 size-20"
    viewBox="0 0 80 80"
    role="img"
    aria-label="60-second confirmation window"
  >
    <!-- Background track -->
    <circle
      cx="40"
      cy="40"
      r="36"
      stroke="currentColor"
      stroke-width="4"
      fill="none"
      class="text-cryptiq-border"
    />
    <!-- Draining progress arc. rotate(-90) starts at 12 o'clock. -->
    <circle
      cx="40"
      cy="40"
      r="36"
      stroke="currentColor"
      stroke-width="4"
      fill="none"
      stroke-dasharray="226.2"
      stroke-dashoffset="0"
      stroke-linecap="round"
      transform="rotate(-90 40 40)"
      class="ring-progress text-cryptiq-accent"
    />
  </svg>

  <!-- SAS digits: absolutely centered over the ring. -->
  <div class="absolute inset-0 flex items-center justify-center">
    <p
      role="status"
      aria-label="Short Authentication String: {sasDisplay}"
      class="select-none font-mono text-display font-semibold tracking-tight text-cryptiq-fg"
    >
      {sasDisplay}
    </p>
  </div>
</div>
