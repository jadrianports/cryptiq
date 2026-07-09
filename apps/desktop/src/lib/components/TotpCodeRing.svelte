<!--
  TotpCodeRing.svelte — live TOTP code + countdown ring (D-04/D-05/D-14, TOTP-04).

  Pure display + ticking clock. D-14: the component OWNS the ticking clock
  (setInterval), calling the pure packages/core generateTotpCode(totp, Date.now())
  each tick — Date.now() is fine here (apps/desktop is not packages/core). No
  vault writes, no entry CRUD knowledge — f(EntryTotp) -> ring + digits.

  Ring geometry (44px diameter, radius 20, stroke-width 3, viewBox "0 0 48 48"):
  track = border-strong, arc = accent while >5s remaining, attention (amber)
  while <=5s remaining (D-05). Numeric seconds-remaining centered inside the
  ring, color-matched to the arc's current state.

  Tap-to-copy (UI-SPEC clipboard-semantics decision, locked): the code uses the
  PLAIN copyField(value, 'other') path — it does NOT join SENSITIVE_COPY_FIELDS
  and does NOT arm the Rust sensitive-clipboard-clear guard. The rotating code
  is explicitly short-lived (rotates within <=30s by default), not a long-lived
  secret (D-04) — arming a multi-second clear timer adds churn with no benefit.

  Unmount cleanup: the interval is cleared in the $effect teardown — the
  OPPOSITE of clipboardGuard.svelte.ts's deliberately module-level
  survives-unmount timer. The countdown is purely cosmetic/derived and has no
  security purpose in continuing off-screen (29-RESEARCH.md Anti-Patterns).
-->
<script lang="ts">
  import { generateTotpCode } from '@cryptiq/core';
  import type { EntryTotp } from '@cryptiq/core';
  import { copyField } from '../util/copyField';

  const RING_RADIUS = 20;
  const RING_CIRCUMFERENCE = 2 * Math.PI * RING_RADIUS;
  const ATTENTION_THRESHOLD_SECONDS = 5;
  const COPY_CHECKMARK_MS = 1500;

  let { totp }: { totp: EntryTotp } = $props();

  let code = $state('');
  let secondsRemaining = $state(0);
  let copied = $state(false);
  let generationFailed = $state(false);

  // D-14: the ticking clock lives here (the app tier), calling the pure core
  // generator every tick. An immediate first tick avoids a 1s blank flash.
  // Fail closed: a malformed `totp` (e.g. an out-of-spec algorithm arriving via
  // sync or a hand-edited vault) makes otpauth throw — verified in 29-01's
  // characterization spike. Merge/CRUD only type-check algorithm/period, not
  // validity, so guard here rather than let an uncaught throw fire every second.
  $effect(() => {
    const tick = () => {
      try {
        const result = generateTotpCode(totp, Date.now());
        code = result.code;
        secondsRemaining = result.secondsRemaining;
        generationFailed = false;
      } catch {
        code = '';
        secondsRemaining = 0;
        generationFailed = true;
      }
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  });

  const isAttention = $derived(secondsRemaining <= ATTENTION_THRESHOLD_SECONDS);

  // Digit-grouped display: 6 digits -> "123 456", 8 digits -> "1234 5678"
  // (one mid-string space, per UI-SPEC).
  const displayCode = $derived.by(() => {
    if (code.length < 2) return code;
    const mid = Math.ceil(code.length / 2);
    return `${code.slice(0, mid)} ${code.slice(mid)}`;
  });

  const dashOffset = $derived.by(() => {
    if (totp.period <= 0) return 0;
    const fraction = Math.max(0, Math.min(1, secondsRemaining / totp.period));
    return RING_CIRCUMFERENCE * (1 - fraction);
  });

  let copyTimeoutId: ReturnType<typeof setTimeout> | undefined;

  async function handleCopyCode() {
    // Non-sensitive path (UI-SPEC binding decision) — plain writeText, no
    // Rust sensitive-clipboard-clear guard. Mirrors EntryDetail's non-password
    // `else` branch of handleCopy, never the sensitive 'password' branch.
    await copyField(code, 'other');
    copied = true;
    clearTimeout(copyTimeoutId);
    copyTimeoutId = setTimeout(() => {
      copied = false;
    }, COPY_CHECKMARK_MS);
  }
</script>

<div class="flex items-center gap-3">
  <!-- Countdown ring (44px diameter, radius 20, stroke-width 3, viewBox 0 0 48 48) -->
  <svg
    class="size-11 shrink-0 -rotate-90"
    viewBox="0 0 48 48"
    role="img"
    aria-label="{secondsRemaining} seconds remaining"
  >
    <circle cx="24" cy="24" r={RING_RADIUS} fill="none" stroke-width="3" class="stroke-cryptiq-border-strong" />
    <circle
      cx="24"
      cy="24"
      r={RING_RADIUS}
      fill="none"
      stroke-width="3"
      stroke-linecap="round"
      stroke-dasharray={RING_CIRCUMFERENCE}
      stroke-dashoffset={dashOffset}
      class={isAttention ? 'stroke-cryptiq-attention' : 'stroke-cryptiq-accent'}
    />
    <text
      x="24"
      y="24"
      transform="rotate(90 24 24)"
      text-anchor="middle"
      dominant-baseline="central"
      class="fill-current font-mono text-meta {isAttention ? 'text-cryptiq-attention' : 'text-cryptiq-accent'}"
    >
      {secondsRemaining}
    </text>
  </svg>

  <div class="min-w-0">
    {#if totp.issuer || totp.label}
      <span class="block truncate text-meta text-cryptiq-fg-subtle">
        {[totp.issuer, totp.label].filter(Boolean).join(' · ')}
      </span>
    {/if}
    {#if generationFailed}
      <span class="block text-body text-cryptiq-attention">
        Can't generate a code — this 2FA seed looks invalid.
      </span>
    {:else}
      <button
        type="button"
        onclick={handleCopyCode}
        title="Copy code"
        aria-label="Copy 2FA code"
        class="rounded-cryptiq px-1 -mx-1 text-left font-mono text-display font-semibold tracking-tight text-cryptiq-fg tabular-nums transition-colors hover:bg-cryptiq-hover
               {copied ? 'text-cryptiq-success' : ''}"
      >
        {displayCode}
      </button>
    {/if}
  </div>
</div>
