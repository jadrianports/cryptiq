<!--
  ChangeMasterView.svelte — AUTH-10/AUTH-11 two-step master-password change flow.

  Step 1 — Verify current password (the always-re-derive gate, P5-02 / AUTH-11):
    Collects the current master password. On "Continue" the UI shows "Verifying…"
    and the step advances — no derive happens yet (see UX split note below).

  Step 2 — Choose new password × 2 with StrengthMeter:
    Collects new password and confirmation. On "Change master password" the ~2s
    Argon2id derive runs (changeMasterPassword takes both args, so the single
    re-derive-heavy call happens here at the final submit — option (a) from the plan).
    This is the always-re-derive gate: no cached plaintext, no fast path.

  UX split decision (AUTH-11 / P5-02 / PLAN Task 1 option a):
    We collect currentPassword in Step 1 and defer the SINGLE changeMasterPassword()
    call to Step 2 submit. The Step-1 "Verifying…" label fires and briefly shows
    a submitting state for UX responsiveness before advancing the step, but no
    actual Argon2id derivation occurs in Step 1. The full re-derive + re-wrap
    (~2s) happens in Step 2 via one changeMasterPassword(current, new) call.
    This honors "the current-password entry IS the gate" — the re-derive gate
    occurs when the change is actually committed, not prematurely.

  On success:
    - Calls setChangeMasterSuccess(true) THEN go('settings') — user stays unlocked.
    - The success panel renders in SettingsShell (reads changeMasterSuccess).
    - NEVER calls go('unlock').

  Security (T-5-REDERIVE / AUTH-11):
    - Plaintext passwords encoded at call time with TextEncoder; never retained beyond handler.
    - Wrong current password → generic error "That password is incorrect. Please try again."
    - Weak new password is warned (StrengthMeter) but NOT blocked (AUTH-02 parity).
    - New must differ from current (plain string comparison before encoding).

  Token rules (P4-03): cryptiq-* tokens only; no literal hex/oklch.
-->
<script lang="ts">
  import { go, setChangeMasterSuccess } from '../state/view.svelte';
  import { vaultSession } from '../state/vault.svelte';
  import { WrongPasswordError } from '@cryptiq/core';
  import StrengthMeter from '../components/StrengthMeter.svelte';

  // ── Step state ───────────────────────────────────────────────────────────────
  type Step = 'verify-current' | 'enter-new';
  let step = $state<Step>('verify-current');

  // ── Form fields (plain $state — transient UI values, NOT vault keys) ─────────
  let currentPassword = $state('');
  let newPassword = $state('');
  let confirmNewPassword = $state('');

  // ── Status ───────────────────────────────────────────────────────────────────
  let error = $state<string | null>(null);
  let submitting = $state(false);

  // ── Derived guards ───────────────────────────────────────────────────────────
  const newPasswordsMatch = $derived(
    newPassword.length > 0 && newPassword === confirmNewPassword,
  );
  const newDiffersFromCurrent = $derived(
    newPassword.length === 0 || newPassword !== currentPassword,
  );

  // ── Step 1: advance to step 2 ────────────────────────────────────────────────
  // No Argon2id derive here (option a) — shows "Verifying…" briefly for UX
  // responsiveness, then advances. The actual derive happens in Step 2.
  async function handleVerifyCurrent(): Promise<void> {
    if (submitting || currentPassword.length === 0) return;
    submitting = true;
    error = null;
    try {
      // Brief async yield so "Verifying…" label renders before advancing.
      // No actual crypto yet — the single derive happens at Step 2 submit.
      await Promise.resolve();
      step = 'enter-new';
    } catch {
      error = 'That password is incorrect. Please try again.';
    } finally {
      submitting = false;
    }
  }

  // ── Step 2: execute the master-password change (the always-re-derive gate) ──
  async function handleChangeMaster(): Promise<void> {
    if (submitting || !newPasswordsMatch || !newDiffersFromCurrent) return;
    submitting = true;
    error = null;
    try {
      // Encode at call time — do NOT retain plaintext beyond this handler.
      // changeMasterPassword re-derives Argon2id (~2s) to verify currentPassword
      // AND to wrap the new key. This is the AUTH-11 always-re-derive gate.
      const currentBytes = new TextEncoder().encode(currentPassword);
      const newBytes = new TextEncoder().encode(newPassword);
      try {
        await vaultSession.changeMasterPassword(currentBytes, newBytes);
      } finally {
        // Zero encoded bytes immediately after use (best-effort defense).
        currentBytes.fill(0);
        newBytes.fill(0);
      }
      // Persist the new master wrap to disk.
      await vaultSession.save();

      // Success: set the pinned success flag, then navigate back to Settings.
      // STAYS UNLOCKED — NEVER go('unlock').
      setChangeMasterSuccess(true);
      go('settings');
    } catch (e) {
      if (e instanceof WrongPasswordError) {
        // Wrong current password → generic error, no path detail (P5-02).
        // Return to Step 1 so the user re-enters the current password.
        step = 'verify-current';
        error = 'That password is incorrect. Please try again.';
      } else {
        // Unexpected failure — user knows their master password was NOT changed.
        error = 'Something went wrong. Your master password was not changed. Please try again.';
      }
    } finally {
      submitting = false;
    }
  }

  function handleStep1Keydown(e: KeyboardEvent): void {
    if (e.key === 'Enter') void handleVerifyCurrent();
  }

  function handleStep2Keydown(e: KeyboardEvent): void {
    if (e.key === 'Enter' && newPasswordsMatch && newDiffersFromCurrent) {
      void handleChangeMaster();
    }
  }

  function goBackToSettings(): void {
    // Cancel: return to Settings WITHOUT setting the success flag.
    go('settings');
  }

  function goBackToStep1(): void {
    // Back: return to Step 1, retaining the current-password value so the user
    // doesn't have to re-type it if they only went back to fix the new password.
    step = 'verify-current';
    error = null;
    newPassword = '';
    confirmNewPassword = '';
  }
</script>

<div class="grid h-full place-items-center bg-cryptiq-bg px-6 py-10">
  <div
    class="w-full max-w-lg rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface p-8 shadow-cryptiq-panel"
  >

    <!-- ── Step 1: Verify current password ─────────────────────────────────── -->
    {#if step === 'verify-current'}

      <!-- Header -->
      <div class="mb-7">
        <h1 class="text-display font-semibold text-cryptiq-fg">
          Change your master password.
        </h1>
        <p class="mt-2 text-body text-cryptiq-fg-muted">
          Enter your current master password to continue. This re-verifies your identity before making any changes.
        </p>
      </div>

      <!-- Error panel -->
      {#if error}
        <div
          class="mb-5 rounded-cryptiq border border-cryptiq-danger-border bg-cryptiq-danger-surface px-4 py-3 text-body text-cryptiq-danger"
          role="alert"
          aria-live="polite"
        >
          {error}
        </div>
      {/if}

      <!-- Current password form -->
      <form onsubmit={(e) => { e.preventDefault(); void handleVerifyCurrent(); }}>
        <div class="space-y-4">
          <div>
            <label for="current-pw" class="mb-1 block text-meta font-medium text-cryptiq-fg-muted">
              Current master password
            </label>
            <input
              id="current-pw"
              type="password"
              bind:value={currentPassword}
              autocomplete="current-password"
              placeholder="Enter your current master password"
              disabled={submitting}
              onkeydown={handleStep1Keydown}
              class="w-full rounded-cryptiq border border-cryptiq-border-strong bg-cryptiq-surface-2 px-3 py-2 font-mono text-body text-cryptiq-fg placeholder:text-cryptiq-fg-subtle focus:border-cryptiq-accent focus:outline-none focus:ring-1 focus:ring-cryptiq-ring disabled:opacity-60"
            />
          </div>

          <button
            type="submit"
            disabled={submitting || currentPassword.length === 0}
            class="w-full rounded-cryptiq bg-cryptiq-accent px-5 py-2.5 text-body font-semibold text-cryptiq-accent-fg transition-colors hover:bg-cryptiq-accent-hover disabled:cursor-not-allowed disabled:opacity-40"
          >
            {submitting ? 'Verifying…' : 'Continue'}
          </button>
        </div>
      </form>

      <!-- Cancel link -->
      <div class="mt-5 border-t border-cryptiq-border pt-5">
        <button
          type="button"
          onclick={goBackToSettings}
          class="text-body font-medium text-cryptiq-fg-muted hover:text-cryptiq-fg hover:underline"
        >
          Cancel
        </button>
      </div>

    <!-- ── Step 2: Choose new password ─────────────────────────────────────── -->
    {:else if step === 'enter-new'}

      <!-- Header -->
      <div class="mb-7">
        <h1 class="text-display font-semibold text-cryptiq-fg">
          Choose a new master password.
        </h1>
        <p class="mt-2 text-body text-cryptiq-fg-muted">
          Pick something long and memorable. A weak password is allowed — but we'll warn you.
        </p>
      </div>

      <!-- Error panel -->
      {#if error}
        <div
          class="mb-5 rounded-cryptiq border border-cryptiq-danger-border bg-cryptiq-danger-surface px-4 py-3 text-body text-cryptiq-danger"
          role="alert"
          aria-live="polite"
        >
          {error}
        </div>
      {/if}

      <!-- New password form -->
      <form onsubmit={(e) => { e.preventDefault(); void handleChangeMaster(); }}>
        <div class="space-y-4">
          <!-- New password field + StrengthMeter -->
          <div>
            <label for="new-pw" class="mb-1 block text-meta font-medium text-cryptiq-fg-muted">
              New master password
            </label>
            <input
              id="new-pw"
              type="password"
              bind:value={newPassword}
              autocomplete="new-password"
              placeholder="Choose a new master password"
              disabled={submitting}
              onkeydown={handleStep2Keydown}
              class="w-full rounded-cryptiq border border-cryptiq-border-strong bg-cryptiq-surface-2 px-3 py-2 font-mono text-body text-cryptiq-fg placeholder:text-cryptiq-fg-subtle focus:border-cryptiq-accent focus:outline-none focus:ring-1 focus:ring-cryptiq-ring disabled:opacity-60"
            />
            <StrengthMeter password={newPassword} />
            <!-- Must-differ guard (shown when new equals current) -->
            {#if newPassword.length > 0 && !newDiffersFromCurrent}
              <p class="mt-1 text-meta text-cryptiq-danger" role="alert">
                New password must be different from your current one.
              </p>
            {/if}
          </div>

          <!-- Confirm new password field -->
          <div>
            <label for="confirm-new-pw" class="mb-1 block text-meta font-medium text-cryptiq-fg-muted">
              Confirm new password
            </label>
            <input
              id="confirm-new-pw"
              type="password"
              bind:value={confirmNewPassword}
              autocomplete="new-password"
              placeholder="Re-enter your new master password"
              disabled={submitting}
              onkeydown={handleStep2Keydown}
              class="w-full rounded-cryptiq border border-cryptiq-border-strong bg-cryptiq-surface-2 px-3 py-2 font-mono text-body text-cryptiq-fg placeholder:text-cryptiq-fg-subtle focus:border-cryptiq-accent focus:outline-none focus:ring-1 focus:ring-cryptiq-ring disabled:opacity-60"
            />
            <!-- Passwords-don't-match guard -->
            {#if confirmNewPassword.length > 0 && !newPasswordsMatch}
              <p class="mt-1 text-meta text-cryptiq-danger" role="alert">
                Passwords do not match.
              </p>
            {/if}
          </div>

          <!-- Submit button (weak-warned-not-blocked: only disabled on mismatch or must-differ) -->
          <button
            type="submit"
            disabled={submitting || !newPasswordsMatch || !newDiffersFromCurrent}
            class="w-full rounded-cryptiq bg-cryptiq-accent px-5 py-2.5 text-body font-semibold text-cryptiq-accent-fg transition-colors hover:bg-cryptiq-accent-hover disabled:cursor-not-allowed disabled:opacity-40"
          >
            {submitting ? 'Saving…' : 'Change master password'}
          </button>
        </div>
      </form>

      <!-- Back link -->
      <div class="mt-5 border-t border-cryptiq-border pt-5">
        <button
          type="button"
          onclick={goBackToStep1}
          class="text-body font-medium text-cryptiq-fg-muted hover:text-cryptiq-fg hover:underline"
        >
          Back
        </button>
      </div>

    {/if}
  </div>
</div>
