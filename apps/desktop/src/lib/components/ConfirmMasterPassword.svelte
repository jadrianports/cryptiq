<!--
  ConfirmMasterPassword.svelte — Reusable always-re-derive master-password gate (P6-09 / AUTH-11).

  Factored out of ChangeMasterView Step 1 as a standalone reusable gate.
  Any sensitive action that requires proof of the master password (e.g. export) can drop
  this component in and pass its own `onConfirmed` callback.

  AUTH-11 always-re-derive contract:
    - Password encoded via TextEncoder at call time; bytes zeroed in `finally`.
    - ALWAYS re-derives Argon2id (~1s) via vaultSession.verifyMasterPassword().
    - Wrong password → generic error copy (no path/branch detail — P5-02).
    - Never logs the password (T-06-19).
    - No cached plaintext; no fast path.

  Security (T-06-15 mitigate):
    The ~1s Argon2id re-derive is the gate that stops a walk-up attacker at an unlocked
    machine from exporting the whole vault undetected.

  Token rules: cryptiq-* tokens only; no literal hex/oklch.
-->
<script lang="ts">
  import { vaultSession } from '../state/vault.svelte';

  type Props = {
    /** Called when the entered password is verified correct. The caller's async work
     *  (e.g. flush + save dialog + invoke export) runs inside this callback. */
    onConfirmed: () => Promise<void>;
    /** Called when the user cancels without confirming. */
    onCancelled: () => void;
  };

  let { onConfirmed, onCancelled }: Props = $props();

  // ── Form fields (plain $state — transient UI values, NOT vault keys) ────────
  let password = $state('');

  // ── Status ──────────────────────────────────────────────────────────────────
  let error = $state<string | null>(null);
  let submitting = $state(false);

  // ── Submit handler (the AUTH-11 always-re-derive gate) ───────────────────────
  async function handleConfirm(): Promise<void> {
    if (submitting || password.length === 0) return;
    submitting = true;
    error = null;

    // Encode at call time — do NOT retain plaintext beyond this handler (AUTH-11).
    const passwordBytes = new TextEncoder().encode(password);
    try {
      const correct = await vaultSession.verifyMasterPassword(passwordBytes);
      if (correct) {
        // Password verified — invoke the caller's confirmed callback.
        await onConfirmed();
      } else {
        // Wrong password → generic error, no path/branch detail (P5-02 / T-06-19).
        error = 'That password is incorrect. Please try again.';
      }
    } catch {
      // Unexpected failure (e.g. session locked mid-verify) — generic message.
      error = 'That password is incorrect. Please try again.';
    } finally {
      // Zero encoded bytes immediately after use (best-effort defense — AUTH-11).
      passwordBytes.fill(0);
      submitting = false;
    }
  }

  function handleKeydown(e: KeyboardEvent): void {
    if (e.key === 'Enter') {
      void handleConfirm();
    }
  }
</script>

<div class="space-y-4">
  <!-- Heading -->
  <div>
    <p class="text-body font-semibold text-cryptiq-fg">Confirm your master password</p>
    <p class="mt-0.5 text-meta text-cryptiq-fg-subtle">
      Enter your master password to continue. This takes about a second to verify.
    </p>
  </div>

  <!-- Password field -->
  <div class="space-y-1.5">
    <label for="confirm-master-pw" class="text-meta font-medium text-cryptiq-fg">
      Master password
    </label>
    <input
      id="confirm-master-pw"
      type="password"
      autocomplete="current-password"
      bind:value={password}
      disabled={submitting}
      onkeydown={handleKeydown}
      placeholder="Enter your master password"
      class="w-full rounded-cryptiq border border-cryptiq-border-strong bg-cryptiq-surface-2 px-3 py-2 text-body text-cryptiq-fg placeholder:text-cryptiq-fg-subtle focus:border-cryptiq-accent focus:outline-none focus:ring-1 focus:ring-cryptiq-ring disabled:opacity-60"
    />
  </div>

  <!-- Error message -->
  {#if error !== null}
    <p class="text-meta text-cryptiq-danger" role="alert">{error}</p>
  {/if}

  <!-- Actions -->
  <div class="flex items-center gap-3">
    <button
      type="button"
      onclick={() => void handleConfirm()}
      disabled={submitting || password.length === 0}
      class="rounded-cryptiq bg-cryptiq-accent px-4 py-2 text-body font-semibold text-cryptiq-accent-fg transition-colors hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40"
    >
      {submitting ? 'Verifying…' : 'Confirm'}
    </button>
    <button
      type="button"
      onclick={onCancelled}
      disabled={submitting}
      class="text-body text-cryptiq-fg-muted transition-colors hover:text-cryptiq-fg disabled:opacity-60"
    >
      Cancel
    </button>
  </div>
</div>
