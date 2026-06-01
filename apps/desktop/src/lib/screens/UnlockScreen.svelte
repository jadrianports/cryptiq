<!--
  UnlockScreen.svelte — AUTH-07/08/09 vault unlock with master-password and
  recovery-key paths.

  Master-password path:
    - Correct password → go('main').
    - Wrong password → mapUnlockError generic string (AUTH-07 / P4-09).
      The failing path is NEVER revealed.

  Recovery-key path (AUTH-08):
    - "Unlock with recovery key instead" toggle reveals a recovery-key field.
    - Correct recovery key → in-flow new-master prompt (collect ×2, call
      resetMasterPasswordAfterRecovery, then go('main')).
    - Wrong recovery key → SAME generic string as wrong password (P4-09 path-agnostic).

  Operational failures → distinct, actionable copy (P4-09):
    - VaultCorruptError → "Vault file appears damaged. Restore from a backup."
    - UnknownVaultVersionError | MigrationFailedError → "Vault format is from a newer
      version of Cryptiq. Update the app."
    - KdfResourceError → "Not enough memory to unlock. Close other apps and try again."

  Cross-host lock warning (P3-10) surfaces non-blockingly below the form.

  Security (T-04-07 / T-04-08):
    - Never reveal which credential path failed.
    - No console.* of password or recovery key.
-->
<script lang="ts">
  import { vaultSession } from '../state/vault.svelte';
  import { go } from '../state/view.svelte';
  import { loadConfig } from '../config/config-adapter';
  import { mapUnlockError } from '../util/errors';
  import { TauriVaultStorageAdapter } from '../adapters/TauriVaultStorageAdapter';
  import StrengthMeter from '../components/StrengthMeter.svelte';

  // ── Auth-path toggle ─────────────────────────────────────────────────────────
  type AuthMode = 'master' | 'recovery' | 'new-master-after-recovery';
  let mode = $state<AuthMode>('master');

  // ── Form fields ──────────────────────────────────────────────────────────────
  let password = $state('');
  let recoveryKeyInput = $state('');
  let newPassword = $state('');
  let confirmNewPassword = $state('');

  // ── Status ───────────────────────────────────────────────────────────────────
  let error = $state<string | null>(null);
  let lockWarningHost = $state<string | null>(null);
  let submitting = $state(false);

  // ── Derived ──────────────────────────────────────────────────────────────────
  const newPasswordsMatch = $derived(
    newPassword.length > 0 && newPassword === confirmNewPassword,
  );

  // ── Master-password unlock ────────────────────────────────────────────────────
  async function handleMasterUnlock(): Promise<void> {
    if (submitting || password.length === 0) return;
    submitting = true;
    error = null;
    lockWarningHost = null;

    try {
      const config = await loadConfig();
      if (!config.vaultPath) {
        go('first-run');
        return;
      }
      const adapter = new TauriVaultStorageAdapter(config.vaultPath);
      const warning = await vaultSession.unlock(adapter, {
        masterPassword: new TextEncoder().encode(password),
      });
      if (warning) {
        lockWarningHost = warning.hostname;
      }
      password = '';
      go('main');
    } catch (e) {
      if (import.meta.env.DEV) {
        console.error('[unlock master] failed:', e);
      }
      error = mapUnlockError(e);
    } finally {
      submitting = false;
    }
  }

  // ── Recovery-key unlock ───────────────────────────────────────────────────────
  async function handleRecoveryUnlock(): Promise<void> {
    if (submitting || recoveryKeyInput.trim().length === 0) return;
    submitting = true;
    error = null;

    try {
      const config = await loadConfig();
      if (!config.vaultPath) {
        go('first-run');
        return;
      }
      const adapter = new TauriVaultStorageAdapter(config.vaultPath);
      await vaultSession.unlock(adapter, {
        recoveryKey: recoveryKeyInput.trim(),
      });
      recoveryKeyInput = '';
      // AUTH-08: recovery unlock → must set a new master password before main.
      mode = 'new-master-after-recovery';
    } catch (e) {
      // AUTH-07/P4-09: SAME generic message — never reveal which path failed.
      error = mapUnlockError(e);
    } finally {
      submitting = false;
    }
  }

  // ── Post-recovery new-master reset (AUTH-08) ──────────────────────────────────
  async function handleSetNewMaster(): Promise<void> {
    if (submitting || !newPasswordsMatch) return;
    submitting = true;
    error = null;

    try {
      const newPwBytes = new TextEncoder().encode(newPassword);
      await vaultSession.resetMasterPasswordAfterRecovery(newPwBytes);
      newPwBytes.fill(0);
      // Persist the new master wrap to disk.
      await vaultSession.save();
      newPassword = '';
      confirmNewPassword = '';
      go('main');
    } catch {
      error = 'Could not set new master password. Please try again.';
    } finally {
      submitting = false;
    }
  }

  function handleKeydown(e: KeyboardEvent): void {
    if (e.key === 'Enter') {
      if (mode === 'master') void handleMasterUnlock();
      else if (mode === 'recovery') void handleRecoveryUnlock();
      else if (mode === 'new-master-after-recovery' && newPasswordsMatch) void handleSetNewMaster();
    }
  }
</script>

<div class="grid h-full place-items-center bg-cryptiq-bg px-6 py-10">
  <div
    class="w-full max-w-md rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface p-8 shadow-cryptiq-panel"
    style="animation: unlock-fade-in 200ms ease-out both"
  >
    <!-- Header -->
    <div class="mb-7">
      <p class="text-meta font-semibold uppercase tracking-wide text-cryptiq-accent">Cryptiq</p>
      <h1 class="mt-1 text-display font-semibold text-cryptiq-fg">
        {#if mode === 'new-master-after-recovery'}
          Set a new master password.
        {:else if mode === 'recovery'}
          Unlock with recovery key.
        {:else}
          Unlock your vault.
        {/if}
      </h1>
      {#if mode === 'new-master-after-recovery'}
        <p class="mt-2 text-body text-cryptiq-fg-muted">
          Your vault is unlocked. Set a new master password to replace the one you forgot.
        </p>
      {/if}
    </div>

    <!-- Error message (generic for auth failures, distinct for operational) -->
    {#if error}
      <div
        class="mb-5 rounded-cryptiq border border-cryptiq-danger-border bg-cryptiq-danger-surface px-4 py-3 text-body text-cryptiq-danger"
        role="alert"
        aria-live="polite"
      >
        {error}
      </div>
    {/if}

    <!-- Cross-host lock warning (non-blocking) -->
    {#if lockWarningHost}
      <div class="mb-5 rounded-cryptiq border border-cryptiq-border bg-cryptiq-surface-2 px-4 py-3 text-body text-cryptiq-fg-muted" role="status">
        Vault was last used on a different machine ({lockWarningHost}). Make sure that session is closed before editing.
      </div>
    {/if}

    <!-- ── Master-password form ─────────────────────────────────────────────── -->
    {#if mode === 'master'}
      <form onsubmit={(e) => { e.preventDefault(); void handleMasterUnlock(); }}>
        <div class="space-y-4">
          <div>
            <label for="unlock-pw" class="mb-1 block text-meta font-medium text-cryptiq-fg-muted">
              Master password
            </label>
            <input
              id="unlock-pw"
              type="password"
              bind:value={password}
              autocomplete="current-password"
              placeholder="Enter your master password"
              disabled={submitting}
              onkeydown={handleKeydown}
              class="w-full rounded-cryptiq border border-cryptiq-border-strong bg-cryptiq-surface-2 px-3 py-2 font-mono text-body text-cryptiq-fg placeholder:text-cryptiq-fg-subtle focus:border-cryptiq-accent focus:outline-none focus:ring-1 focus:ring-cryptiq-ring disabled:opacity-60"
            />
          </div>

          <button
            type="submit"
            disabled={submitting || password.length === 0}
            class="w-full rounded-cryptiq bg-cryptiq-accent px-5 py-2.5 text-body font-semibold text-cryptiq-accent-fg transition-colors hover:bg-cryptiq-accent-hover disabled:cursor-not-allowed disabled:opacity-40"
          >
            {submitting ? 'Unlocking…' : 'Unlock'}
          </button>
        </div>
      </form>

      <!-- Recovery-key toggle (AUTH-08) -->
      <div class="mt-5 border-t border-cryptiq-border pt-5">
        <button
          type="button"
          onclick={() => { mode = 'recovery'; error = null; password = ''; }}
          class="text-body font-medium text-cryptiq-accent hover:underline"
        >
          Unlock with recovery key instead
        </button>
      </div>

    <!-- ── Recovery-key form ────────────────────────────────────────────────── -->
    {:else if mode === 'recovery'}
      <form onsubmit={(e) => { e.preventDefault(); void handleRecoveryUnlock(); }}>
        <div class="space-y-4">
          <div>
            <label for="recovery-key" class="mb-1 block text-meta font-medium text-cryptiq-fg-muted">
              Recovery key
            </label>
            <textarea
              id="recovery-key"
              bind:value={recoveryKeyInput}
              placeholder="Paste your recovery key here"
              rows={3}
              disabled={submitting}
              class="w-full rounded-cryptiq border border-cryptiq-border-strong bg-cryptiq-surface-2 px-3 py-2 font-mono text-body text-cryptiq-fg placeholder:text-cryptiq-fg-subtle focus:border-cryptiq-accent focus:outline-none focus:ring-1 focus:ring-cryptiq-ring disabled:opacity-60 resize-none"
            ></textarea>
          </div>

          <button
            type="submit"
            disabled={submitting || recoveryKeyInput.trim().length === 0}
            class="w-full rounded-cryptiq bg-cryptiq-accent px-5 py-2.5 text-body font-semibold text-cryptiq-accent-fg transition-colors hover:bg-cryptiq-accent-hover disabled:cursor-not-allowed disabled:opacity-40"
          >
            {submitting ? 'Verifying…' : 'Unlock with recovery key'}
          </button>
        </div>
      </form>

      <!-- Back to password -->
      <div class="mt-5 border-t border-cryptiq-border pt-5">
        <button
          type="button"
          onclick={() => { mode = 'master'; error = null; recoveryKeyInput = ''; }}
          class="text-body font-medium text-cryptiq-fg-muted hover:text-cryptiq-fg hover:underline"
        >
          Back to master password
        </button>
      </div>

    <!-- ── New-master form (AUTH-08, post-recovery) ─────────────────────────── -->
    {:else if mode === 'new-master-after-recovery'}
      <form onsubmit={(e) => { e.preventDefault(); void handleSetNewMaster(); }}>
        <div class="space-y-4">
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
              class="w-full rounded-cryptiq border border-cryptiq-border-strong bg-cryptiq-surface-2 px-3 py-2 font-mono text-body text-cryptiq-fg placeholder:text-cryptiq-fg-subtle focus:border-cryptiq-accent focus:outline-none focus:ring-1 focus:ring-cryptiq-ring disabled:opacity-60"
            />
            <StrengthMeter password={newPassword} />
          </div>
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
              class="w-full rounded-cryptiq border border-cryptiq-border-strong bg-cryptiq-surface-2 px-3 py-2 font-mono text-body text-cryptiq-fg placeholder:text-cryptiq-fg-subtle focus:border-cryptiq-accent focus:outline-none focus:ring-1 focus:ring-cryptiq-ring disabled:opacity-60"
            />
            {#if confirmNewPassword.length > 0 && !newPasswordsMatch}
              <p class="mt-1 text-meta text-cryptiq-danger" role="alert">Passwords do not match.</p>
            {/if}
          </div>

          <button
            type="submit"
            disabled={submitting || !newPasswordsMatch}
            class="w-full rounded-cryptiq bg-cryptiq-accent px-5 py-2.5 text-body font-semibold text-cryptiq-accent-fg transition-colors hover:bg-cryptiq-accent-hover disabled:cursor-not-allowed disabled:opacity-40"
          >
            {submitting ? 'Saving…' : 'Set new password and unlock'}
          </button>
        </div>
      </form>
    {/if}
  </div>
</div>

<style>
  @keyframes unlock-fade-in {
    from { opacity: 0; transform: translateY(8px); }
    to   { opacity: 1; transform: translateY(0); }
  }
</style>
