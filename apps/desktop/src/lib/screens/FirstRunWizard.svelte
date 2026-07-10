<!--
  FirstRunWizard.svelte — P4-07 stepped first-run setup wizard.

  Step sequence (AUTH-01/02/03/04, UI-01):
    1  explainer       — focused brand intro + what to expect
    2  warning         — unmissable unrecoverable-password danger panel (P4-08)
                         tone="danger" + required-ack gates Continue (AUTH-03)
    3  vault-location  — native save dialog → $APPCONFIG/cryptiq/vaults/vault.cryptiq
                         (AUTH-01)
    4  master-password — password ×2 + live zxcvbn StrengthMeter; mismatch blocks
                         Continue; weak WARNS but never blocks (AUTH-02)
    5  recovery-opt-in — user chooses whether to generate a recovery key (AUTH-04)
    6  recovery-key    — shown once + print + required "I have saved" gate (AUTH-04/05/06)
                         (only rendered when withRecoveryKey === true)
    7  creating        — async vault creation + go('main')

  Security (T-04-08):
    - Master password held in a plain string $state — never logged, wiped on completion.
    - Recovery key held in $state only until step changes to main (it's SHOWN there).
    - No console.* of either secret anywhere in this file.
-->
<script lang="ts">
  import { onMount } from 'svelte';
  import FirstRunStep from '../components/FirstRunStep.svelte';
  import StrengthMeter from '../components/StrengthMeter.svelte';
  import RecoveryKeyCard from '../components/RecoveryKeyCard.svelte';
  import HibpConsentDialog from '../hibp/HibpConsentDialog.svelte';
  import { vaultSession } from '../state/vault.svelte';
  import { go } from '../state/view.svelte';
  import {
    saveConfig,
    defaultVaultPath,
    ensureVaultDir,
  } from '../config/config-adapter';
  import { TauriVaultStorageAdapter } from '../adapters/TauriVaultStorageAdapter';
  import { lookupHibpRange } from '@cryptiq/core';
  import { hibpInvoke } from '../adapters/hibpInvoke';

  // ── Step machine ────────────────────────────────────────────────────────────
  // Not-so-clever trick: numeric steps (not string) so progress bar math is trivial.
  // 6 total steps when recovery-key is included; 5 when skipped.
  type WizardStep = 'explainer' | 'warning' | 'location' | 'password' | 'recovery-opt-in' | 'recovery-key' | 'creating';

  let step = $state<WizardStep>('explainer');

  // Step numbering (1-indexed) and total used by FirstRunStep progress bar.
  const STEPS_WITH_RECOVERY = 6;
  const STEPS_WITHOUT_RECOVERY = 5;

  function stepNumber(s: WizardStep): number {
    const map: Record<WizardStep, number> = {
      explainer: 1,
      warning: 2,
      location: 3,
      password: 4,
      'recovery-opt-in': 5,
      'recovery-key': 6,
      creating: 6,
    };
    return map[s] ?? 1;
  }

  // ── Form state (non-secret visual state only — passwords are NOT logged) ────
  let vaultPath = $state('');
  let masterPassword = $state('');
  let confirmPassword = $state('');
  let withRecoveryKey = $state(true);
  let recoveryKey = $state<string | null>(null);

  // ── Master-password breach check (HIBP-06) ───────────────────────────────────
  // In-memory-only consent (no config.json exists yet — D-13 defers persistence
  // to the handleCreate saveConfig literal below). Click-only, advisory,
  // fail-closed to 'unknown' — NEVER wired to masterPassword via an
  // $effect/$derived (D-15/Pitfall 6). Independent of hibpEntryScanEnabled (D-16).
  type BreachCheckResult = 'idle' | 'checking' | 'breached' | 'safe' | 'unknown';
  let masterCheckConsent = $state(false);
  let breachCheckResult = $state<BreachCheckResult>('idle');
  let showMasterCheckDialog = $state(false);

  // v1 stores the vault at a FIXED app-managed path (UAT T4 decision — fixed location).
  // Resolve it once on mount so the location step + create() use it; no freeform picker.
  onMount(async () => {
    vaultPath = await defaultVaultPath();
  });
  let error = $state<string | null>(null);
  let creatingVault = $state(false);

  // ── Derived gate conditions ──────────────────────────────────────────────────
  const passwordsMatch = $derived(
    masterPassword.length > 0 && masterPassword === confirmPassword,
  );
  const passwordStepCanContinue = $derived(passwordsMatch);
  const totalSteps = $derived(withRecoveryKey ? STEPS_WITH_RECOVERY : STEPS_WITHOUT_RECOVERY);

  // ── Master-password breach check handlers (click-only — never $effect/$derived) ──
  // The ONLY trigger for a lookup — a type="button" onclick. Never fires on keystroke.
  async function handleBreachCheckClick(): Promise<void> {
    if (breachCheckResult === 'checking') return;
    if (!masterCheckConsent) {
      // First use: gate behind the master-check disclosure (D-16) — do not check yet.
      showMasterCheckDialog = true;
      return;
    }
    await runBreachCheck();
  }

  // In-memory consent capture only — there is no config.json yet at this point in
  // the wizard, so persistence is deferred to handleCreate's single saveConfig
  // literal (D-13). Do NOT saveConfig here.
  async function handleMasterCheckConfirm(): Promise<void> {
    masterCheckConsent = true;
    showMasterCheckDialog = false;
    await runBreachCheck();
  }

  function handleMasterCheckCancel(): void {
    // Consent stays OFF, nothing captured; the button remains visible for a later retry.
    showMasterCheckDialog = false;
  }

  async function runBreachCheck(): Promise<void> {
    breachCheckResult = 'checking';
    try {
      const breached = await lookupHibpRange(masterPassword, hibpInvoke);
      breachCheckResult = breached ? 'breached' : 'safe';
    } catch {
      // ANY failure (HibpLookupError or otherwise) reads as 'unknown' — NEVER 'safe'.
      breachCheckResult = 'unknown';
    }
  }

  // WR-01: clear a stale result banner the moment the checked field is edited —
  // purely a local state reset, NOT a lookup trigger (does not reintroduce the
  // banned per-keystroke egress pattern / D-15 / Pitfall 6).
  function handleMasterPasswordInput(): void {
    if (breachCheckResult !== 'idle' && breachCheckResult !== 'checking') {
      breachCheckResult = 'idle';
    }
  }

  // ── Navigation helpers ───────────────────────────────────────────────────────
  function nextStep(): void {
    if (step === 'explainer') { step = 'warning'; return; }
    if (step === 'warning')   { step = 'location'; return; }
    if (step === 'location')  { step = 'password'; return; }
    if (step === 'password')  {
      step = 'recovery-opt-in';
      return;
    }
    if (step === 'recovery-opt-in') {
      // handleCreate() itself branches on withRecoveryKey internally (recovery key
      // is shown after vault creation only when withRecoveryKey is true).
      void handleCreate();
      return;
    }
    if (step === 'recovery-key') {
      // User has acked saving the key → land in main.
      // Wipe in-memory recovery key string (best-effort — JS GC may retain copies).
      recoveryKey = null;
      masterPassword = '';
      confirmPassword = '';
      go('main');
    }
  }

  function prevStep(): void {
    if (step === 'warning')         { step = 'explainer'; return; }
    if (step === 'location')        { step = 'warning'; return; }
    if (step === 'password')        { step = 'location'; return; }
    if (step === 'recovery-opt-in') { step = 'password'; return; }
    if (step === 'recovery-key')    { step = 'recovery-opt-in'; return; }
  }

  // ── Vault location step ──────────────────────────────────────────────────────
  // ── Vault creation ───────────────────────────────────────────────────────────
  async function handleCreate(): Promise<void> {
    if (creatingVault) return;
    creatingVault = true;
    error = null;
    step = 'creating';

    try {
      // Ensure $APPCONFIG/cryptiq/vaults exists — vault_write_atomic requires the parent dir.
      await ensureVaultDir();
      const adapter = new TauriVaultStorageAdapter(vaultPath);
      // Encode password to bytes; never log the password (T-04-08).
      const passwordBytes = new TextEncoder().encode(masterPassword);
      const result = await vaultSession.create(adapter, passwordBytes, withRecoveryKey);
      // Wipe password bytes from memory (best-effort).
      passwordBytes.fill(0);

      // Persist the chosen vault path to config so subsequent launches go straight to unlock.
      // D-13: the in-memory masterCheckConsent captured above widens this SAME literal —
      // never a second saveConfig call, never a loadConfig-spread (no prior config exists yet).
      await saveConfig({ vaultPath, schemaVersion: 1, hibpMasterCheckEnabled: masterCheckConsent });

      if (withRecoveryKey && result.recoveryKey !== undefined) {
        recoveryKey = result.recoveryKey;
        step = 'recovery-key';
      } else {
        // No recovery key → land in main immediately.
        masterPassword = '';
        confirmPassword = '';
        go('main');
      }
    } catch (e) {
      // DEV-ONLY diagnostic (stripped from production by Vite — respects T-04-08).
      // Surfaces the real create() failure during local UAT so we can diagnose it.
      if (import.meta.env.DEV) {
        console.error('[first-run create] vault creation failed:', e);
      }
      // Never reveal internals in production. Keep error generic (T-04-08).
      error = 'Could not create vault. Please check the save location and try again.';
      step = 'recovery-opt-in';
      creatingVault = false;
    }
  }
</script>

<!-- ── Step: explainer ────────────────────────────────────────────────────── -->
{#if step === 'explainer'}
  <FirstRunStep
    step={stepNumber('explainer')}
    total={totalSteps}
    eyebrow="Welcome"
    title="Your vault, your keys."
    continueLabel="Get started"
    onContinue={nextStep}
  >
    <p>
      Cryptiq stores your passwords in a single encrypted file on <em>your</em> machine.
      No account, no server, no subscription — and no way for anyone to reset your master password.
    </p>
    <p class="mt-3">
      You'll set a master password, choose where to save your vault, and optionally create a
      recovery key. The next screen explains what "no reset" really means.
    </p>
  </FirstRunStep>

<!-- ── Step: warning (P4-08) ─────────────────────────────────────────────── -->
{:else if step === 'warning'}
  <FirstRunStep
    step={stepNumber('warning')}
    total={totalSteps}
    eyebrow="Important"
    title="There is no password reset."
    tone="danger"
    ackLabel="I understand — if I forget my master password and have no recovery key, my vault is gone forever."
    onBack={prevStep}
    onContinue={nextStep}
  >
    <p class="font-semibold">
      If you forget your master password and have no recovery key, your vault is gone forever.
      There is no reset — by design.
    </p>
    <p class="mt-3">
      This is the security guarantee that makes Cryptiq trustworthy: nobody can break in, and
      nobody can let you back in either. A recovery key (shown in a later step) is your only
      fallback if you forget your master password.
    </p>
  </FirstRunStep>

<!-- ── Step: vault location (AUTH-01) ────────────────────────────────────── -->
{:else if step === 'location'}
  <FirstRunStep
    step={stepNumber('location')}
    total={totalSteps}
    eyebrow="Vault location"
    title="Your vault is stored securely."
    canContinue={vaultPath.length > 0}
    onBack={prevStep}
    onContinue={nextStep}
  >
    <p>
      Your vault is a single encrypted file, kept in Cryptiq's private app folder on
      <em>this</em> computer. You can back it up or export it later from Settings.
    </p>
    <div class="mt-4 space-y-2">
      {#if vaultPath}
        <div class="flex items-center gap-2 rounded-cryptiq border border-cryptiq-border bg-cryptiq-surface-2 px-3 py-2">
          <svg class="size-4 shrink-0 text-cryptiq-success" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M20 6 9 17l-5-5"/>
          </svg>
          <span class="truncate font-mono text-meta text-cryptiq-fg-muted">{vaultPath}</span>
        </div>
      {/if}
    </div>
  </FirstRunStep>

<!-- ── Step: master password (AUTH-02) ───────────────────────────────────── -->
{:else if step === 'password'}
  <FirstRunStep
    step={stepNumber('password')}
    total={totalSteps}
    eyebrow="Master password"
    title="Set your master password."
    canContinue={passwordStepCanContinue}
    onBack={prevStep}
    onContinue={nextStep}
  >
    <p class="text-cryptiq-fg-muted">
      This password encrypts your vault. Choose something long and memorable — a passphrase works well.
    </p>
    <div class="mt-4 space-y-3">
      <!-- Password field — font-mono for secret material -->
      <div>
        <label for="master-pw" class="mb-1 block text-meta font-medium text-cryptiq-fg-muted">
          Master password
        </label>
        <input
          id="master-pw"
          type="password"
          bind:value={masterPassword}
          autocomplete="new-password"
          placeholder="Enter your master password"
          oninput={handleMasterPasswordInput}
          class="w-full rounded-cryptiq border border-cryptiq-border-strong bg-cryptiq-surface-2 px-3 py-2 font-mono text-body text-cryptiq-fg placeholder:text-cryptiq-fg-subtle focus:border-cryptiq-accent focus:outline-none focus:ring-1 focus:ring-cryptiq-ring"
        />
        <!-- Live strength meter (AUTH-02 weak-warned-not-blocked) -->
        <StrengthMeter password={masterPassword} />
      </div>

      <!-- Master-password breach check (HIBP-06) — sibling row, never inside StrengthMeter.
           Visually subordinate to the wizard's one dominant danger moment (the earlier
           "no password reset" step) — a plain secondary button, no tone="danger" panel. -->
      <div>
        <button
          type="button"
          onclick={() => void handleBreachCheckClick()}
          disabled={breachCheckResult === 'checking'}
          class="rounded-cryptiq px-3 py-2 text-meta font-medium text-cryptiq-fg-muted transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-fg disabled:cursor-not-allowed disabled:opacity-40"
        >
          {breachCheckResult === 'checking' ? 'Checking…' : 'Check against breaches'}
        </button>

        {#if breachCheckResult === 'breached'}
          <div class="mt-2 flex items-start gap-2" role="alert" aria-live="polite">
            <svg class="mt-0.5 size-4 shrink-0 text-cryptiq-danger" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <line x1="12" y1="8" x2="12" y2="13" />
              <circle cx="12" cy="16.5" r="0.75" fill="currentColor" stroke="none" />
            </svg>
            <p class="text-meta text-cryptiq-danger">
              This password has appeared in a known data breach. Consider choosing a different one.
            </p>
          </div>
        {:else if breachCheckResult === 'safe'}
          <div class="mt-2 flex items-center gap-2" role="alert" aria-live="polite">
            <svg class="size-4 shrink-0 text-cryptiq-success" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M20 6 9 17l-5-5" />
            </svg>
            <p class="text-meta text-cryptiq-fg-muted">Not found in known breaches.</p>
          </div>
        {:else if breachCheckResult === 'unknown'}
          <div class="mt-2 flex items-center gap-2" role="alert" aria-live="polite">
            <span class="flex size-4 shrink-0 items-center justify-center rounded-full bg-cryptiq-attention text-cryptiq-fg dark:text-cryptiq-bg">
              <svg class="size-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <circle cx="12" cy="12" r="9" />
                <path d="M9.5 9a2.5 2.5 0 0 1 4.9.8c0 1.7-2.4 1.5-2.4 3.2" />
                <circle cx="12" cy="16.3" r="0.4" fill="currentColor" stroke="none" />
              </svg>
            </span>
            <p class="text-meta text-cryptiq-fg-muted">Couldn't check right now — try again in a moment.</p>
          </div>
        {/if}
      </div>

      <!-- Confirm field -->
      <div>
        <label for="confirm-pw" class="mb-1 block text-meta font-medium text-cryptiq-fg-muted">
          Confirm password
        </label>
        <input
          id="confirm-pw"
          type="password"
          bind:value={confirmPassword}
          autocomplete="new-password"
          placeholder="Re-enter your master password"
          class="w-full rounded-cryptiq border border-cryptiq-border-strong bg-cryptiq-surface-2 px-3 py-2 font-mono text-body text-cryptiq-fg placeholder:text-cryptiq-fg-subtle focus:border-cryptiq-accent focus:outline-none focus:ring-1 focus:ring-cryptiq-ring"
        />
        <!-- Mismatch warning — DOES block Continue (auth-02 mismatch blocks) -->
        {#if confirmPassword.length > 0 && !passwordsMatch}
          <p class="mt-1 text-meta text-cryptiq-danger" role="alert">Passwords do not match.</p>
        {/if}
      </div>
    </div>
  </FirstRunStep>

<!-- ── Step: recovery opt-in (AUTH-04) ───────────────────────────────────── -->
{:else if step === 'recovery-opt-in'}
  <FirstRunStep
    step={stepNumber('recovery-opt-in')}
    total={totalSteps}
    eyebrow="Recovery key"
    title="Create a recovery key?"
    continueLabel={withRecoveryKey ? 'Create vault + recovery key' : 'Create vault'}
    onBack={prevStep}
    onContinue={nextStep}
  >
    {#if error}
      <p class="mb-3 rounded-cryptiq border border-cryptiq-danger-border bg-cryptiq-danger-surface px-3 py-2 text-body text-cryptiq-danger" role="alert">
        {error}
      </p>
    {/if}
    <p class="text-cryptiq-fg-muted">
      A recovery key lets you unlock your vault if you ever forget your master password.
      It works like an emergency override — keep it somewhere safe and separate from your vault.
    </p>
    <div class="mt-4 space-y-2">
      <label class="flex cursor-pointer items-start gap-3 rounded-cryptiq border p-3 transition-colors {withRecoveryKey ? 'border-cryptiq-accent bg-cryptiq-selected' : 'border-cryptiq-border bg-cryptiq-surface'}">
        <input
          type="radio"
          bind:group={withRecoveryKey}
          value={true}
          class="mt-0.5 shrink-0"
          style="accent-color: var(--color-cryptiq-accent)"
        />
        <div>
          <p class="text-body font-medium text-cryptiq-fg">Yes, create a recovery key</p>
          <p class="text-meta text-cryptiq-fg-subtle">Recommended — shown once after vault creation.</p>
        </div>
      </label>
      <label class="flex cursor-pointer items-start gap-3 rounded-cryptiq border p-3 transition-colors {!withRecoveryKey ? 'border-cryptiq-accent bg-cryptiq-selected' : 'border-cryptiq-border bg-cryptiq-surface'}">
        <input
          type="radio"
          bind:group={withRecoveryKey}
          value={false}
          class="mt-0.5 shrink-0"
          style="accent-color: var(--color-cryptiq-accent)"
        />
        <div>
          <p class="text-body font-medium text-cryptiq-fg">No, I'll rely on my memory</p>
          <p class="text-meta text-cryptiq-fg-subtle">You can generate one later from Settings.</p>
        </div>
      </label>
    </div>
  </FirstRunStep>

<!-- ── Step: recovery key display (AUTH-04/05/06) ────────────────────────── -->
{:else if step === 'recovery-key' && recoveryKey !== null}
  <FirstRunStep
    step={stepNumber('recovery-key')}
    total={totalSteps}
    eyebrow="Recovery key"
    title="Save your recovery key."
    showContinue={false}
  >
    <!--
      RecoveryKeyCard owns its own Continue gate (required checkbox) and calls onDone.
      showContinue=false omits FirstRunStep's footer Continue entirely (canContinue only
      DISABLES it, leaving a duplicate button — UAT T4); RecoveryKeyCard renders its own.
    -->
    <RecoveryKeyCard
      recoveryKey={recoveryKey}
      onDone={() => {
        recoveryKey = null;
        masterPassword = '';
        confirmPassword = '';
        go('main');
      }}
    />
  </FirstRunStep>

<!-- ── Step: creating (async spinner) ────────────────────────────────────── -->
{:else if step === 'creating'}
  <div class="grid h-full place-items-center bg-cryptiq-bg px-6 py-10">
    <div class="w-full max-w-lg space-y-4 rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface p-8 shadow-cryptiq-panel text-center">
      <div class="mx-auto size-8 animate-spin rounded-full border-2 border-cryptiq-border border-t-cryptiq-accent" aria-hidden="true"></div>
      <p class="text-body text-cryptiq-fg-muted">Creating your vault…</p>
    </div>
  </div>
{/if}

{#if showMasterCheckDialog}
  <HibpConsentDialog
    kind="master-check"
    onConfirm={() => void handleMasterCheckConfirm()}
    onCancel={handleMasterCheckCancel}
  />
{/if}
