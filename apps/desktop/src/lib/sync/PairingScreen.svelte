<!--
  PairingScreen.svelte — Full pairing sub-view wizard (UI-15).

  State machine: IDLE → CODE_DISPLAYED/WAITING_FOR_PEER → CONNECTING → SAS_WINDOW
                  → FINALIZING → DONE/FAILED

  Security-critical invariants (LOCKED — do NOT weaken):
    1. Listener for 'pairing://sas' is registered BEFORE pairingInitiate/pairingConnect (Pitfall 1)
    2. stopSyncListener() runs before pairingInitiate; startSyncListenerIfPaired on every exit (Pitfall 3)
    3. SAS window is NON-DISMISSIBLE: Back hidden/replaced with Cancel; Escape → Cancel only (D-02/D-07)
    4. pairingConfirm THEN pairingFinalize in the SAME handler, no gap (PAIR-LOW2 / D-08)
    5. No entry data (title/username/password/url) in any string — counts/SAS/device-name only (T-12-12)

  Source: 12-RESEARCH.md lines 129-248, 668-721; 12-PATTERNS.md PairingScreen section;
          12-UI-SPEC.md Pairing Sub-View Copy; 12-CONTEXT.md D-02/D-05/D-06/D-07/D-08/D-09/D-18.
-->
<script lang="ts">
  import { listen } from '@tauri-apps/api/event';
  import type { UnlistenFn } from '@tauri-apps/api/event';
  import {
    pairingInitiate,
    pairingConnect,
    pairingConfirm,
    pairingFinalize,
    pairingGetSas,
  } from './syncBridge';
  import {
    startSyncListenerIfPaired,
    stopSyncListener,
  } from './syncOrchestration';
  import { pairingStore } from './PairingStore.svelte';
  import { pushToast } from '../state/ui.svelte';
  import SasCountdownRing from './SasCountdownRing.svelte';
  import { PairingCodeInvalidError } from '@cryptiq/core';

  // ---------------------------------------------------------------------------
  // Props
  // ---------------------------------------------------------------------------

  type Props = {
    /**
     * Optional back callback. When provided (rendered inside SettingsShell),
     * calls this instead of navigating directly. Mirrors AboutView.svelte pattern.
     */
    onBack?: () => void;
    /** Tauri app config directory. */
    configDir: string;
    /** Filesystem path to the vault file. */
    vaultPath: string;
  };

  let { onBack, configDir, vaultPath }: Props = $props();

  // ---------------------------------------------------------------------------
  // Local state — plain $state (NOT $state.raw): these are non-secret UI strings.
  // The SAS digits are publicly compared between devices; no secret material here.
  // ---------------------------------------------------------------------------

  type PairingState =
    | 'IDLE'
    | 'CODE_DISPLAYED'
    | 'WAITING_FOR_PEER'
    | 'CONNECTING'
    | 'SAS_WINDOW'
    | 'FINALIZING'
    | 'DONE'
    | 'FAILED';

  let pairingState = $state<PairingState>('IDLE');
  let currentSessionId = $state<string | null>(null);
  let previousSessionId = $state<string | null>(null); // D-08 reaper: track prior session
  let sasDisplay = $state<string | null>(null);
  let qrSvg = $state<string>('');
  let bundledCode = $state<string>('');
  let joinerCode = $state<string>('');
  let manualIp = $state<string>(''); // D-06 manual-IP fallback
  let showManualIp = $state<boolean>(false);
  let failedMessage = $state<string>('');
  let codeError = $state<string>('');
  let firewallAck = $state<boolean>(false); // D-09 one-time firewall heads-up per session
  let sasExpired = $state<boolean>(false); // true when 60s ring expires
  let isWorking = $state<boolean>(false); // debounce multiple button clicks

  // D-08 reaper: detect re-entry with a stale session
  let hasStaleSession = $state<boolean>(false);

  // ---------------------------------------------------------------------------
  // Event listeners (SECURITY: registered BEFORE pairingInitiate/pairingConnect — Pitfall 1)
  // ---------------------------------------------------------------------------

  $effect(() => {
    let unlistenSas: UnlistenFn | null = null;
    let unlistenError: UnlistenFn | null = null;

    // Register BOTH listeners eagerly on mount — before any pairingInitiate/pairingConnect call.
    // Tauri events are fire-and-forget; missed events cannot be replayed (Pitfall 1).
    void (async () => {
      unlistenSas = await listen<{ sessionId: string; sasDisplay: string }>('pairing://sas', (event) => {
        if (event.payload.sessionId === currentSessionId) {
          sasDisplay = event.payload.sasDisplay;
          pairingState = 'SAS_WINDOW';
          sasExpired = false;
          // Belt-and-suspenders (Pitfall 1): if event arrived with empty display, poll fallback
          if (!sasDisplay && currentSessionId) {
            void pairingGetSas(currentSessionId).then((s) => { sasDisplay = s; }).catch(() => {/* non-fatal */});
          }
        }
      });

      unlistenError = await listen<{ sessionId: string; message: string }>(
        'pairing://error',
        (event) => {
          if (
            event.payload.sessionId === currentSessionId ||
            currentSessionId === null
          ) {
            // T-12-11: coalesced safe copy — no handshake-vs-network distinction surfaced
            pairingState = 'FAILED';
            failedMessage = "Pairing didn't complete — try again.";
            void restartListener();
          }
        },
      );
    })();

    // Teardown: unregister listeners when component unmounts
    return () => {
      unlistenSas?.();
      unlistenError?.();
    };
  });

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  function handleBack(): void {
    if (onBack) {
      onBack();
    }
  }

  async function restartListener(): Promise<void> {
    try {
      await startSyncListenerIfPaired(configDir, vaultPath);
    } catch {
      // Non-fatal — the listener will retry on next entry
    }
  }

  // D-08 reaper: finalize any lingering prior session (idempotent)
  async function reaperFinalizePrior(priorId: string | null): Promise<void> {
    if (!priorId) return;
    try {
      await pairingFinalize(configDir, priorId);
    } catch {
      // Idempotent: Rust self-zeroizes on 60s timeout; safe to ignore errors here
    }
  }

  // ---------------------------------------------------------------------------
  // A-side path: share this device's code (initiator / responder)
  // ---------------------------------------------------------------------------

  async function handleStartSharing(): Promise<void> {
    if (isWorking) return;
    isWorking = true;

    try {
      // D-08 reaper: if a prior session exists, finalize it before starting new
      if (currentSessionId !== null) {
        hasStaleSession = true;
        failedMessage = "Pairing didn't complete — try again.";
        previousSessionId = currentSessionId;
        currentSessionId = null;
        qrSvg = '';
        bundledCode = '';
        pairingState = 'IDLE';
        await reaperFinalizePrior(previousSessionId);
        isWorking = false;
        return;
      }

      // D-09 firewall heads-up: show before first pairingInitiate if not yet acked
      if (!firewallAck) {
        // The notice is rendered inline — user must click "Got it" to proceed
        // We set pairingState to a special transient value indicating we're waiting
        // for firewall ack before continuing. We handle this via the firewallAck flag.
        // The "Start sharing" button is replaced by the firewall notice when !firewallAck.
        firewallAck = false; // will be set to true when user clicks "Got it"
        isWorking = false;
        return;
      }

      // Pitfall 3: stop sync listener BEFORE pairingInitiate (frees port 54321)
      await stopSyncListener();

      const result = await pairingInitiate(configDir);
      currentSessionId = result.sessionId;
      qrSvg = result.qrSvg;
      bundledCode = result.base32Code;
      pairingState = 'WAITING_FOR_PEER';
      hasStaleSession = false;
    } catch (err) {
      pairingState = 'FAILED';
      failedMessage = "Pairing didn't complete — try again.";
      await restartListener();
    } finally {
      isWorking = false;
    }
  }


  // ---------------------------------------------------------------------------
  // B-side path: enter the other device's code (joiner / initiator)
  // ---------------------------------------------------------------------------

  async function handleConnect(): Promise<void> {
    if (isWorking) return;
    isWorking = true;
    codeError = '';

    const codeToUse = manualIp.trim()
      ? joinerCode.trim().replace(/^[^:]+:[^:]+:/, `${manualIp.trim()}:54321:`)
      : joinerCode.trim();

    try {
      // D-08 reaper: finalize prior session before starting new
      if (currentSessionId !== null) {
        previousSessionId = currentSessionId;
        currentSessionId = null;
        await reaperFinalizePrior(previousSessionId);
      }

      // D-09 firewall heads-up before first connection attempt
      if (!firewallAck) {
        isWorking = false;
        return;
      }

      // Pitfall 3: stop sync listener before pairingConnect
      await stopSyncListener();

      const result = await pairingConnect(configDir, codeToUse);
      currentSessionId = result.sessionId;
      pairingState = 'CONNECTING';
      hasStaleSession = false;
    } catch (err) {
      if (err instanceof PairingCodeInvalidError) {
        codeError = 'Invalid code — check for typos and try again.';
        await restartListener();
      } else {
        pairingState = 'FAILED';
        failedMessage = "Pairing didn't complete — try again.";
        await restartListener();
      }
    } finally {
      isWorking = false;
    }
  }

  // ---------------------------------------------------------------------------
  // SAS window: Confirm — pairingConfirm THEN pairingFinalize in same handler (PAIR-LOW2)
  // ---------------------------------------------------------------------------

  async function handleConfirm(): Promise<void> {
    if (isWorking || sasExpired || currentSessionId === null) return;
    isWorking = true;

    pairingState = 'FINALIZING';

    try {
      // PAIR-LOW2 / D-08: confirm and finalize with NO gap between them
      await pairingConfirm(currentSessionId);
      await pairingFinalize(configDir, currentSessionId);

      // Success: re-init pairingStore so the new device row appears (D-18)
      await pairingStore.init(configDir);

      const peer = pairingStore.peers[0];
      const deviceName = peer?.deviceName ?? 'the other device';
      pushToast(`Paired with ${deviceName}.`);

      pairingState = 'DONE';
    } catch {
      pairingState = 'FAILED';
      failedMessage = "Pairing didn't complete — try again.";
    } finally {
      isWorking = false;
      // On every exit (success or failure): restart the sync listener (Pitfall 3)
      await restartListener();
    }
  }

  // ---------------------------------------------------------------------------
  // Cancel / Back — safe in all states EXCEPT none should auto-confirm
  // D-02: during SAS_WINDOW and FINALIZING, Escape triggers Cancel (not Back)
  // ---------------------------------------------------------------------------

  async function handleCancel(): Promise<void> {
    // Do NOT call pairingConfirm — Escape/Cancel must never auto-confirm
    pairingState = 'IDLE';
    currentSessionId = null;
    sasDisplay = null;
    sasExpired = false;
    qrSvg = '';
    bundledCode = '';
    joinerCode = '';
    codeError = '';
    failedMessage = '';
    // Restart listener on cancel (Pitfall 3)
    await restartListener();
  }

  // Keyboard handler for Escape — only Cancel during SAS_WINDOW/FINALIZING
  function handleKeydown(event: KeyboardEvent): void {
    if (event.key === 'Escape') {
      if (pairingState === 'SAS_WINDOW' || pairingState === 'FINALIZING') {
        // During SAS window Escape triggers Cancel, never auto-confirm (D-02 SC-1)
        void handleCancel();
      } else if (
        pairingState !== 'DONE' &&
        pairingState !== 'CODE_DISPLAYED' &&
        pairingState !== 'WAITING_FOR_PEER' &&
        pairingState !== 'CONNECTING'
      ) {
        void handleCancel();
      }
    }
  }

  function handleSasExpired(): void {
    sasExpired = true;
  }

  function handleReset(): void {
    pairingState = 'IDLE';
    currentSessionId = null;
    previousSessionId = null;
    sasDisplay = null;
    sasExpired = false;
    qrSvg = '';
    bundledCode = '';
    joinerCode = '';
    codeError = '';
    failedMessage = '';
    hasStaleSession = false;
  }

  // Back is safe to call from IDLE or DONE/FAILED states only
  async function handleBackSafe(): Promise<void> {
    await restartListener();
    handleBack();
  }
</script>

<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
<main
  aria-label="Pair a Device"
  class="flex h-screen flex-col bg-cryptiq-bg"
  onkeydown={handleKeydown}
>
  <!-- Page header -->
  <header class="flex items-center gap-3 border-b border-cryptiq-border bg-cryptiq-surface px-6 py-4">
    <!--
      D-02/SC-1 NON-DISMISSIBLE: Back is hidden during SAS_WINDOW and FINALIZING.
      During those states, only Cancel is shown (which does NOT call pairingConfirm).
    -->
    {#if pairingState !== 'SAS_WINDOW' && pairingState !== 'FINALIZING'}
      <button
        type="button"
        onclick={() => void handleBackSafe()}
        class="grid size-8 place-items-center rounded-cryptiq text-cryptiq-fg-muted transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-fg"
        aria-label="Back to settings"
        title="Back to settings"
      >
        <svg
          class="size-4"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="1.75"
          stroke-linecap="round"
          stroke-linejoin="round"
          aria-hidden="true"
        >
          <path d="M19 12H5" /><path d="m12 5-7 7 7 7" />
        </svg>
      </button>
    {:else}
      <!-- During SAS_WINDOW / FINALIZING: Back is replaced with Cancel -->
      <button
        type="button"
        onclick={() => void handleCancel()}
        class="grid size-8 place-items-center rounded-cryptiq text-cryptiq-fg-muted transition-colors hover:bg-cryptiq-hover hover:text-cryptiq-fg"
        aria-label="Cancel pairing"
        title="Cancel pairing"
      >
        <svg
          class="size-4"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="1.75"
          stroke-linecap="round"
          stroke-linejoin="round"
          aria-hidden="true"
        >
          <path d="M18 6 6 18" /><path d="m6 6 12 12" />
        </svg>
      </button>
    {/if}
    <h1 class="text-title font-semibold text-cryptiq-fg">Pair a Device</h1>
  </header>

  <!-- Scrollable content body -->
  <div class="flex-1 overflow-y-auto px-6 py-6">
    <div class="mx-auto max-w-lg space-y-6">

      <!-- ── Peer cap notice (v2.0 supports 1 peer) ──────────────────────── -->
      {#if pairingStore.peers.length > 0 && pairingState === 'IDLE'}
        <div class="overflow-hidden rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface shadow-cryptiq-panel">
          <div class="px-4 py-4">
            <p class="text-body text-cryptiq-fg">
              Unpair your current device before pairing a new one. (v2.0 supports one paired device.)
            </p>
          </div>
        </div>

      <!-- ── D-08 stale session notice ─────────────────────────────────── -->
      {:else if hasStaleSession && pairingState === 'IDLE'}
        <div role="status" class="overflow-hidden rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface shadow-cryptiq-panel">
          <div class="px-4 py-4">
            <p class="text-body text-cryptiq-fg">Pairing didn't complete — try again.</p>
          </div>
        </div>
        <!-- Fall through to show the IDLE UI below so user can retry -->
      {/if}

      <!-- ── D-09 Firewall heads-up (one-time per session) ─────────────── -->
      {#if !firewallAck && pairingState === 'IDLE' && pairingStore.peers.length === 0}
        <div role="status" class="overflow-hidden rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface shadow-cryptiq-panel">
          <div class="px-4 py-4 space-y-3">
            <p class="text-body font-semibold text-cryptiq-fg">Allow network access</p>
            <p class="text-body text-cryptiq-fg-muted">
              Windows will ask to allow Cryptiq network access. Click Allow and choose Private networks only.
            </p>
            <button
              type="button"
              onclick={() => { firewallAck = true; }}
              class="rounded-cryptiq bg-cryptiq-accent px-4 py-2 text-body font-semibold text-cryptiq-accent-fg transition-colors hover:bg-cryptiq-accent-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cryptiq-ring"
            >
              Got it
            </button>
          </div>
        </div>
      {/if}

      <!-- ── IDLE / CODE_DISPLAYED: dual-affordance share + join (D-05) ── -->
      {#if (pairingState === 'IDLE' || pairingState === 'CODE_DISPLAYED') && pairingStore.peers.length === 0}

        <!-- A-side: show your code + QR -->
        <section aria-labelledby="share-heading" class="overflow-hidden rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface shadow-cryptiq-panel">
          <div class="px-4 py-4 space-y-4">
            <!-- D-09 QR privacy warning -->
            <div>
              <p class="mb-1 text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">YOUR CODE</p>
              <p class="text-body text-cryptiq-fg-muted">
                Show this to the other device. Pair somewhere private — this code can be photographed.
              </p>
            </div>

            {#if pairingState === 'CODE_DISPLAYED' && bundledCode}
              <!-- Display the bundled code -->
              <div class="rounded-cryptiq border border-cryptiq-border-strong bg-cryptiq-surface-2 px-4 py-3">
                <p class="font-mono text-body font-medium text-cryptiq-fg break-all select-all">
                  {bundledCode}
                </p>
              </div>

              <!-- QR code (D-05: {#html qrSvg}) -->
              {#if qrSvg}
                <div class="flex flex-col items-center gap-2">
                  {@html qrSvg}
                  <p class="text-meta text-cryptiq-fg-subtle text-center">
                    Or scan this QR code with another device's camera app.
                  </p>
                </div>
              {/if}

              <p class="text-body text-cryptiq-fg-muted">Waiting for the other device to connect…</p>
              <p class="text-meta text-cryptiq-fg-subtle">Make sure both devices are on the same network.</p>
            {:else}
              <!-- Not yet initiated: show the share button -->
              <button
                type="button"
                onclick={() => void handleStartSharing()}
                disabled={isWorking || !firewallAck}
                class="w-full rounded-cryptiq bg-cryptiq-accent px-4 py-2 text-body font-semibold text-cryptiq-accent-fg transition-colors hover:bg-cryptiq-accent-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cryptiq-ring disabled:cursor-not-allowed disabled:opacity-50"
              >
                {isWorking ? 'Starting…' : 'Share this code'}
              </button>
            {/if}
          </div>
        </section>

        <!-- B-side: enter the other device's code -->
        <section aria-labelledby="join-heading" class="overflow-hidden rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface shadow-cryptiq-panel">
          <div class="px-4 py-4 space-y-3">
            <label for="joiner-code" class="block text-body font-medium text-cryptiq-fg">
              Enter the other device's code
            </label>
            <input
              id="joiner-code"
              type="text"
              bind:value={joinerCode}
              placeholder="Paste or type the code from the other device"
              autocomplete="off"
              autocorrect="off"
              spellcheck="false"
              class="w-full rounded-cryptiq border border-cryptiq-border-strong bg-cryptiq-surface-2 px-3 py-2 font-mono text-body text-cryptiq-fg placeholder:text-cryptiq-fg-subtle focus:outline-none focus:ring-1 focus:ring-cryptiq-ring"
            />

            <!-- D-06 manual-IP fallback -->
            {#if !showManualIp}
              <button
                type="button"
                onclick={() => { showManualIp = true; }}
                class="text-meta text-cryptiq-fg-subtle hover:text-cryptiq-fg"
              >
                Having trouble? Override the IP address
              </button>
            {:else}
              <div class="space-y-1">
                <label for="manual-ip" class="block text-meta text-cryptiq-fg-subtle">
                  Other device's IP address (overrides the bundled IP if stale)
                </label>
                <input
                  id="manual-ip"
                  type="text"
                  bind:value={manualIp}
                  placeholder="192.168.1.100"
                  autocomplete="off"
                  class="w-full rounded-cryptiq border border-cryptiq-border-strong bg-cryptiq-surface-2 px-3 py-2 font-mono text-meta text-cryptiq-fg placeholder:text-cryptiq-fg-subtle focus:outline-none focus:ring-1 focus:ring-cryptiq-ring"
                />
              </div>
            {/if}

            {#if codeError}
              <p class="text-meta text-cryptiq-danger" role="alert">{codeError}</p>
            {/if}

            <button
              type="button"
              onclick={() => void handleConnect()}
              disabled={isWorking || !joinerCode.trim() || !firewallAck}
              class="w-full rounded-cryptiq bg-cryptiq-accent px-4 py-2 text-body font-semibold text-cryptiq-accent-fg transition-colors hover:bg-cryptiq-accent-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cryptiq-ring disabled:cursor-not-allowed disabled:opacity-50"
            >
              {isWorking ? 'Connecting…' : 'Connect'}
            </button>
          </div>
        </section>

      <!-- ── WAITING_FOR_PEER ──────────────────────────────────────────── -->
      {:else if pairingState === 'WAITING_FOR_PEER'}
        <div class="overflow-hidden rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface shadow-cryptiq-panel">
          <div class="px-4 py-4 space-y-4">
            {#if bundledCode}
              <div>
                <p class="mb-1 text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">YOUR CODE</p>
                <p class="mb-2 text-body text-cryptiq-fg-muted">
                  Show this to the other device. Pair somewhere private — this code can be photographed.
                </p>
                <div class="rounded-cryptiq border border-cryptiq-border-strong bg-cryptiq-surface-2 px-4 py-3">
                  <p class="font-mono text-body font-medium text-cryptiq-fg break-all select-all">
                    {bundledCode}
                  </p>
                </div>
              </div>

              {#if qrSvg}
                <div class="flex flex-col items-center gap-2">
                  {@html qrSvg}
                  <p class="text-meta text-cryptiq-fg-subtle text-center">
                    Or scan this QR code with another device's camera app.
                  </p>
                </div>
              {/if}
            {/if}
            <p class="text-body text-cryptiq-fg-muted">Waiting for the other device to connect…</p>
            <p class="text-meta text-cryptiq-fg-subtle">Make sure both devices are on the same network.</p>
            <button
              type="button"
              onclick={() => void handleCancel()}
              class="text-body text-cryptiq-fg-muted hover:text-cryptiq-fg"
            >
              Cancel
            </button>
          </div>
        </div>

      <!-- ── CONNECTING ────────────────────────────────────────────────── -->
      {:else if pairingState === 'CONNECTING'}
        <div class="overflow-hidden rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface shadow-cryptiq-panel">
          <div class="px-4 py-4 space-y-3">
            <p class="text-body text-cryptiq-fg-muted">Connecting…</p>
            <button
              type="button"
              onclick={() => void handleCancel()}
              class="text-body text-cryptiq-fg-muted hover:text-cryptiq-fg"
            >
              Cancel
            </button>
          </div>
        </div>

      <!-- ── SAS_WINDOW (D-02/D-07 LOCKED — non-dismissible) ─────────── -->
      {:else if pairingState === 'SAS_WINDOW' || pairingState === 'FINALIZING'}
        <!--
          SC-1 / D-02 NON-DISMISSIBLE: no backdrop click possible (full sub-view, not modal).
          Back is replaced with Cancel in the header above.
          SAS_WINDOW state gates the Back/Cancel rendering throughout this block.
        -->
        <div class="overflow-hidden rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface shadow-cryptiq-panel">
          <div class="px-4 py-8 flex flex-col items-center gap-6 text-center">

            <!-- Eyebrow -->
            <p class="text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">
              VERIFY THE CODE MATCHES
            </p>

            <!-- Instruction -->
            <p class="text-body text-cryptiq-fg-muted max-w-sm">
              Both devices must show the same six digits. If they don't match, someone may be intercepting — cancel, move somewhere private, and try again.
            </p>

            <!-- SAS countdown ring with digits -->
            {#if sasDisplay !== null}
              <SasCountdownRing
                sasDisplay={sasDisplay}
                onExpired={handleSasExpired}
              />
            {/if}

            <!-- SAS mismatch warning (if user notices mismatch before cancelling) -->
            <p class="text-meta text-cryptiq-danger max-w-sm">
              The codes don't match. Cancel this pairing — someone may be intercepting. Move somewhere private and try again.
            </p>
            <p class="text-meta text-cryptiq-fg-subtle">
              (Only cancel if the codes are different. If they match, click Confirm.)
            </p>

            <!-- Action buttons -->
            <div class="flex flex-col items-center gap-3 w-full max-w-xs">
              <button
                type="button"
                onclick={() => void handleConfirm()}
                disabled={isWorking || sasExpired || pairingState === 'FINALIZING'}
                class="w-full rounded-cryptiq bg-cryptiq-accent px-5 py-2 text-body font-semibold text-cryptiq-accent-fg transition-colors hover:bg-cryptiq-accent-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cryptiq-ring disabled:cursor-not-allowed disabled:opacity-50"
              >
                {pairingState === 'FINALIZING' ? 'Confirming…' : 'Confirm — codes match'}
              </button>

              <!-- Cancel is always visible during SAS window (D-02) -->
              {#if pairingState !== 'FINALIZING'}
                <button
                  type="button"
                  onclick={() => void handleCancel()}
                  class="text-body text-cryptiq-fg-muted hover:text-cryptiq-fg"
                >
                  Cancel
                </button>
              {/if}
            </div>

          </div>
        </div>

      <!-- ── DONE ──────────────────────────────────────────────────────── -->
      {:else if pairingState === 'DONE'}
        <div class="overflow-hidden rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface shadow-cryptiq-panel">
          <div class="px-4 py-4 space-y-3">
            <p class="text-body font-semibold text-cryptiq-fg">
              {pairingStore.peers[0]?.deviceName ? `Paired with ${pairingStore.peers[0].deviceName}.` : 'Pairing complete.'}
            </p>
            <button
              type="button"
              onclick={() => void handleBackSafe()}
              class="rounded-cryptiq bg-cryptiq-accent px-4 py-2 text-body font-semibold text-cryptiq-accent-fg transition-colors hover:bg-cryptiq-accent-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cryptiq-ring"
            >
              Done
            </button>
          </div>
        </div>

      <!-- ── FAILED ────────────────────────────────────────────────────── -->
      {:else if pairingState === 'FAILED'}
        <div class="overflow-hidden rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface shadow-cryptiq-panel">
          <div class="px-4 py-4 space-y-3">
            <p class="text-body text-cryptiq-fg-muted">
              {failedMessage || "Pairing didn't complete — try again."}
            </p>
            <div class="flex items-center gap-4">
              <button
                type="button"
                onclick={handleReset}
                class="rounded-cryptiq bg-cryptiq-accent px-4 py-2 text-body font-semibold text-cryptiq-accent-fg transition-colors hover:bg-cryptiq-accent-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cryptiq-ring"
              >
                Try Again
              </button>
              <button
                type="button"
                onclick={() => void handleBackSafe()}
                class="text-body text-cryptiq-fg-muted hover:text-cryptiq-fg"
              >
                Back
              </button>
            </div>
          </div>
        </div>

      {/if}

    </div>
  </div>
</main>
