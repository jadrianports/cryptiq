<!--
  ExtensionApprovalModal.svelte — TOFU approval prompt for a new browser extension
  (BRIDGE-05 / D-01).

  On a `bridge://associate-request` Tauri event, shows a role="dialog" aria-modal
  overlay: "A browser extension (<label>) wants to use Cryptiq autofill" + the
  grouped-hex fingerprint (bridgeFingerprint.ts) + Approve/Deny.

  Unlike sync's PairingScreen SAS flow (no modal — a full sub-view), this genuinely
  IS a modal: there is no existing role="dialog" shell in the codebase to copy, so
  this adapts DeviceList.svelte's inline danger-ack panel a11y grouping
  (role="group" + aria-label + button pair) into a real dialog shell.

  Mounted APP-GLOBALLY (in App.svelte, alongside <Toast />) so an approval request
  surfaces regardless of the current screen — mirrors how Toast overlays every view.

  Security:
    - Listener registered BEFORE any invoke — same eager-listen discipline as
      PairingScreen's 'pairing://sas' subscription (Pitfall 1: Tauri events are
      fire-and-forget; a missed event cannot be replayed).
    - The event payload's `clientPublicKey` is BASE64 (per extension_bridge.rs's
      `BASE64.encode(client_public_key)` emit — NOT hex, unlike the persisted
      ExtensionAssociation.clientPublicKey which is hex-encoded).
    - No entry/vault data ever appears in this modal — only the label + fingerprint
      (both public, non-secret display data).
    - Approve/Deny invoke bridge_approve/bridge_deny via bridgeCommands.ts (never
      raw invoke() in the component — mirrors the project's *Bridge.ts wrapper
      convention).

  Source: 15-05-PLAN.md Task 2; 15-PATTERNS.md "ExtensionApprovalModal.svelte";
          15-RESEARCH.md Pattern 2 (TOFU approval) + Pattern 3 (fingerprint).
-->
<script lang="ts">
  import { listen } from '@tauri-apps/api/event';
  import type { UnlistenFn } from '@tauri-apps/api/event';
  import { formatFingerprint } from './bridgeFingerprint';
  import { bridgeApprove, bridgeDeny } from './bridgeCommands';

  // ---------------------------------------------------------------------------
  // Pending-request state — plain $state (non-secret display strings + a public key).
  // null = no pending approval request to show.
  // ---------------------------------------------------------------------------
  type PendingRequest = {
    sessionId: string;
    label: string;
    fingerprint: string;
  };

  let pending = $state<PendingRequest | null>(null);
  let isWorking = $state(false);

  /** Decode a base64 string to a Uint8Array (browser-safe, no Buffer dependency). */
  function base64ToBytes(b64: string): Uint8Array {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  // ---------------------------------------------------------------------------
  // Event listener (SECURITY: registered eagerly on mount — Pitfall 1 discipline,
  // mirrors PairingScreen's 'pairing://sas' subscription).
  // ---------------------------------------------------------------------------
  $effect(() => {
    let unlisten: UnlistenFn | null = null;

    void (async () => {
      unlisten = await listen<{ sessionId: string; clientPublicKey: string; label: string }>(
        'bridge://associate-request',
        (event) => {
          const { sessionId, clientPublicKey, label } = event.payload;
          const fingerprint = formatFingerprint(base64ToBytes(clientPublicKey));
          pending = { sessionId, label, fingerprint };
        },
      );
    })();

    return () => {
      unlisten?.();
    };
  });

  async function handleApprove(): Promise<void> {
    if (!pending || isWorking) return;
    isWorking = true;
    try {
      await bridgeApprove(pending.sessionId);
    } finally {
      pending = null;
      isWorking = false;
    }
  }

  async function handleDeny(): Promise<void> {
    if (!pending || isWorking) return;
    isWorking = true;
    try {
      await bridgeDeny(pending.sessionId);
    } finally {
      pending = null;
      isWorking = false;
    }
  }
</script>

{#if pending}
  <!-- Modal overlay — role="dialog" aria-modal (genuine modal, unlike DeviceList's inline panel) -->
  <div class="fixed inset-0 z-50 grid place-items-center bg-black/40 px-4">
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="extension-approval-heading"
      class="w-full max-w-sm overflow-hidden rounded-cryptiq-lg border border-cryptiq-border bg-cryptiq-surface shadow-cryptiq-panel"
    >
      <div class="px-4 py-4 space-y-4">
        <div>
          <p id="extension-approval-heading" class="text-body font-semibold text-cryptiq-fg">
            A browser extension ({pending.label}) wants to use Cryptiq autofill
          </p>
        </div>

        <!-- Fingerprint — human-eyeball re-approval aid (D-01), NOT a security check itself -->
        <div class="rounded-cryptiq border border-cryptiq-border-strong bg-cryptiq-surface-2 px-4 py-3">
          <p class="mb-1 text-meta font-medium tracking-wide text-cryptiq-fg-subtle uppercase">
            Fingerprint
          </p>
          <p class="font-mono text-body font-medium text-cryptiq-fg break-all select-all">
            {pending.fingerprint}
          </p>
        </div>

        <!-- Actions — grouped for accessibility (mirrors DeviceList's danger-ack button group) -->
        <div role="group" aria-label="Approve or deny {pending.label}" class="flex items-center gap-4">
          <button
            type="button"
            onclick={() => void handleApprove()}
            disabled={isWorking}
            class="rounded-cryptiq bg-cryptiq-accent px-4 py-2 text-body font-semibold text-cryptiq-accent-fg transition-colors hover:bg-cryptiq-accent-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cryptiq-ring disabled:cursor-not-allowed disabled:opacity-50"
          >
            Approve
          </button>
          <button
            type="button"
            onclick={() => void handleDeny()}
            disabled={isWorking}
            class="rounded-cryptiq bg-cryptiq-danger px-4 py-2 text-body font-semibold text-cryptiq-danger-fg transition-colors hover:opacity-90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-cryptiq-ring disabled:cursor-not-allowed disabled:opacity-50"
          >
            Deny
          </button>
        </div>
      </div>
    </div>
  </div>
{/if}
