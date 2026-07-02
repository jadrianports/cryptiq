<script lang="ts">
  // apps/extension/entrypoints/popup/Popup.svelte
  //
  // Minimal popup (D-17: background SW + popup only, zero content script).
  // Real popup UX (search/copy/lock state) lands in Phase 18 — this phase
  // only needs a shell to host the DEV-only echo trigger (D-18/D-20) PLUS
  // the production (NOT dev-gated) association states from Plan 06:
  // waiting-for-approval, directional version-mismatch (D-05, fail closed,
  // no partial-function fallback), and not-associated.
  //
  // D-18: the dev echo section is loaded via a DYNAMIC import gated on
  // import.meta.env.DEV, mirroring apps/desktop/src/main.ts's boot-self-test
  // gating exactly, so Vite/WXT's build-time DEV replacement + dead-code
  // elimination strips the entire DevEcho.svelte chunk (including the
  // "send echo" button string) from production builds.
  import type { Component } from 'svelte';

  let DevEchoComponent: Component | null = $state(null);

  if (import.meta.env.DEV) {
    import('./DevEcho.svelte').then((mod) => {
      DevEchoComponent = mod.default;
    });
  }

  // Same `let X = $state(...)` + conditional-render technique as the DEV
  // echo gate above, but these states are PRODUCTION — the directional
  // mismatch message and the approval-pending state must show for real
  // users, not just in dev builds.
  type BridgeUiState =
    | { state: 'unknown' }
    | { state: 'not-associated' }
    | { state: 'waiting-for-approval' }
    | { state: 'associated' }
    | { state: 'version-mismatch'; code: 'app-outdated' | 'extension-outdated'; message: string };

  let bridgeState: BridgeUiState = $state({ state: 'unknown' });

  interface IncomingBridgeStateMessage {
    type: 'cryptiq-bridge-state';
    state: 'waiting-for-approval' | 'associated' | 'error' | 'unknown';
    code?: string;
    message?: string;
  }

  // The app is the source of truth for WHICH side is behind (D-05) — the
  // popup renders the forwarded message string verbatim, never a
  // hardcoded per-direction copy of its own.
  function applyBridgeStateMessage(message: IncomingBridgeStateMessage): void {
    if (message.state === 'error' && (message.code === 'app-outdated' || message.code === 'extension-outdated')) {
      bridgeState = { state: 'version-mismatch', code: message.code, message: message.message ?? '' };
      return;
    }
    if (message.state === 'error' && message.code === 'not-associated') {
      bridgeState = { state: 'not-associated' };
      return;
    }
    if (message.state === 'waiting-for-approval' || message.state === 'associated') {
      bridgeState = { state: message.state };
      return;
    }
    // invalid-token / protocol-error / unknown — no dedicated visual state
    // yet; fail closed by staying out of the (only) success state.
  }

  chrome.runtime.onMessage.addListener((message: IncomingBridgeStateMessage) => {
    if (message?.type === 'cryptiq-bridge-state') {
      applyBridgeStateMessage(message);
    }
  });

  // A popup can open AFTER the background SW already resolved (or is
  // mid-resolving) the handshake, so ask for the current state rather than
  // only listening for future broadcasts.
  chrome.runtime
    .sendMessage({ type: 'cryptiq-get-bridge-state' })
    .then((response: IncomingBridgeStateMessage | undefined) => {
      if (response) applyBridgeStateMessage(response);
    })
    .catch(() => {
      // Background not ready yet — stay in 'unknown' until a broadcast
      // arrives via the listener above.
    });
</script>

<main>
  <h1 style="font-size: 14px; margin: 0 0 8px;">Cryptiq</h1>

  {#if bridgeState.state === 'waiting-for-approval'}
    <p style="font-size: 12px; margin: 0;">Open Cryptiq to approve this browser.</p>
  {:else if bridgeState.state === 'not-associated'}
    <p style="font-size: 12px; margin: 0;">
      This browser is not paired with Cryptiq yet — open the app to approve it.
    </p>
  {:else if bridgeState.state === 'version-mismatch'}
    <!-- D-05: fail closed, no partial-function fallback — the copy comes
         verbatim from the app, which knows which side (app-outdated vs
         extension-outdated) is actually behind. -->
    <p style="font-size: 12px; margin: 0; color: #b00020;">{bridgeState.message}</p>
  {:else}
    <p style="font-size: 12px; color: #666; margin: 0;">Native-messaging bridge skeleton.</p>
  {/if}

  {#if import.meta.env.DEV && DevEchoComponent}
    <DevEchoComponent />
  {/if}
</main>
