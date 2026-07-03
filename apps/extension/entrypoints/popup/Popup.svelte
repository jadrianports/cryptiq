<script lang="ts">
  // apps/extension/entrypoints/popup/Popup.svelte
  //
  // D-10 (XSEC-06): the real (non-dev) popup status surface. On every open
  // (MV3 popups are always a fresh script instantiation — RESEARCH.md
  // Pattern 3, no persistent-state assumption) this renders EXACTLY ONE of
  // five states:
  //   - not-paired            -> "Open Cryptiq to approve"
  //   - disconnected/app-closed -> "Cryptiq isn't running"
  //   - locked                -> "Cryptiq is locked — unlock it to fill"
  //   - connected-matches     -> match COUNT only (never titles/usernames
  //                              rendered here — that's the Phase 17/18
  //                              picker; this phase's popup is status-only)
  //   - connected-no-matches  -> "No saved logins for this site"
  //
  // HARD CONSTRAINT (XSEC-06): every state renders counts/status text ONLY —
  // never a password, never any secret, in any state.
  //
  // The popup never holds a popup-local `chrome.runtime.Port` (Pitfall 4 /
  // MV3 SW teardown) — every RPC is relayed through background.ts's
  // 'cryptiq-rpc' message handler, which calls sendAuthenticatedRpc() and
  // therefore always fetches the native port FRESH via background's lazy
  // getPort() accessor.
  import type { Component } from 'svelte';
  import { loadAssociation } from '../../src/lib/associationStore';
  import type { BridgeErrorCode } from '../../src/lib/bridgeRpc';

  let DevEchoComponent: Component | null = $state(null);

  if (import.meta.env.DEV) {
    // D-18: dev-only echo trigger, dynamically imported so Vite/WXT's
    // import.meta.env.DEV replacement strips this chunk from production.
    import('./DevEcho.svelte').then((mod) => {
      DevEchoComponent = mod.default;
    });
  }

  /** Metadata-only match shape (mirrors @cryptiq/core's EntryMatchMetadata
   * wire shape — deliberately re-declared locally rather than adding a
   * workspace dependency from apps/extension on @cryptiq/core; this type
   * carries NO password field by construction, matching BRIDGE-08). */
  interface EntryMatchMetadata {
    id: string;
    title: string;
    username: string;
    domainHint: string;
  }

  type PopupStatus =
    | { kind: 'loading' }
    | { kind: 'not-paired' }
    | { kind: 'disconnected' }
    | { kind: 'locked' }
    | { kind: 'connected-matches'; count: number }
    | { kind: 'connected-no-matches' };

  let status: PopupStatus = $state({ kind: 'loading' });
  let unlockRequested = $state(false);

  interface RpcMessageOutcome {
    ok: boolean;
    code?: BridgeErrorCode;
    payload?: unknown;
  }

  /**
   * Relay one inner `{ method, params }` RPC through background.ts's
   * 'cryptiq-rpc' handler. Never throws — a missing/torn-down background
   * context resolves as a transport failure, which callers fail closed on.
   */
  async function sendRpcViaBackground(innerPayload: Record<string, unknown>): Promise<RpcMessageOutcome> {
    try {
      const result = (await chrome.runtime.sendMessage({ type: 'cryptiq-rpc', payload: innerPayload })) as
        | RpcMessageOutcome
        | undefined;
      return result ?? { ok: false, code: 'unknown' };
    } catch {
      return { ok: false, code: 'unknown' };
    }
  }

  /**
   * Read the current active tab's top-level origin. Requires the
   * `activeTab` permission (granted for the duration of this popup-open
   * user gesture) — returns null if unavailable, which fails closed to the
   * `disconnected` state rather than guessing.
   */
  async function getCurrentTabOrigin(): Promise<string | null> {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.url) return null;
      return new URL(tab.url).origin;
    } catch {
      return null;
    }
  }

  /**
   * D-10 / RESEARCH.md Pattern 3: on-open status query. (1) check
   * association, (2) fetch the current tab origin, (3) fire a lock-aware
   * `match-origin` RPC and map the outcome to exactly one of the five
   * states.
   */
  async function refreshStatus(): Promise<void> {
    const association = await loadAssociation();
    if (!association) {
      status = { kind: 'not-paired' };
      return;
    }

    const origin = await getCurrentTabOrigin();
    if (origin === null) {
      // No readable tab origin (e.g. a chrome:// page) — fail closed the
      // same as any other transport-level failure rather than guessing.
      status = { kind: 'disconnected' };
      return;
    }

    const outcome = await sendRpcViaBackground({ method: 'match-origin', params: { origin } });

    if (!outcome.ok) {
      // vault-locked is a distinct, honest render (XSEC-06) — branch it off
      // BEFORE the generic disconnected fallback below. Every OTHER failure
      // (timeout, not-associated, protocol-error, app-not-running) stays
      // disconnected, fail closed (RESEARCH.md Pattern 3).
      if (outcome.code === 'vault-locked') {
        status = { kind: 'locked' };
        return;
      }
      status = { kind: 'disconnected' };
      return;
    }

    // Success payload is now a decrypted, authenticated JSON value (BUG-2 fix) —
    // the app never sends vault-locked on the success path, it is always a
    // plaintext error envelope handled above. The bytes are authenticated, but
    // `JSON.parse` can still yield any shape (null / array / number / object), so
    // treat a real match list as ONLY an object carrying an array `candidates`;
    // anything else renders connected-no-matches rather than mis-driving a count.
    const payload = outcome.payload;
    const candidates =
      payload !== null && typeof payload === 'object' && Array.isArray((payload as { candidates?: unknown }).candidates)
        ? ((payload as { candidates: EntryMatchMetadata[] }).candidates)
        : [];
    const count = candidates.length;
    status = count > 0 ? { kind: 'connected-matches', count } : { kind: 'connected-no-matches' };
  }

  void refreshStatus();

  /**
   * D-11: best-effort "Unlock Cryptiq" focus-raise. Fires a `focus-app` RPC
   * and ignores the result entirely — the locked message stays shown
   * regardless of whether the app's window was actually raised (Windows
   * foreground-lock restrictions can silently no-op set_focus()).
   */
  async function handleUnlockClick(): Promise<void> {
    unlockRequested = true;
    await sendRpcViaBackground({ method: 'focus-app', params: {} });
  }
</script>

<main>
  <h1 style="font-size: 14px; margin: 0 0 8px;">Cryptiq</h1>

  {#if status.kind === 'loading'}
    <p style="font-size: 12px; color: #666; margin: 0;">Checking status…</p>
  {:else if status.kind === 'not-paired'}
    <p style="font-size: 12px; margin: 0;">Open Cryptiq to approve</p>
  {:else if status.kind === 'disconnected'}
    <p style="font-size: 12px; margin: 0;">Cryptiq isn't running</p>
  {:else if status.kind === 'locked'}
    <p style="font-size: 12px; margin: 0 0 8px;">Cryptiq is locked — unlock it to fill</p>
    <button onclick={handleUnlockClick} disabled={unlockRequested}>
      {unlockRequested ? 'Unlock requested' : 'Unlock Cryptiq'}
    </button>
  {:else if status.kind === 'connected-matches'}
    <p style="font-size: 12px; margin: 0;">
      {status.count} saved {status.count === 1 ? 'login' : 'logins'} for this site
    </p>
  {:else if status.kind === 'connected-no-matches'}
    <p style="font-size: 12px; margin: 0;">No saved logins for this site</p>
  {/if}

  {#if import.meta.env.DEV && DevEchoComponent}
    <DevEchoComponent />
  {/if}
</main>
