<script lang="ts">
  // apps/extension/entrypoints/popup/DevEcho.svelte
  //
  // D-18/D-20: dev-only "send echo" trigger — proves the full
  // browser -> sidecar -> named-pipe -> app -> back round trip (SC-1) and
  // gives D-19's app-not-running case a visible dev signal (SC-2). Loaded
  // ONLY via a dynamic import gated on import.meta.env.DEV in Popup.svelte,
  // mirroring apps/desktop/src/lib/dev/boot-self-test.ts's DEV-gating
  // discipline so this component (and its "send echo" button string) is
  // excluded from production builds entirely.

  let status = $state('idle');
  let resultText = $state('');

  async function handleSendEcho() {
    status = 'sending';
    resultText = '';
    const result = await chrome.runtime.sendMessage({ type: 'cryptiq-send-echo' });

    if (result?.ok) {
      status = 'ok';
      resultText = JSON.stringify(result.payload);
      console.info(`[cryptiq-ext] echo result: ok ${resultText}`);
    } else if (result?.appNotRunning) {
      status = 'app-not-running';
      resultText = 'Cryptiq app is not running';
      console.info('[cryptiq-ext] echo result: app-not-running');
    } else {
      status = 'error';
      resultText = result?.error ?? 'unknown error';
      console.info(`[cryptiq-ext] echo result: error ${resultText}`);
    }
  }
</script>

<div style="margin-top: 8px; border-top: 1px solid #ccc; padding-top: 8px;">
  <p style="font-size: 11px; color: #888; margin: 0 0 4px;">DEV ONLY</p>
  <button onclick={handleSendEcho}>send echo</button>
  <p style="font-size: 12px; word-break: break-all;">status: {status}</p>
  {#if resultText}
    <p style="font-size: 12px; word-break: break-all;">{resultText}</p>
  {/if}
</div>
