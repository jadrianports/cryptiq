// apps/desktop/src/lib/dev/rpcHarness.ts
//
// D-13: dev-only match/fill RPC harness. Stripped from production by Vite's
// import.meta.env.DEV branch in main.ts, mirroring boot-self-test.ts's
// import.meta.env.DEV discipline and console.info/console.warn-only logging.
//
// Scope honesty: the Rust <-> extension legs of the round trip
// (extension -> sidecar -> pipe -> app) are already pinned by their own
// dedicated automated suites — the four `#[tokio::test]` pins in
// extension_bridge.rs (Plan 16-02: metadata-only shape, single-secret,
// vault-locked gate, dispatch timeout) and apps/extension's bridgeRpc.test.ts
// (Plan 15: box-sealed transport). This harness proves the ONE leg those
// suites cannot reach without a live browser + running sidecar: the
// renderer(vault) hop, driven against the REAL live VaultSession in this
// running dev build, using the exact same `handleRpcRequest` pure router
// that `registerRpcDispatch()` (Plan 16-03) invokes for every real
// `bridge://rpc-request` event emitted by the Rust bridge. Logging narrates
// the full conceptual path (extension -> sidecar -> pipe -> app ->
// renderer(vault) -> back) so a developer reading the console output can
// see where this harness's proof begins and ends.
//
// D-10 / no-secrets-to-logs: logs the match CANDIDATE COUNT only (never
// titles/usernames verbatim) and, for fill-entry, logs ONLY that a secret
// was received — never the secret value itself.

import { handleRpcRequest } from '../bridge/rpcDispatch';

const SAMPLE_ORIGIN = 'https://example.com';

export function runRpcHarness(): void {
  console.info('[rpc-harness] running (dev only — stripped in production builds).');
  console.info(
    '[rpc-harness] hop 1/6: extension issues match-origin (simulated — see apps/extension bridgeRpc.test.ts for the real transport leg)',
  );
  console.info('[rpc-harness] hop 2/6: sidecar relays stdio <-> pipe (simulated — see apps/native-host tests)');
  console.info(
    '[rpc-harness] hop 3/6: app (Rust) decrypts + dispatches via PendingRpcMap (simulated — see extension_bridge.rs #[tokio::test] pins)',
  );
  console.info('[rpc-harness] hop 4/6: renderer(vault) — REAL call into handleRpcRequest() against the live VaultSession');

  const matchRequestId = 'rpc-harness-match-origin';
  const matchResult = handleRpcRequest({
    requestId: matchRequestId,
    method: 'match-origin',
    params: { origin: SAMPLE_ORIGIN },
  }) as { code?: string; candidates?: Array<{ id: string }> };

  if (matchResult.code === 'vault-locked') {
    console.info('[rpc-harness] hop 5/6: renderer answered vault-locked (no data) — harness stops here, as expected when locked');
    console.info('[rpc-harness] hop 6/6: app would re-box + reply rpc-ok/error, sidecar relays back, extension renders (simulated)');
    return;
  }

  const candidateCount = matchResult.candidates?.length ?? 0;
  console.info(`[rpc-harness] match-origin: ${candidateCount} candidate(s) for ${SAMPLE_ORIGIN} (count only — no titles/usernames logged)`);

  if (candidateCount === 0) {
    console.info('[rpc-harness] no candidates to fill — skipping fill-entry leg');
    console.info('[rpc-harness] hop 5/6-6/6: app would re-box + reply, sidecar relays back, extension renders (simulated)');
    return;
  }

  const firstCandidate = matchResult.candidates?.[0];
  if (!firstCandidate) {
    console.warn('[rpc-harness] candidateCount > 0 but candidates[0] is missing — unexpected shape, skipping fill-entry leg');
    return;
  }
  const firstCandidateId = firstCandidate.id;
  console.info('[rpc-harness] hop 4/6 (continued): issuing fill-entry for the first returned id — REAL call into handleRpcRequest()');

  const fillResult = handleRpcRequest({
    requestId: 'rpc-harness-fill-entry',
    method: 'fill-entry',
    params: { entryId: firstCandidateId },
  }) as { code?: string; secret?: string };

  if (fillResult.code === 'not-found') {
    console.warn('[rpc-harness] fill-entry: not-found for a match-origin-returned id — investigate (V4 access-control mismatch?)');
  } else if (typeof fillResult.secret === 'string') {
    // D-10: never log the secret value itself — only that one was received.
    console.info('[rpc-harness] fill-entry: secret received (value not logged)');
  } else {
    console.warn('[rpc-harness] fill-entry: unexpected result shape');
  }

  console.info('[rpc-harness] hop 5/6: app would re-box the renderer result into rpc-ok/error (simulated)');
  console.info('[rpc-harness] hop 6/6: sidecar relays back over the pipe, extension resolves sendRpc() (simulated)');
  console.info('[rpc-harness] done.');
}
