// apps/desktop/src/lib/bridge/rpcDispatch.ts
//
// Phase 16 Plan 03 — the renderer side of the Rust <-> JS RPC round trip
// (FILL-03 / BRIDGE-08 / XSEC-05 / XSEC-06).
//
// `registerRpcDispatch()` listens app-globally for `bridge://rpc-request`
// (emitted by extension_bridge.rs's `dispatch_rpc_method`, Plan 16-02) and
// replies via `invoke('bridge_rpc_response', { requestId, result })`.
//
// Routing:
//   - vault locked (D-09, checked PER REQUEST — no cached "still unlocked"
//     assumption)         -> { code: 'vault-locked' }, no data.
//   - method 'match-origin' -> { candidates: matchByOrigin(entries, origin) }
//     (metadata-only, structurally has no password field — SC-1 / BRIDGE-08),
//     each candidate additionally carrying candidate-scoped `weak`/`reused`
//     booleans (HEALTH-02, Phase 17 Plan 02) computed via core's `runAudit` —
//     see the match-origin branch below for the candidate-scoping rationale.
//   - method 'fill-entry'   -> { secret } for exactly the requested id, ONLY
//     when it exists and is not soft-deleted (V4 access control); otherwise
//     { code: 'not-found' }. RESEARCH.md Open Question 2: fill-entry-ok stays
//     `{ secret }` only — the extension already holds title/username from the
//     prior match-origin response (wire-minimization).
//   - any other method      -> { code: 'invalid-request' }.
//
// HARD CONSTRAINT (XSEC-05 / D-12 / T-16-03): this module MUST NOT import
// `../state/idle.svelte` (or call resetTimer/dispatch any window event). It
// is a pure background listener with ZERO DOM side effects — no toast, no
// `.focus()`, no visible render — so a burst of extension RPC traffic can
// never keep the vault unlocked past its idle timeout. See
// rpcDispatch.test.ts for the regression guard (fires an RPC burst and
// asserts the idle timer's expiry is unaffected).
//
// Mount discipline (Pitfall 2 / 16-RESEARCH.md): `registerRpcDispatch()` MUST
// be called app-globally — the SAME lifetime tier as `<ExtensionApprovalModal
// />` in App.svelte — and NEVER from inside the `isUnlocked`-gated $effect
// that starts the idle controller. A locked vault must still have a live
// listener so it can answer the typed `vault-locked` response instead of
// leaving the Rust-side `PendingRpcMap` entry to time out.

import { listen } from '@tauri-apps/api/event';
import { invoke } from '@tauri-apps/api/core';
import type { Entry } from '@cryptiq/core';
import { matchByOrigin, runAudit } from '@cryptiq/core';
import { vaultSession } from '../state/vault.svelte';
import { scorePassword } from '../zxcvbnSetup';

/** The decrypted inner RPC request payload emitted by the Rust bridge. */
interface RpcRequestPayload {
  requestId: string;
  method: string;
  params: Record<string, unknown>;
}

/**
 * Extract the typed Entry array from the vault's opaque `entries` field.
 *
 * Mirrors MainView.svelte's `getEntries` helper verbatim (16-PATTERNS.md
 * "Opaque vault.entries -> typed Entry[] cast" shared pattern) — reusing the
 * identical cast idiom rather than importing internal core cast functions.
 */
function getEntries(vault: { entries: object } | null): Entry[] {
  if (vault === null) return [];
  const inner = vault.entries as { entries?: Entry[] };
  return Array.isArray(inner.entries) ? inner.entries : [];
}

/**
 * Handle one decrypted `bridge://rpc-request` payload and return the plain
 * JSON result to box+reply with. Exported (in addition to
 * `registerRpcDispatch`) so rpcDispatch.test.ts can drive it directly without
 * mocking the Tauri event system for every case.
 */
export function handleRpcRequest(payload: RpcRequestPayload): unknown {
  const { method, params } = payload;

  // D-09: the renderer is the source of truth for lock state — checked PER
  // REQUEST, never cached. No data crosses the wire when locked (XSEC-05/06).
  if (!vaultSession.isUnlocked) {
    return { code: 'vault-locked' };
  }

  const entries = getEntries(vaultSession.vault);

  if (method === 'match-origin') {
    const origin = typeof params.origin === 'string' ? params.origin : '';
    const candidates = matchByOrigin(entries, origin);

    // HEALTH-02: candidate-scoped weak/reused flags, computed fresh on every
    // call. Deliberately does NOT use the session-scoped healthAudit.svelte.ts
    // store (ensureAuditFresh) — that store stays null until the Health screen
    // has been opened this session, so a match-origin call right after unlock
    // would never show a badge (17-RESEARCH.md "Scoring the whole vault..."
    // pitfall). Score ONLY the matched candidates' source entries — runAudit
    // still needs the FULL active `entries` set for reuse detection (a
    // password group-by; no scoring involved for entries outside the
    // candidate list).
    const weakScores = new Map<string, number>();
    for (const candidate of candidates) {
      const source = entries.find((e) => e.id === candidate.id);
      if (source !== undefined) {
        weakScores.set(source.id, scorePassword(source.password));
      }
    }
    // staleThresholdDays mirrors healthAudit.svelte.ts's `?? 365` default —
    // stale is irrelevant to HEALTH-02 but runAudit requires the option.
    const audit = runAudit(entries, { weakScores, staleThresholdDays: 365 });
    const weakIds = new Set(audit.weak.map((e) => e.id));
    const reusedIds = new Set(audit.reused.map((e) => e.id));

    return {
      candidates: candidates.map((c) => ({
        ...c,
        weak: weakIds.has(c.id),
        reused: reusedIds.has(c.id),
      })),
    };
  }

  if (method === 'fill-entry') {
    const entryId = typeof params.entryId === 'string' ? params.entryId : '';
    const entry = entries.find((e) => e.id === entryId);
    // V4 Access Control: exactly one secret, only for a live (non-tombstoned) id.
    if (entry !== undefined && entry.deletedAt === null) {
      return { secret: entry.password };
    }
    return { code: 'not-found' };
  }

  return { code: 'invalid-request' };
}

/**
 * Register the app-global `bridge://rpc-request` listener.
 *
 * Call ONCE from App.svelte's top-level setup (same tier as
 * `<ExtensionApprovalModal />`) — NEVER from inside the `isUnlocked`-gated
 * $effect (Pitfall 2). Returns the `listen()` unlisten promise so the caller
 * can clean it up alongside the other app-global Tauri listeners.
 */
export function registerRpcDispatch(): Promise<() => void> {
  return listen<RpcRequestPayload>('bridge://rpc-request', async (event) => {
    const result = handleRpcRequest(event.payload);
    await invoke('bridge_rpc_response', { requestId: event.payload.requestId, result });
  });
}
