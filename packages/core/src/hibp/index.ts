// packages/core/src/hibp/index.ts
//
// Fail-closed orchestrator for the HIBP k-anonymity range lookup (D-04, D-07).
//
// `lookupHibpRange` takes an INJECTED `invoke`-shaped function (mirrors the
// `VaultStorageAdapter` injection precedent in storage/ — keeps this module
// Tauri-free per CLAUDE.md's "packages/core cannot import @tauri-apps/*" rule).
// It computes the SHA-1 hash, splits prefix/suffix, calls the injected `invoke`
// with the 5-char prefix AND a REQUIRED purpose discriminator, and locally
// matches the returned raw response text against the suffix.
//
// D-04: ANY rejection from the injected `invoke` (network unreachable, timeout,
// non-200, malformed body, or any other thrown/rejected value) is wrapped and
// re-thrown as a typed `HibpLookupError` — NEVER interpreted as "not breached."
// D-05: no retry/backoff here — this seam is one-shot by design.
//
// DEBT-01/W-1 (Phase 36, D-13): `purpose` is REQUIRED, not optional with a default — a
// defaulted purpose is the same class of silent-wrong as a defaulted fail-direction (see
// config_guard.rs's doc-comment). The Rust `hibp_range_lookup` command enforces consent for
// the stated purpose AT THE SEAM; this function's job is only to forward the caller's purpose
// unchanged, never to guess or default it.
//
// Core purity: no @tauri-apps/*, svelte, node:fs, node:path imports. No
// console.*, no Math.random, no Date.now().

import { HibpLookupError } from '../errors';
import { sha1Hex } from './hash';
import { matchesSuffix, splitPrefixSuffix } from './kanon';
import type { HibpInvoke, HibpLookupPurpose } from './types';

export type { HibpInvoke, HibpLookupPurpose } from './types';

/**
 * Looks up whether `password` appears in the HIBP Pwned Passwords range response,
 * via the injected `invoke` (which must call the Rust `hibp_range_lookup` shuttle
 * command in production). Resolves `true`/`false` only on a successful round trip;
 * ANY failure throws `HibpLookupError` (fail-closed, D-04) — this function NEVER
 * resolves `false` on a network/transport error.
 *
 * @param purpose REQUIRED — 'entry-scan' or 'master-check' (Phase 36, D-13). Forwarded
 *                unchanged to the Rust seam guard, which refuses egress unless the config
 *                field governing THIS purpose is explicitly true. Never defaulted here.
 */
export async function lookupHibpRange(
  password: string,
  invoke: HibpInvoke,
  purpose: HibpLookupPurpose,
): Promise<boolean> {
  const { prefix, suffix } = splitPrefixSuffix(sha1Hex(password));

  let responseText: string;
  try {
    responseText = await invoke('hibp_range_lookup', { prefix, purpose });
  } catch (cause) {
    const reason = typeof cause === 'string' ? cause : cause instanceof Error ? cause.message : undefined;
    throw new HibpLookupError('HIBP range lookup failed', reason);
  }

  const lines = responseText.split(/\r?\n/).filter((line) => line.length > 0);
  return matchesSuffix(lines, suffix);
}
