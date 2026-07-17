// apps/desktop/src/tests/HibpConsentSeamBypass.spec.ts
//
// Phase 36 (DEBT-01/W-1) proof: a caller reaching lookupHibpRange DIRECTLY, bypassing every
// UI-level consent check (breachAudit.svelte.ts / ChangeMasterView.svelte / FirstRunWizard.svelte
// all stay untouched here — this simulates a FUTURE second caller that skips them entirely, the
// exact scenario W-1 warned about), must still be refused by the Rust-side seam guard when
// consent for its stated purpose is off. This is the test that would have caught W-1 before this
// phase closed it — no dialog, no toggle, no button click, just the seam itself.
//
// Test environment: Vitest browser mode (see vitest.browser.config.ts — this file lives at
// src/tests/*.spec.ts, the ONLY glob the browser config includes). @tauri-apps/api/core is
// aliased to mockTauriInvoke.ts, whose hibp_range_lookup handler models the real hibp.rs
// fail-closed consent-seam guard (Task 2 of this plan) — see that file's header comment.

import { test, expect, beforeEach, afterEach } from 'vitest';
import { lookupHibpRange, HibpLookupError } from '@cryptiq/core';
import { hibpInvoke } from '../lib/adapters/hibpInvoke';
import { resetMockState, setMockConfigFlags } from './support/mockTauriInvoke';

beforeEach(() => {
  resetMockState();
});

afterEach(() => {
  resetMockState();
});

test('lookupHibpRange called directly with consent OFF is refused at the seam, never resolves a breach verdict (W-1)', async () => {
  setMockConfigFlags({ hibpEntryScanEnabled: false });

  // No UI, no dialog, no toggle — the DIRECT call a future second caller would make, exactly
  // the bypass W-1 describes. The seam must refuse regardless of who is calling it.
  let caught: unknown = null;
  try {
    await lookupHibpRange('some-password', hibpInvoke, 'entry-scan');
  } catch (err) {
    caught = err;
  }

  expect(caught).toBeInstanceOf(HibpLookupError);
  // The rejection must carry the specific consent-denial reason, not merely "some error" — a
  // caller must never read this as "no breaches found" (D-04's contract extended to consent).
  expect((caught as HibpLookupError).reason).toBe('hibp_consent_denied');
});

test('an unseeded/empty config (fail-closed default) also refuses — absence is never consent', async () => {
  // setMockConfigFlags is never called — _mockConfigFlags stays {} after resetMockState(),
  // mirroring a pre-consent install with no config.json at all (or one missing this field).
  let caught: unknown = null;
  try {
    await lookupHibpRange('some-password', hibpInvoke, 'master-check');
  } catch (err) {
    caught = err;
  }

  expect(caught).toBeInstanceOf(HibpLookupError);
  expect((caught as HibpLookupError).reason).toBe('hibp_consent_denied');
});

test('the SAME direct call succeeds once the governing purpose-specific consent flag is explicitly true', async () => {
  // Proves the guard is genuinely purpose-scoped, not a blanket refusal: entry-scan consent
  // alone does NOT authorize a master-check call (Phase 31 D-16 independence), but the matching
  // purpose does let the call through to the (mocked, default no-match) response.
  setMockConfigFlags({ hibpEntryScanEnabled: true });

  await expect(lookupHibpRange('some-password', hibpInvoke, 'entry-scan')).resolves.toBe(false);

  let caught: unknown = null;
  try {
    await lookupHibpRange('some-password', hibpInvoke, 'master-check');
  } catch (err) {
    caught = err;
  }
  expect(caught).toBeInstanceOf(HibpLookupError);
  expect((caught as HibpLookupError).reason).toBe('hibp_consent_denied');
});
