// apps/desktop/src/tests/unlock.spec.ts
//
// Layer-2 component tests for UnlockScreen.svelte (TEST-09).
//
// Covers:
//   (a) Correct master password → view transitions to 'main' (unlock success)
//   (b) Wrong master password   → SINGLE generic error message (AUTH-07 / P4-09)
//   (c) Wrong recovery key      → THE SAME generic string as (b) — oracle defense
//
// Security invariant (T-04-26):
//   Wrong-password and wrong-recovery-key must produce an IDENTICAL error message.
//   A regression that reveals which path failed would break the AUTH-07 contract.
//
// Harness: Vitest browser mode + vitest-browser-svelte (Playwright provider). The spec
// and the rendered component share one realm, so `view`/`vaultSession` singletons are
// the same instances the component mutates. See vitest.browser.config.ts.
//
// Note: The real Argon2id KDF runs during mountVaultSession() setup (~1 s). This
// is acceptable — it is the minimum verifiable cost and uses floor params (256MiB/3ops).

import { test, expect, beforeEach, afterEach, vi } from 'vitest';
import { render } from 'vitest-browser-svelte';
import UnlockScreen from '../lib/screens/UnlockScreen.svelte';
import { mountVaultSession } from './support/mountVaultSession';
import { vaultSession, view } from './support/testState';
import {
  setMockVaultBytes,
  setMockVaultPath,
  resetMockState,
} from './support/mockTauriInvoke';
import { mapUnlockError } from '../lib/util/errors';
import { WrongPasswordError, WrongRecoveryKeyError } from '@cryptiq/core';

// ---------------------------------------------------------------------------
// Shared setup: create a test vault once per test.
// The vault bytes are captured before locking, then seeded into the FS mock.
// ---------------------------------------------------------------------------

let vaultBytes: Uint8Array | null = null;

beforeEach(async () => {
  resetMockState();

  // Create a fresh test vault and capture the bytes create() wrote. (A second
  // vaultSession.save() here would be skipped by the content-hash dedup — the vault
  // is unchanged since creation — so we take the bytes from the create() save itself.)
  const { vaultBytes: createdBytes } = await mountVaultSession('/fake/vault.cryptiq');
  vaultBytes = createdBytes;

  // Lock the session — unlock tests start from a locked state.
  await vaultSession.lock();

  // Seed the mock FS with the vault bytes so TauriVaultStorageAdapter.load() works.
  setMockVaultPath('/fake/vault.cryptiq');
  if (vaultBytes) {
    setMockVaultBytes(vaultBytes);
  }
});

afterEach(async () => {
  // Ensure the session is locked after each test (avoid state bleed).
  if (vaultSession.isUnlocked) {
    await vaultSession.lock();
  }
  resetMockState();
  setMockVaultBytes(null);
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test('(a) correct master password unlocks and navigates to main', async () => {
  const screen = render(UnlockScreen);

  // Find the password field and submit button.
  const passwordInput = screen.getByLabelText('Master password');
  const unlockButton = screen.getByRole('button', { name: 'Unlock', exact: true });

  // Type the test master password (matches the one used in mountVaultSession).
  await passwordInput.fill('test-master-pw');
  await expect.element(unlockButton).toBeEnabled();

  // Submit the form.
  await unlockButton.click();

  // After success, go('main') is called — assert the shared view state changed.
  await vi.waitFor(() => expect(view.current).toBe('main'), { timeout: 10_000 });
});

test('(b) wrong master password shows the generic error message', async () => {
  const screen = render(UnlockScreen);

  const passwordInput = screen.getByLabelText('Master password');
  const unlockButton = screen.getByRole('button', { name: 'Unlock', exact: true });

  // Enter a deliberately wrong password.
  await passwordInput.fill('wrong-password-xyz');
  await unlockButton.click();

  // Assert the generic error string appears (mapUnlockError / AUTH-07).
  const expectedMsg = mapUnlockError(new WrongPasswordError('wrong pw'));
  await expect
    .element(screen.getByRole('alert'), { timeout: 10_000 })
    .toHaveTextContent(expectedMsg);
});

test('(c) wrong recovery key shows THE SAME generic error as wrong password (AUTH-07 oracle defense)', async () => {
  const screen = render(UnlockScreen);

  // ── Wrong password path ────────────────────────────────────────────────
  const passwordInput = screen.getByLabelText('Master password');
  const unlockButton = screen.getByRole('button', { name: 'Unlock', exact: true });

  await passwordInput.fill('wrong-password-xyz');
  await unlockButton.click();

  const alertEl = screen.getByRole('alert');
  await expect.element(alertEl, { timeout: 10_000 }).toBeVisible();
  const wrongPasswordMsg = alertEl.element().textContent;

  // ── Recovery key path ──────────────────────────────────────────────────
  // Navigate to recovery mode.
  const recoveryToggle = screen.getByRole('button', {
    name: /unlock with recovery key/i,
  });
  await recoveryToggle.click();

  const recoveryTextarea = screen.getByLabelText('Recovery key');
  await recoveryTextarea.fill('ABCD-1234-WRONG-KEY-THAT-IS-INVALID');
  // The submit button shares the /unlock with recovery key/i name — use the last one.
  await screen
    .getByRole('button', { name: /unlock with recovery key/i })
    .last()
    .click();

  await expect.element(screen.getByRole('alert'), { timeout: 10_000 }).toBeVisible();
  const wrongRecoveryMsg = screen.getByRole('alert').element().textContent;

  // ── AUTH-07 oracle defense assertion ────────────────────────────────────
  // Both paths MUST yield an identical message — revealing which path failed is a
  // security bug (T-04-26 / P4-09).
  expect(wrongPasswordMsg?.trim()).toBe(wrongRecoveryMsg?.trim());

  // Also assert against the canonical string from mapUnlockError so a rename
  // to a path-specific string would fail the test.
  const canonicalMsg = mapUnlockError(new WrongPasswordError(''));
  const canonicalRecoveryMsg = mapUnlockError(new WrongRecoveryKeyError(''));
  expect(canonicalMsg).toBe(canonicalRecoveryMsg);
});
