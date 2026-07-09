// apps/desktop/src/tests/totpTransition.spec.ts
//
// Regression test for debug session totp-section-stale-ui.
//
// TotpSection.spec.ts mounts the component with `totp` already set (or already
// undefined) as a fixed prop — it can never observe a TRANSITION, which is
// exactly why 546 green core tests, a green component suite, and a passing
// verifier all missed this bug. This spec drives the SAME EntryDetail instance
// (no re-selecting the entry, no remount) through a real save and a real
// remove, and asserts the rendered view transitions immediately both times.
//
// Root cause (see .planning/debug/resolved/totp-section-stale-ui.md):
// TotpSection's `totp` prop was bound directly to `entry?.totp`, where `entry`
// is a Svelte 5 $derived over vaultSession.vault. crud.ts's updateEntry
// mutates the Entry object in place (locked DC-8/P3-02 pattern), so on a
// same-entry save/remove the `entry` derived recomputes to the IDENTICAL
// object reference and Svelte never re-notifies dependents reading
// `entry?.totp`. Fix: EntryDetail now keeps a local `totp` $state mirror
// (same pattern as title/username/card/identity), updated explicitly by
// persistTotp/removeTotp.

import { test, expect, beforeEach, afterEach } from 'vitest';
import { render } from 'vitest-browser-svelte';
import EntryDetail from '../lib/components/EntryDetail.svelte';
import { mountVaultSession } from './support/mountVaultSession';
import { ui, vaultSession } from './support/testState';
import { resetMockState } from './support/mockTauriInvoke';

const AUTO_SAVE_DEBOUNCE_MS = 600; // D-TIMING: 500ms blur debounce + 100ms buffer
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

// RFC 6238 public test vector — not a real secret.
const VALID_BASE32_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

beforeEach(async () => {
  resetMockState();
  await mountVaultSession();
  ui.selectedEntryId = null;
  ui.listFilter = 'all';
  ui.toasts = [];
});

afterEach(async () => {
  if (vaultSession.isUnlocked) {
    await vaultSession.lock();
  }
  resetMockState();
});

test('save transitions TotpSection to the filled view WITHOUT re-selecting the entry', async () => {
  const entry = await vaultSession.addEntry({ title: 'Regression Entry' });

  const screen = render(EntryDetail, { entryId: entry.id });

  // Empty state renders first — the entry has no totp yet.
  await expect.element(screen.getByText('No 2FA code yet')).toBeVisible();

  const pasteInput = screen.getByPlaceholder('Paste otpauth:// link or setup key');
  await expect.element(pasteInput).toBeVisible();
  await pasteInput.fill(VALID_BASE32_SECRET);
  (pasteInput.element() as HTMLInputElement).blur();

  // Preview renders before save.
  await expect.element(screen.getByText('SHA1')).toBeVisible();

  await screen.getByRole('button', { name: 'Save code' }).click();

  // THE REGRESSION: without re-selecting the entry, the section must show the
  // filled view immediately — never "No 2FA code yet" and never the raw preview.
  await expect
    .element(screen.getByRole('button', { name: 'Copy 2FA code' }), { timeout: 3_000 })
    .toBeVisible();
  await expect.element(screen.getByText('No 2FA code yet')).not.toBeInTheDocument();

  // Persistence sanity: the mutation actually landed in the vault (data-layer
  // correctness was never in question, per the debug session, but assert it
  // anyway so this test also guards against a regression there).
  await sleep(AUTO_SAVE_DEBOUNCE_MS);
  const persisted = vaultSession
    .vault!.entries as unknown as { entries: Array<{ id: string; totp?: unknown }> };
  const persistedEntry = persisted.entries.find((e) => e.id === entry.id);
  expect(persistedEntry?.totp).toBeDefined();
});

test('remove transitions TotpSection to the empty state immediately after confirm', async () => {
  const entry = await vaultSession.addEntry({
    title: 'Regression Entry 2',
    totp: {
      secret: VALID_BASE32_SECRET,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
    },
  });

  const screen = render(EntryDetail, { entryId: entry.id });

  // Filled view renders first.
  await expect
    .element(screen.getByRole('button', { name: 'Copy 2FA code' }), { timeout: 3_000 })
    .toBeVisible();

  await screen.getByRole('button', { name: 'Remove 2FA code' }).click();
  await expect.element(screen.getByRole('alertdialog')).toBeVisible();
  await screen
    .getByRole('alertdialog')
    .getByRole('button', { name: 'Remove 2FA code' })
    .click();

  // THE REGRESSION: without re-selecting the entry, the section must show the
  // empty state immediately — never a lingering live/rotating code.
  await expect.element(screen.getByText('No 2FA code yet'), { timeout: 3_000 }).toBeVisible();
  await expect
    .element(screen.getByRole('button', { name: 'Copy 2FA code' }))
    .not.toBeInTheDocument();

  await sleep(AUTO_SAVE_DEBOUNCE_MS);
  const persisted = vaultSession
    .vault!.entries as unknown as { entries: Array<{ id: string; totp?: unknown }> };
  const persistedEntry = persisted.entries.find((e) => e.id === entry.id);
  expect(persistedEntry?.totp).toBeUndefined();
});
