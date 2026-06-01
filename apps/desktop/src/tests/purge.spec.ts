// apps/desktop/src/tests/purge.spec.ts
//
// Layer-2 component tests for permanent-delete confirmation (TEST-09).
//
// Covers (ENTRY-06 / T-04-28):
//   (a) Triggering permanent-delete shows PurgeConfirm modal without purging the entry.
//   (b) Clicking "Cancel" in PurgeConfirm closes the modal without purging.
//   (c) Clicking "Delete permanently" in PurgeConfirm:
//       - purges the entry from the vault
//       - increments the fake adapter's saveCount
//       - fires the onPurge callback
//
// Security (T-04-28):
//   purgeEntry MUST only fire after explicit confirmation. The spec asserts that
//   the entry is still present before confirming and absent after — locking the
//   destructive-action guard. A regression that deletes on first click fails the test.
//
// Test design:
//   - Use mountVaultSession() for an unlocked session.
//   - Add an entry via vaultSession.addEntry(), render EntryDetail with that entry's ID.
//   - Verify PurgeConfirm appears only after the trash icon is clicked.
//   - Assert the entry count before/after confirmation.

import { test, expect, beforeEach, afterEach, vi } from 'vitest';
import { render } from 'vitest-browser-svelte';
import EntryDetail from '../lib/components/EntryDetail.svelte';
import PurgeConfirm from '../lib/components/PurgeConfirm.svelte';
import { mountVaultSession } from './support/mountVaultSession';
import { ui, vaultSession } from './support/testState';
import { resetMockState } from './support/mockTauriInvoke';
import type { Entry } from '@cryptiq/core';

beforeEach(async () => {
  resetMockState();
  await mountVaultSession();
  ui.toasts = [];
  ui.selectedEntryId = null;
});

afterEach(async () => {
  if (vaultSession.isUnlocked) {
    await vaultSession.lock();
  }
  resetMockState();
});

// ---------------------------------------------------------------------------
// Helper: get the active (non-deleted) entry count from the vault.
// ---------------------------------------------------------------------------

function activeEntryCount(): number {
  const vault = vaultSession.vault;
  if (vault === null) return 0;
  const inner = vault.entries as { entries?: Entry[] };
  return Array.isArray(inner.entries)
    ? inner.entries.filter((e) => e.deletedAt === null).length
    : 0;
}

// ---------------------------------------------------------------------------
// (a) Clicking the permanent-delete button shows the PurgeConfirm modal
// ---------------------------------------------------------------------------

test('(a) permanent-delete button shows PurgeConfirm without purging the entry', async () => {
  const { adapter } = await mountVaultSession();
  const entry = await vaultSession.addEntry({ title: 'Entry to Purge' });
  adapter.saveCount = 0;

  const countBefore = activeEntryCount();
  expect(countBefore).toBeGreaterThan(0);

  const screen = render(EntryDetail, { entryId: entry.id });

  // Wait for the detail pane to render.
  await expect
    .element(screen.getByRole('textbox', { name: /^Title/i }), { timeout: 3_000 })
    .toBeVisible();

  // The PurgeConfirm modal should NOT be in the DOM yet.
  await expect.element(screen.getByRole('alertdialog')).not.toBeInTheDocument();

  // Click the "Delete entry permanently" button (aria-label).
  await screen.getByRole('button', { name: /delete.*permanently/i }).click();

  // PurgeConfirm modal should now be visible.
  await expect.element(screen.getByRole('alertdialog')).toBeVisible();

  // The entry should NOT be purged yet (saveCount unchanged).
  expect(adapter.saveCount).toBe(0);
  expect(activeEntryCount()).toBe(countBefore);
});

// ---------------------------------------------------------------------------
// (b) "Cancel" closes the modal without purging
// ---------------------------------------------------------------------------

test('(b) Cancel in PurgeConfirm closes the modal and keeps the entry intact', async () => {
  const { adapter } = await mountVaultSession();
  const entry = await vaultSession.addEntry({ title: 'Entry to Protect' });
  adapter.saveCount = 0;

  const countBefore = activeEntryCount();

  const screen = render(EntryDetail, { entryId: entry.id });

  await expect
    .element(screen.getByRole('textbox', { name: /^Title/i }), { timeout: 3_000 })
    .toBeVisible();

  // Open the purge modal.
  await screen.getByRole('button', { name: /delete.*permanently/i }).click();
  await expect.element(screen.getByRole('alertdialog')).toBeVisible();

  // Click Cancel.
  await screen.getByRole('button', { name: /cancel/i }).click();

  // Modal should be gone.
  await expect
    .element(screen.getByRole('alertdialog'), { timeout: 2_000 })
    .not.toBeInTheDocument();

  // Entry is still alive.
  expect(adapter.saveCount).toBe(0);
  expect(activeEntryCount()).toBe(countBefore);
});

// ---------------------------------------------------------------------------
// (c) "Delete permanently" confirms purge and triggers save
// ---------------------------------------------------------------------------

test('(c) confirming purge removes the entry and increments saveCount (ENTRY-06)', async () => {
  const { adapter } = await mountVaultSession();
  const entry = await vaultSession.addEntry({ title: 'Entry to Purge For Real' });
  const entryId = entry.id;
  adapter.saveCount = 0;

  const countBefore = activeEntryCount();
  expect(countBefore).toBeGreaterThan(0);

  let purgeCallbackFiredWith: string | null = null;

  const screen = render(EntryDetail, {
    entryId,
    onPurge: (id: string) => {
      purgeCallbackFiredWith = id;
    },
  });

  await expect
    .element(screen.getByRole('textbox', { name: /^Title/i }), { timeout: 3_000 })
    .toBeVisible();

  // Open the purge modal.
  await screen.getByRole('button', { name: /delete.*permanently/i }).click();
  await expect.element(screen.getByRole('alertdialog')).toBeVisible();

  // Confirm by clicking "Delete permanently".
  await screen.getByRole('button', { name: 'Delete permanently' }).click();

  // Wait for the async purge + save to complete.
  await vi.waitFor(() => expect(adapter.saveCount).toBeGreaterThan(0), {
    timeout: 5_000,
  });

  // The entry should now be purged (removed from vault.entries entirely).
  const inner = vaultSession.vault?.entries as { entries?: Entry[] } | undefined;
  const stillExists =
    Array.isArray(inner?.entries) && inner.entries.some((e) => e.id === entryId);
  expect(stillExists).toBe(false);

  // The onPurge callback should have fired with the entry's ID.
  expect(purgeCallbackFiredWith).toBe(entryId);

  // The adapter should have saved once (purgeEntry + save).
  expect(adapter.saveCount).toBeGreaterThan(0);
});

// ---------------------------------------------------------------------------
// PurgeConfirm standalone: confirm/cancel via direct render
// ---------------------------------------------------------------------------

test('PurgeConfirm standalone: onConfirm fires on "Delete permanently" click', async () => {
  let confirmed = false;
  let cancelled = false;

  const screen = render(PurgeConfirm, {
    title: 'My Important Entry',
    onConfirm: () => {
      confirmed = true;
    },
    onCancel: () => {
      cancelled = true;
    },
  });

  // The dialog is visible by default when mounted.
  await expect.element(screen.getByRole('alertdialog')).toBeVisible();

  // Entry title is shown in the description.
  await expect.element(screen.getByText('My Important Entry')).toBeVisible();

  // Click Delete permanently.
  await screen.getByRole('button', { name: 'Delete permanently' }).click();
  expect(confirmed).toBe(true);
  expect(cancelled).toBe(false);
});

test('PurgeConfirm standalone: onCancel fires on Cancel click', async () => {
  let confirmed = false;
  let cancelled = false;

  const screen = render(PurgeConfirm, {
    title: 'Test Entry',
    onConfirm: () => {
      confirmed = true;
    },
    onCancel: () => {
      cancelled = true;
    },
  });

  await screen.getByRole('button', { name: /cancel/i }).click();
  expect(cancelled).toBe(true);
  expect(confirmed).toBe(false);
});
