// apps/desktop/src/tests/entry.spec.ts
//
// Layer-2 component tests for entry create/edit in EntryDetail.svelte (TEST-09).
//
// Covers (P4-14 / P4-11 / UI-12):
//   (a) Create: "+ New" via MainView produces a blank form that renders (P4-14).
//   (b) Title-required gate: blurring an empty title does NOT trigger a save.
//   (c) Edit: blurring a field calls vaultSession.updateEntry, increments the
//       fake adapter's saveCount, and pushes a 'Saved' toast onto ui.toasts (UI-12).
//
// Test design:
//   - Use mountVaultSession() for an unlocked session with the fake adapter.
//   - For the create test: render MainView, click New, assert the form opens.
//   - For edit tests: add an entry via vaultSession.addEntry(), render EntryDetail
//     with that entry's ID, blur a field, then assert the save pipeline ran.
//   - The 'Saved' toast is asserted via the shared ui.toasts queue (state, not DOM)
//     because the Toast component's auto-dismiss timer is not wired in these mounts.

import { test, expect, beforeEach, afterEach } from 'vitest';
import { render } from 'vitest-browser-svelte';
import EntryDetail from '../lib/components/EntryDetail.svelte';
import MainView from '../lib/screens/MainView.svelte';
import { mountVaultSession } from './support/mountVaultSession';
import { ui, vaultSession } from './support/testState';
import { resetMockState } from './support/mockTauriInvoke';

const AUTO_SAVE_DEBOUNCE_MS = 600; // D-TIMING: 500ms blur debounce + 100ms buffer
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

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

// ---------------------------------------------------------------------------
// (a) Create: "+ New" via MainView opens a form
// ---------------------------------------------------------------------------

test('(a) "+ New" button adds a blank entry and selects it in the detail pane', async () => {
  const screen = render(MainView);

  // The vault is empty: empty-vault state should show.
  await expect
    .element(screen.getByText('Your vault is empty'), { timeout: 5_000 })
    .toBeVisible();

  // Click the "+ New" button (aria-label="New entry").
  const newButton = screen.getByRole('button', { name: 'New entry' });
  await expect.element(newButton).toBeVisible();
  await newButton.click();

  // After addEntry(), the detail pane opens with a title field visible.
  const titleField = screen.getByRole('textbox', { name: /title/i }).first();
  await expect.element(titleField, { timeout: 3_000 }).toBeVisible();
});

// ---------------------------------------------------------------------------
// (b) Title-required gate (P4-14)
// ---------------------------------------------------------------------------

test('(b) title-required gate: blurring an empty title does NOT trigger a save', async () => {
  // Use a fresh mount with its own adapter to get the spy.
  const { adapter } = await mountVaultSession();
  ui.toasts = [];

  const entry = await vaultSession.addEntry({ title: 'Test Entry' });
  adapter.saveCount = 0;

  const screen = render(EntryDetail, { entryId: entry.id });

  // Wait for the entry to render.
  const titleField = screen.getByRole('textbox', { name: /^Title/i }).first();
  await expect.element(titleField, { timeout: 3_000 }).toBeVisible();

  // Clear the title field and blur it.
  await titleField.fill('');
  (titleField.element() as HTMLElement).blur();

  // Wait for potential debounce.
  await sleep(AUTO_SAVE_DEBOUNCE_MS);

  // EntryDetail's handleTitleBlur() returns early when title is empty (P4-14).
  // No save should have occurred.
  expect(adapter.saveCount).toBe(0);

  // No 'Saved' toast should appear.
  const savedToasts = ui.toasts.filter((t) => t.msg === 'Saved');
  expect(savedToasts).toHaveLength(0);
});

// ---------------------------------------------------------------------------
// (c) Edit: blur triggers updateEntry + save + 'Saved' toast (UI-12 / P4-11)
// ---------------------------------------------------------------------------

test('(c) blurring title field triggers updateEntry and the Saved toast (UI-12)', async () => {
  const { adapter } = await mountVaultSession();
  ui.toasts = [];

  const entry = await vaultSession.addEntry({ title: 'Original Title' });

  // Reset the save counter AFTER adding the entry.
  adapter.saveCount = 0;
  adapter.lastSavedBytes = null;

  const screen = render(EntryDetail, { entryId: entry.id });

  const titleField = screen.getByRole('textbox', { name: /^Title/i }).first();
  await expect.element(titleField, { timeout: 3_000 }).toBeVisible();

  // Edit the title field.
  await titleField.fill('Updated Title');

  // Blur the field to trigger auto-save.
  (titleField.element() as HTMLElement).blur();

  // Wait for the 500ms auto-save debounce to fire.
  await sleep(AUTO_SAVE_DEBOUNCE_MS);

  // The adapter should have saved (saveCount > 0 after a successful field edit).
  expect(adapter.saveCount).toBeGreaterThan(0);

  // The 'Saved' toast should appear in the ui.toasts queue (UI-12).
  const savedToasts = ui.toasts.filter((t) => t.msg === 'Saved');
  expect(savedToasts.length).toBeGreaterThan(0);
});

test('(c) blurring username field triggers save and Saved toast', async () => {
  const { adapter } = await mountVaultSession();
  ui.toasts = [];

  const entry = await vaultSession.addEntry({
    title: 'Test Entry',
    username: 'olduser',
  });
  adapter.saveCount = 0;

  const screen = render(EntryDetail, { entryId: entry.id });

  const usernameField = screen
    .getByRole('textbox', { name: /^Username/i })
    .first();
  await expect.element(usernameField, { timeout: 3_000 }).toBeVisible();

  await usernameField.fill('newuser@example.com');
  (usernameField.element() as HTMLElement).blur();

  await sleep(AUTO_SAVE_DEBOUNCE_MS);

  expect(adapter.saveCount).toBeGreaterThan(0);
  expect(ui.toasts.some((t) => t.msg === 'Saved')).toBe(true);
});
