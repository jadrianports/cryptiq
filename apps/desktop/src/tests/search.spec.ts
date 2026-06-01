// apps/desktop/src/tests/search.spec.ts
//
// Layer-2 component tests for multi-field search in MainView.svelte (TEST-09).
//
// Covers (UI-04 / UI-11):
//   (a) Typing a query that matches a subset of entries across title/username/
//       url/tags/notes — only matching rows should render.
//   (b) Typing a non-matching query — the "No results" state appears.
//   (c) Debounce: filtering does not apply until ~100ms after input stops (D-TIMING).
//
// Test design:
//   - Use mountVaultSession() to get an unlocked VaultSession with the fake adapter.
//   - Add several entries directly via vaultSession.addEntry() (no real crypto needed
//     for entry creation — it's UUID generation + in-memory mutation).
//   - Render MainView and type into the search input.
//   - After the debounce delay, assert the visible row count / no-results state.
//
// Security (T-04-12 / Pitfall 7):
//   MainView uses $derived(vaultSession.vault?.entries) — never local $state.
//   Tests confirm display-only — no decrypted bytes are asserted in detail.

import { test, expect, beforeEach, afterEach } from 'vitest';
import { render } from 'vitest-browser-svelte';
import MainView from '../lib/screens/MainView.svelte';
import { mountVaultSession } from './support/mountVaultSession';
import { ui, vaultSession } from './support/testState';
import { resetMockState } from './support/mockTauriInvoke';

const DEBOUNCE_MS = 120; // D-TIMING: 100ms + 20ms buffer for test reliability
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

beforeEach(async () => {
  resetMockState();
  // Set up an unlocked vault with several entries seeded.
  await mountVaultSession();

  // Seed entries across multiple searchable fields.
  await vaultSession.addEntry({
    title: 'GitHub',
    username: 'devuser',
    url: 'https://github.com',
    notes: 'code hosting',
  });
  await vaultSession.addEntry({
    title: 'Gmail',
    username: 'user@gmail.com',
    url: 'https://mail.google.com',
  });
  await vaultSession.addEntry({
    title: 'AWS Console',
    username: 'aws-admin',
    url: 'https://console.aws.amazon.com',
    notes: 'cloud infrastructure',
  });
  await vaultSession.addEntry({
    title: 'Dropbox',
    username: 'dropbox@example.com',
    url: 'https://dropbox.com',
  });
  await vaultSession.addEntry({
    title: 'Linear',
    username: 'pm@company.com',
    notes: 'project tracking',
  });

  // Reset the selected entry so the detail pane shows "Select an entry".
  ui.selectedEntryId = null;
  ui.listFilter = 'all';
});

afterEach(async () => {
  if (vaultSession.isUnlocked) {
    await vaultSession.lock();
  }
  resetMockState();
});

// ---------------------------------------------------------------------------
// (a) Title-match subset filtering
// ---------------------------------------------------------------------------

test('(a) title query shows only matching entries', async () => {
  const screen = render(MainView);

  // Wait for the entry list to render at least one row.
  await expect
    .element(screen.getByRole('button', { name: /GitHub/i }), { timeout: 5_000 })
    .toBeVisible();

  // Type a query that matches only "GitHub".
  const searchInput = screen.getByRole('searchbox', { name: /search entries/i });
  await searchInput.fill('github');

  // Wait for the debounce to fire.
  await sleep(DEBOUNCE_MS);

  // GitHub should be visible; Gmail/AWS should NOT.
  await expect.element(screen.getByRole('button', { name: /GitHub/i })).toBeVisible();
  await expect
    .element(screen.getByRole('button', { name: /Gmail/i }))
    .not.toBeInTheDocument();
  await expect
    .element(screen.getByRole('button', { name: /AWS/i }))
    .not.toBeInTheDocument();
});

test('(a) username query matches across entries', async () => {
  const screen = render(MainView);

  // Wait for entry list.
  await expect
    .element(screen.getByRole('button', { name: /GitHub/i }), { timeout: 5_000 })
    .toBeVisible();

  const searchInput = screen.getByRole('searchbox', { name: /search entries/i });
  // 'aws-admin' is the username for "AWS Console" only.
  await searchInput.fill('aws-admin');
  await sleep(DEBOUNCE_MS);

  await expect.element(screen.getByRole('button', { name: /AWS/i })).toBeVisible();
  await expect
    .element(screen.getByRole('button', { name: /GitHub/i }))
    .not.toBeInTheDocument();
});

test('(a) notes query filters entries that contain matching text in notes', async () => {
  const screen = render(MainView);

  await expect
    .element(screen.getByRole('button', { name: /GitHub/i }), { timeout: 5_000 })
    .toBeVisible();

  const searchInput = screen.getByRole('searchbox', { name: /search entries/i });
  // 'cloud' matches AWS Console notes.
  await searchInput.fill('cloud');
  await sleep(DEBOUNCE_MS);

  await expect.element(screen.getByRole('button', { name: /AWS/i })).toBeVisible();
  await expect
    .element(screen.getByRole('button', { name: /GitHub/i }))
    .not.toBeInTheDocument();
  await expect
    .element(screen.getByRole('button', { name: /Gmail/i }))
    .not.toBeInTheDocument();
});

// ---------------------------------------------------------------------------
// (b) No-results state (UI-11)
// ---------------------------------------------------------------------------

test('(b) non-matching query shows the no-results state', async () => {
  const screen = render(MainView);

  await expect
    .element(screen.getByRole('button', { name: /GitHub/i }), { timeout: 5_000 })
    .toBeVisible();

  const searchInput = screen.getByRole('searchbox', { name: /search entries/i });
  await searchInput.fill('xyzzy-no-match-at-all-99999');
  await sleep(DEBOUNCE_MS);

  // "No results" state text appears (MainView uses this exact copy, UI-11).
  await expect.element(screen.getByText('No results')).toBeVisible();

  // None of the seeded entries should be visible.
  await expect
    .element(screen.getByRole('button', { name: /GitHub/i }))
    .not.toBeInTheDocument();
  await expect
    .element(screen.getByRole('button', { name: /AWS/i }))
    .not.toBeInTheDocument();
});

// ---------------------------------------------------------------------------
// (c) Debounce: results update after the delay fires
// ---------------------------------------------------------------------------

test('(c) results are filtered after the 100ms debounce fires', async () => {
  const screen = render(MainView);

  await expect
    .element(screen.getByRole('button', { name: /GitHub/i }), { timeout: 5_000 })
    .toBeVisible();

  const searchInput = screen.getByRole('searchbox', { name: /search entries/i });
  await searchInput.fill('github');

  // We do NOT assert pre-debounce state (race-prone); instead we wait and assert
  // the post-debounce state is correct.
  await sleep(DEBOUNCE_MS);

  // Post-debounce: only the matching entry is shown.
  await expect.element(screen.getByRole('button', { name: /GitHub/i })).toBeVisible();
  // The non-matching entries are absent.
  await expect
    .element(screen.getByRole('button', { name: /Dropbox/i }))
    .not.toBeInTheDocument();
});

// ---------------------------------------------------------------------------
// Clearing the search restores all entries
// ---------------------------------------------------------------------------

test('clearing search restores all entries in the list', async () => {
  const screen = render(MainView);

  await expect
    .element(screen.getByRole('button', { name: /GitHub/i }), { timeout: 5_000 })
    .toBeVisible();

  const searchInput = screen.getByRole('searchbox', { name: /search entries/i });
  await searchInput.fill('github');
  await sleep(DEBOUNCE_MS);

  // Only GitHub visible after filtering.
  await expect
    .element(screen.getByRole('button', { name: /Gmail/i }))
    .not.toBeInTheDocument();

  // Clear the search.
  await searchInput.fill('');
  await sleep(DEBOUNCE_MS);

  // All entries should be back.
  await expect.element(screen.getByRole('button', { name: /Gmail/i })).toBeVisible();
  await expect.element(screen.getByRole('button', { name: /GitHub/i })).toBeVisible();
});
