// apps/desktop/src/tests/ExtensionSettingsSection.spec.ts
//
// Layer-2 component tests for ExtensionSettingsSection.svelte (BRIDGE-09).
//
// Covers (15-05-PLAN.md Task 2 acceptance criteria):
//   (a) The section lists associations seeded into the store via extensionPeerStore.init().
//   (b) Rename updates a label (persisted via rename_extension_association + local reassign).
//   (c) The revoke button opens the inline confirm panel, then calls revoke on confirm.
//
// Test environment: Vitest browser mode (Playwright/Chromium) — see vitest.browser.config.ts.
// Tauri: @tauri-apps/api/core is aliased to mockTauriInvoke.ts (real invoke() names handled
// there: extension_peers_list / rename_extension_association / revoke_extension_association_cmd).

import { test, expect, beforeEach, afterEach } from 'vitest';
import { render } from 'vitest-browser-svelte';
import { userEvent } from '@vitest/browser/context';
import ExtensionSettingsSection from '../lib/bridge/ExtensionSettingsSection.svelte';
import { extensionPeerStore } from '../lib/bridge/ExtensionPeerStore.svelte';
import { resetMockState, setMockExtensionAssociations } from './support/mockTauriInvoke';

const CONFIG_DIR = '/fake/config';

beforeEach(() => {
  resetMockState();
  extensionPeerStore.reset();
});

afterEach(() => {
  resetMockState();
  extensionPeerStore.reset();
});

test('(a) lists associations seeded into the store', async () => {
  setMockExtensionAssociations([
    {
      clientId: 'client-a',
      clientPublicKey: 'aabbccdd',
      label: 'Chrome',
      pairedAt: '2026-07-01T00:00:00.000Z',
      lastUsedAt: null,
      pairingTokenHash: 'deadbeef',
    },
  ]);
  await extensionPeerStore.init(CONFIG_DIR);

  const screen = render(ExtensionSettingsSection, { configDir: CONFIG_DIR });

  await expect.element(screen.getByText('Chrome')).toBeInTheDocument();
});

test('(b) rename updates the label', async () => {
  setMockExtensionAssociations([
    {
      clientId: 'client-a',
      clientPublicKey: 'aabbccdd',
      label: 'Chrome',
      pairedAt: '2026-07-01T00:00:00.000Z',
      lastUsedAt: null,
      pairingTokenHash: 'deadbeef',
    },
  ]);
  await extensionPeerStore.init(CONFIG_DIR);

  const screen = render(ExtensionSettingsSection, { configDir: CONFIG_DIR });

  const renameButton = screen.getByLabelText('Rename Chrome');
  await renameButton.click();

  const input = screen.getByLabelText('Rename Chrome');
  await input.fill('Chrome (work)');
  await userEvent.keyboard('{Enter}');

  await expect.element(screen.getByText('Chrome (work)')).toBeInTheDocument();
  expect(extensionPeerStore.associations[0]?.label).toBe('Chrome (work)');
});

test('(c) revoke opens the confirm panel then removes the association on confirm', async () => {
  setMockExtensionAssociations([
    {
      clientId: 'client-a',
      clientPublicKey: 'aabbccdd',
      label: 'Chrome',
      pairedAt: '2026-07-01T00:00:00.000Z',
      lastUsedAt: null,
      pairingTokenHash: 'deadbeef',
    },
  ]);
  await extensionPeerStore.init(CONFIG_DIR);

  const screen = render(ExtensionSettingsSection, { configDir: CONFIG_DIR });

  // Revoke button opens the inline confirm panel — not an instant removal (D-04).
  await screen.getByText('Revoke', { exact: true }).click();
  await expect.element(screen.getByText('Revoke Chrome?')).toBeInTheDocument();
  expect(extensionPeerStore.associations).toHaveLength(1);

  // Confirming actually calls revoke and removes the row.
  await screen.getByText('Revoke Chrome', { exact: true }).click();

  expect(extensionPeerStore.associations).toHaveLength(0);
});
