// apps/desktop/src/tests/HibpSettingsSection.spec.ts
//
// Layer-2 component tests for HibpSettingsSection.svelte + HibpConsentDialog.svelte
// (HIBP-01, 31-03-PLAN.md Task 2 acceptance criteria).
//
// Covers:
//   (a) default-OFF render — aria-checked="false" when hibpEntryScanEnabled is
//       false/absent (mirrors a pre-Phase-31 config.json).
//   (b) clicking the OFF toggle opens the disclosure dialog and does NOT yet
//       persist — getLastSavedConfig() shows no hibpEntryScanEnabled: true and
//       the toggle has not flipped.
//   (c) clicking "Not now" closes the dialog with the toggle still OFF and no
//       saveConfig with hibpEntryScanEnabled: true.
//   (d) clicking "Enable breach checking" makes
//       getLastSavedConfig().hibpEntryScanEnabled === true and flips the toggle ON.
//   (e) the dialog body copy contains the exact required disclosure facts.
//
// Test environment: Vitest browser mode (see vitest.browser.config.ts — this file
// lives at src/tests/*.spec.ts, the ONLY glob the browser config includes).
// Tauri: @tauri-apps/api/core is aliased to mockTauriInvoke.ts.

import { test, expect, beforeEach, afterEach } from 'vitest';
import { render } from 'vitest-browser-svelte';
import HibpSettingsSection from '../lib/hibp/HibpSettingsSection.svelte';
import { resetMockState, setMockConfigFlags, getLastSavedConfig } from './support/mockTauriInvoke';

beforeEach(() => {
  resetMockState();
});

afterEach(() => {
  resetMockState();
});

test('(a) toggle renders OFF (aria-checked="false") by default', async () => {
  setMockConfigFlags({ hibpEntryScanEnabled: false });

  const screen = render(HibpSettingsSection);

  const toggle = screen.getByRole('switch', { name: 'Check passwords against known breaches' });
  await expect.element(toggle).toBeInTheDocument();
  await expect.element(toggle).toHaveAttribute('aria-checked', 'false');
});

test('(b) clicking the OFF toggle opens the disclosure dialog without persisting', async () => {
  setMockConfigFlags({ hibpEntryScanEnabled: false });

  const screen = render(HibpSettingsSection);

  const toggle = screen.getByRole('switch', { name: 'Check passwords against known breaches' });
  await toggle.click();

  await expect.element(screen.getByText('Enable breach checking?')).toBeInTheDocument();
  await expect.element(screen.getByText('api.pwnedpasswords.com')).toBeInTheDocument();

  // Not persisted yet — the toggle onclick alone must never call saveConfig.
  const saved = getLastSavedConfig() as { hibpEntryScanEnabled?: boolean } | null;
  expect(saved?.hibpEntryScanEnabled).not.toBe(true);
  await expect.element(toggle).toHaveAttribute('aria-checked', 'false');
});

test('(c) "Not now" closes the dialog, toggle stays OFF, nothing persisted', async () => {
  setMockConfigFlags({ hibpEntryScanEnabled: false });

  const screen = render(HibpSettingsSection);

  const toggle = screen.getByRole('switch', { name: 'Check passwords against known breaches' });
  await toggle.click();

  await expect.element(screen.getByText('Enable breach checking?')).toBeInTheDocument();

  await screen.getByText('Not now', { exact: true }).click();

  await expect.element(screen.getByText('Enable breach checking?')).not.toBeInTheDocument();
  await expect.element(toggle).toHaveAttribute('aria-checked', 'false');

  const saved = getLastSavedConfig() as { hibpEntryScanEnabled?: boolean } | null;
  expect(saved?.hibpEntryScanEnabled).not.toBe(true);
});

test('(d) confirming "Enable breach checking" persists true and flips the toggle ON', async () => {
  setMockConfigFlags({ hibpEntryScanEnabled: false });

  const screen = render(HibpSettingsSection);

  const toggle = screen.getByRole('switch', { name: 'Check passwords against known breaches' });
  await toggle.click();

  await expect.element(screen.getByText('Enable breach checking?')).toBeInTheDocument();

  await screen.getByText('Enable breach checking', { exact: true }).click();

  await expect.element(toggle).toHaveAttribute('aria-checked', 'true');
  const saved = getLastSavedConfig() as { hibpEntryScanEnabled?: boolean } | null;
  expect(saved?.hibpEntryScanEnabled).toBe(true);
});

test('(e) dialog body names the exact required disclosure facts', async () => {
  setMockConfigFlags({ hibpEntryScanEnabled: false });

  const screen = render(HibpSettingsSection);

  const toggle = screen.getByRole('switch', { name: 'Check passwords against known breaches' });
  await toggle.click();

  await expect
    .element(screen.getByText('the first network call', { exact: false }))
    .toBeInTheDocument();
  await expect.element(screen.getByText('5-character prefix', { exact: false })).toBeInTheDocument();
  await expect.element(screen.getByText('api.pwnedpasswords.com')).toBeInTheDocument();
});

test('toggling ON -> OFF flips immediately with no dialog and persists false', async () => {
  setMockConfigFlags({ hibpEntryScanEnabled: true });

  const screen = render(HibpSettingsSection);

  const toggle = screen.getByRole('switch', { name: 'Check passwords against known breaches' });
  await expect.element(toggle).toHaveAttribute('aria-checked', 'true');

  await toggle.click();

  // No dialog on the OFF path.
  await expect.element(screen.getByText('Enable breach checking?')).not.toBeInTheDocument();
  await expect.element(toggle).toHaveAttribute('aria-checked', 'false');

  const saved = getLastSavedConfig() as { hibpEntryScanEnabled?: boolean } | null;
  expect(saved?.hibpEntryScanEnabled).toBe(false);
});
