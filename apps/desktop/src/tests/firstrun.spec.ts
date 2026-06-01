// apps/desktop/src/tests/firstrun.spec.ts
//
// Layer-2 component tests for the first-run warning gate (TEST-09).
//
// Covers (UI-01 / AUTH-03 / P4-08):
//   (a) Explainer step (FirstRunStep with default tone) renders focused brand copy.
//   (b) Warning step (FirstRunStep with tone="danger" + ackLabel) has Continue
//       DISABLED until the required-ack checkbox is ticked, then ENABLED.
//   (c) Unchecking the ack re-disables Continue (gate is reversible).
//
// Test design:
//   - Render FirstRunStep directly (the shell used by each wizard step) to isolate
//     the ack-gate behaviour without driving the full wizard flow.
//   - FirstRunStep has no Tauri/crypto dependencies — no mock setup needed.
//
// Note: FirstRunWizard screen is not rendered in component tests because it imports
// @tauri-apps/plugin-dialog (vault-path picker) which requires the Tauri runtime.
// FirstRunStep covers the tested behaviours without the runtime dependency.

import { test, expect, beforeEach } from 'vitest';
import { render } from 'vitest-browser-svelte';
import FirstRunStep from '../lib/components/FirstRunStep.svelte';
import { resetMockState } from './support/mockTauriInvoke';

beforeEach(() => {
  resetMockState();
});

// ---------------------------------------------------------------------------
// (a) Explainer step — renders focused brand content
// ---------------------------------------------------------------------------

test('(a) explainer step renders the title and Continue button enabled (no ack gate)', async () => {
  const screen = render(FirstRunStep, {
    step: 1,
    total: 5,
    eyebrow: 'Welcome',
    title: 'Your vault, your keys.',
    continueLabel: 'Get started',
    onContinue: () => {
      /* no-op */
    },
  });

  // The title renders.
  await expect.element(screen.getByText('Your vault, your keys.')).toBeVisible();

  // Eyebrow text renders.
  await expect.element(screen.getByText('Welcome')).toBeVisible();

  // Progress shows Step 1 of 5.
  await expect.element(screen.getByText('Step 1 of 5')).toBeVisible();

  // The Continue button is labeled "Get started" and is ENABLED (no ack gate).
  const continueButton = screen.getByRole('button', { name: /get started/i });
  await expect.element(continueButton).toBeVisible();
  await expect.element(continueButton).toBeEnabled();
});

test('(a) explainer step has no ack checkbox (only danger tone adds the gate)', async () => {
  const screen = render(FirstRunStep, {
    step: 1,
    total: 5,
    eyebrow: 'Welcome',
    title: 'Your vault, your keys.',
    continueLabel: 'Get started',
    onContinue: () => {
      /* no-op */
    },
  });

  // No checkbox should appear on the explainer step.
  await expect.element(screen.getByRole('checkbox')).not.toBeInTheDocument();
});

// ---------------------------------------------------------------------------
// (b) Warning step — required-ack gates Continue (AUTH-03 / P4-08)
// ---------------------------------------------------------------------------

const dangerProps = {
  step: 2,
  total: 5,
  eyebrow: 'Important',
  title: 'There is no password reset.',
  tone: 'danger' as const,
  ackLabel:
    'I understand — if I forget my master password and have no recovery key, my vault is gone forever.',
  onContinue: () => {
    /* no-op */
  },
};

test('(b) warning step: Continue is DISABLED before the ack checkbox is ticked', async () => {
  const screen = render(FirstRunStep, { ...dangerProps });

  // The danger-tone title renders.
  await expect
    .element(screen.getByText('There is no password reset.'))
    .toBeVisible();

  // The ack checkbox is present and unchecked.
  const ackCheckbox = screen.getByRole('checkbox');
  await expect.element(ackCheckbox).toBeVisible();
  await expect.element(ackCheckbox).not.toBeChecked();

  // Continue is DISABLED — the ack must be ticked first (AUTH-03 / P4-08).
  const continueButton = screen.getByRole('button', { name: /continue/i });
  await expect.element(continueButton).toBeDisabled();
});

test('(b) warning step: Continue is ENABLED after the ack checkbox is ticked', async () => {
  const screen = render(FirstRunStep, { ...dangerProps });

  const ackCheckbox = screen.getByRole('checkbox');
  const continueButton = screen.getByRole('button', { name: /continue/i });

  // Tick the acknowledgment checkbox.
  await ackCheckbox.click();
  await expect.element(ackCheckbox).toBeChecked();

  // Continue is now ENABLED.
  await expect.element(continueButton).toBeEnabled();
});

// ---------------------------------------------------------------------------
// (c) Unchecking the ack re-disables Continue (gate is reversible)
// ---------------------------------------------------------------------------

test('(c) unchecking the ack re-disables Continue (reversible gate)', async () => {
  const screen = render(FirstRunStep, { ...dangerProps });

  const ackCheckbox = screen.getByRole('checkbox');
  const continueButton = screen.getByRole('button', { name: /continue/i });

  // Check → enabled.
  await ackCheckbox.click();
  await expect.element(continueButton).toBeEnabled();

  // Uncheck → disabled again.
  await ackCheckbox.click();
  await expect.element(continueButton).toBeDisabled();
});

// ---------------------------------------------------------------------------
// Ack label text is shown (AUTH-03 copy requirement)
// ---------------------------------------------------------------------------

test('warning step ack label contains the expected copy', async () => {
  const ackLabelText =
    'I understand — if I forget my master password and have no recovery key, my vault is gone forever.';

  const screen = render(FirstRunStep, { ...dangerProps, ackLabel: ackLabelText });

  // The label text is visible in the component.
  await expect.element(screen.getByText(ackLabelText)).toBeVisible();
});
