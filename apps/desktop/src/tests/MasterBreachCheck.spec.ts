// apps/desktop/src/tests/MasterBreachCheck.spec.ts
//
// Layer-2 component tests for the master-password breach check (HIBP-06,
// 31-05-PLAN.md Task 3 acceptance criteria). Mounts ChangeMasterView (the
// simpler of the two HIBP-06 surfaces — FirstRunWizard shares the identical
// click-only button + result-row implementation, unit-proven here).
//
// Covers:
//   (a) click-only (D-15/Pitfall 6) — typing into the new-password field
//       fires ZERO hibp lookups; only clicking "Check against breaches" does.
//   (b) advisory-not-blocking (D-14) — a breached result never disables the
//       surrounding Save/Continue control.
//   (c) unknown-on-failure (HIBP-05) — a failed lookup renders the unknown
//       state, never a "Not found"/safe reading.
//   (d) first-use disclosure (D-16) — consent not yet granted opens the
//       master-check dialog instead of calling the seam; declining fires
//       zero lookups.
//
// Single seam call site (D-17): the ONLY production TypeScript call site for
// the literal `hibp_range_lookup` command string is
// packages/core/src/hibp/index.ts's `lookupHibpRange` (verified this plan via
// `grep -rn "hibp_range_lookup" apps/desktop/src` — every match under
// apps/desktop/src is a comment or the mockTauriInvoke.ts test double, never
// a second production call site). apps/desktop/src/lib/adapters/hibpInvoke.ts
// is the sole DI binding that forwards to it — no second Rust command, no
// second client, exactly as required by D-17.
//
// Test environment: Vitest browser mode (see vitest.browser.config.ts — this
// file lives at src/tests/*.spec.ts, the ONLY glob the browser config
// includes). Tauri: @tauri-apps/api/core is aliased to mockTauriInvoke.ts.
// Does NOT mock @cryptiq/core; does NOT edit mockTauriInvoke.ts (Plan-02 owns
// that shared file).

import { test, expect, beforeEach, afterEach } from 'vitest';
import { render } from 'vitest-browser-svelte';
import ChangeMasterView from '../lib/screens/ChangeMasterView.svelte';
import { resetMockState, setMockConfigFlags, setMockHibpResponse } from './support/mockTauriInvoke';

const CURRENT_PASSWORD = 'CurrentMasterPass123!';
const NEW_PASSWORD = 'BrandNewMasterPass456!';

beforeEach(() => {
  resetMockState();
});

afterEach(() => {
  resetMockState();
});

/** Advances ChangeMasterView from Step 1 (verify current) to Step 2 (enter new). */
async function advanceToStep2(screen: ReturnType<typeof render>): Promise<void> {
  const currentPwInput = screen.getByLabelText('Current master password');
  await currentPwInput.fill(CURRENT_PASSWORD);
  await screen.getByText('Continue', { exact: true }).click();
  await expect.element(screen.getByText('Choose a new master password.')).toBeInTheDocument();
}

test('(a) typing into the new-password field fires zero hibp lookups — only the click does', async () => {
  setMockConfigFlags({ hibpMasterCheckEnabled: true });

  const screen = render(ChangeMasterView);
  await advanceToStep2(screen);

  const newPwInput = screen.getByLabelText('New master password');
  await newPwInput.fill(NEW_PASSWORD);

  // No result row appeared and the button never entered a checking/result state —
  // the ONLY way breachCheckResult leaves 'idle' is the button's onclick handler,
  // so this proves typing alone never fired lookupHibpRange.
  const checkButton = screen.getByText('Check against breaches', { exact: true });
  await expect.element(checkButton).toBeInTheDocument();
  await expect.element(screen.getByText('Not found in known breaches.')).not.toBeInTheDocument();
  await expect
    .element(screen.getByText("Couldn't check right now — try again in a moment."))
    .not.toBeInTheDocument();
  await expect
    .element(
      screen.getByText('This password has appeared in a known data breach. Consider choosing a different one.'),
    )
    .not.toBeInTheDocument();

  // The explicit click DOES issue a lookup — proving the seam is reachable at all,
  // and that only the click (not the preceding keystrokes) triggers it.
  await checkButton.click();
  await expect.element(screen.getByText('Not found in known breaches.')).toBeInTheDocument();
});

test('(b) a breached result never disables the surrounding Save/Continue control (D-14)', async () => {
  setMockConfigFlags({ hibpMasterCheckEnabled: true });
  setMockHibpResponse('match', NEW_PASSWORD);

  const screen = render(ChangeMasterView);
  await advanceToStep2(screen);

  const newPwInput = screen.getByLabelText('New master password');
  await newPwInput.fill(NEW_PASSWORD);
  const confirmPwInput = screen.getByLabelText('Confirm new password');
  await confirmPwInput.fill(NEW_PASSWORD);

  await screen.getByText('Check against breaches', { exact: true }).click();

  await expect
    .element(
      screen.getByText('This password has appeared in a known data breach. Consider choosing a different one.'),
    )
    .toBeInTheDocument();

  // Advisory only — the submit control stays enabled despite the breached result
  // (newPasswordsMatch + newDiffersFromCurrent are both satisfied above).
  const submitButton = screen.getByText('Change master password', { exact: true });
  await expect.element(submitButton).not.toBeDisabled();
});

test('(c) a failed lookup renders the unknown state, never "Not found"/safe (HIBP-05)', async () => {
  setMockConfigFlags({ hibpMasterCheckEnabled: true });
  setMockHibpResponse('fail');

  const screen = render(ChangeMasterView);
  await advanceToStep2(screen);

  const newPwInput = screen.getByLabelText('New master password');
  await newPwInput.fill(NEW_PASSWORD);

  await screen.getByText('Check against breaches', { exact: true }).click();

  await expect
    .element(screen.getByText("Couldn't check right now — try again in a moment."))
    .toBeInTheDocument();
  await expect.element(screen.getByText('Not found in known breaches.')).not.toBeInTheDocument();
});

test('(d) first use (consent not yet granted) opens the master-check disclosure instead of calling the seam', async () => {
  setMockConfigFlags({ hibpMasterCheckEnabled: false });

  const screen = render(ChangeMasterView);
  await advanceToStep2(screen);

  const newPwInput = screen.getByLabelText('New master password');
  await newPwInput.fill(NEW_PASSWORD);

  await screen.getByText('Check against breaches', { exact: true }).click();

  // The SECOND, independent master-check dialog opens — scoped copy, not the
  // entry-scan dialog's title.
  await expect
    .element(screen.getByText('Check your master password against breaches?'))
    .toBeInTheDocument();

  // No lookup fired yet — declining must leave the button inert with zero lookups.
  await screen.getByText('Not now', { exact: true }).click();

  await expect
    .element(screen.getByText('Check your master password against breaches?'))
    .not.toBeInTheDocument();
  await expect.element(screen.getByText('Not found in known breaches.')).not.toBeInTheDocument();
  await expect
    .element(
      screen.getByText('This password has appeared in a known data breach. Consider choosing a different one.'),
    )
    .not.toBeInTheDocument();

  // The button remains visible for a later retry (not hidden after a decline).
  await expect.element(screen.getByText('Check against breaches', { exact: true })).toBeInTheDocument();
});

test('(e) editing the new-password field after a check clears the stale result banner (WR-01)', async () => {
  setMockConfigFlags({ hibpMasterCheckEnabled: true });

  const screen = render(ChangeMasterView);
  await advanceToStep2(screen);

  const newPwInput = screen.getByLabelText('New master password');
  await newPwInput.fill(NEW_PASSWORD);
  await screen.getByText('Check against breaches', { exact: true }).click();
  await expect.element(screen.getByText('Not found in known breaches.')).toBeInTheDocument();

  // Edit the field after the result rendered — the stale "safe" banner for the
  // now-different value must disappear, not linger attached to a changed field.
  await newPwInput.fill(`${NEW_PASSWORD}-edited`);
  await expect.element(screen.getByText('Not found in known breaches.')).not.toBeInTheDocument();
});

test('(f) going back to Step 1 and forward again does not show a leftover result banner (WR-01)', async () => {
  setMockConfigFlags({ hibpMasterCheckEnabled: true });

  const screen = render(ChangeMasterView);
  await advanceToStep2(screen);

  const newPwInput = screen.getByLabelText('New master password');
  await newPwInput.fill(NEW_PASSWORD);
  await screen.getByText('Check against breaches', { exact: true }).click();
  await expect.element(screen.getByText('Not found in known breaches.')).toBeInTheDocument();

  await screen.getByText('Back', { exact: true }).click();
  await expect.element(screen.getByText('Enter your current master password to continue.', { exact: false })).toBeInTheDocument();

  await advanceToStep2(screen);
  await expect.element(screen.getByText('Not found in known breaches.')).not.toBeInTheDocument();
});
