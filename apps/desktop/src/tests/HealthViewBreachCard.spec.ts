// apps/desktop/src/tests/HealthViewBreachCard.spec.ts
//
// Layer-2 component tests for HealthView.svelte's bespoke 5th "breached" card
// (HIBP-02/HIBP-05, 31-04-PLAN.md Task 2 acceptance criteria).
//
// Covers:
//   (a) an all-failures sweep (consent ON) never renders a false all-clear
//       "0 breached" reading — the unknown clause is always present (T-31-04).
//   (b) the "All clear" hero never renders while the breach sweep is still in
//       flight, even when all 4 existing healthAudit buckets are already
//       clear — and the "Checking passwords…" affordance IS shown. Once the
//       sweep settles to all-safe, "All clear" MAY appear (T-31-04b).
//   (c) consent OFF: the 5th card is a CTA-only explainer with no toggle,
//       whose only action deep-links to Settings (D-01).
//   (d) the breach drill-down expands without an uncaught runtime error
//       (proving 'breached' never reaches the generic CARDS.find(...)! path)
//       and a breached entry's "Fix" action sets ui.selectedEntryId +
//       ui.openGeneratorFor (D-12).
//
// Test environment: Vitest browser mode (vitest.browser.config.ts) — this
// file lives at src/tests/*.spec.ts, the ONLY glob the browser config
// includes. @tauri-apps/api/core is aliased to mockTauriInvoke.ts (never
// edited by this plan). The single injected seam this file controls directly
// is the `hibpInvoke` adapter binding (mocked below via vi.mock on its own
// module path) — @cryptiq/core is NEVER mocked wholesale, so the real
// sha1Hex/matchesSuffix/lookupHibpRange k-anonymity logic runs exactly as in
// production; only the network round-trip itself is faked.

import { test, expect, beforeEach, afterEach, vi } from 'vitest';
import { render } from 'vitest-browser-svelte';

vi.mock('../lib/adapters/hibpInvoke', () => ({
  hibpInvoke: vi.fn(),
}));

import { hibpInvoke } from '../lib/adapters/hibpInvoke';
import HealthView from '../lib/screens/HealthView.svelte';
import { mountVaultSession } from './support/mountVaultSession';
import { ui, vaultSession, view } from './support/testState';
import { resetMockState, setMockConfigFlags } from './support/mockTauriInvoke';
import { clearBreachAudit } from '../lib/state/breachAudit.svelte';

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

/**
 * A unique, sufficiently strong password (mixed case + digits + symbols,
 * length 18+) so the real zxcvbn-ts scorer never flags it weak (score > 2) —
 * keeps the 4 existing healthAudit buckets clear so the test isolates the
 * breach dimension, per the plan's read_first instruction.
 */
function strongPw(seed: number): string {
  return `Xk9#mPzQ2vR7Ln4T!${seed}`;
}

beforeEach(async () => {
  resetMockState();
  await mountVaultSession();
  clearBreachAudit();
  ui.toasts = [];
  ui.selectedEntryId = null;
  ui.openGeneratorFor = null;
  view.current = 'health';
  vi.mocked(hibpInvoke).mockReset();
  // Sane default so any test that forgets to configure a response doesn't
  // hang forever on `await undefined` inside the real lookupHibpRange seam.
  vi.mocked(hibpInvoke).mockResolvedValue('');
});

afterEach(async () => {
  if (vaultSession.isUnlocked) {
    await vaultSession.lock();
  }
  clearBreachAudit();
  resetMockState();
});

// ---------------------------------------------------------------------------
// (a) all-failures sweep never renders a false all-clear "0 breached" reading
// ---------------------------------------------------------------------------

test('(a) all-failures sweep never renders a false all-clear "0 breached" reading (T-31-04)', async () => {
  setMockConfigFlags({ hibpEntryScanEnabled: true });
  vi.mocked(hibpInvoke).mockRejectedValue(new Error('mock hibp failure'));

  await vaultSession.addEntry({ title: 'Site A', password: strongPw(1) });
  await vaultSession.addEntry({ title: 'Site B', password: strongPw(2) });

  const screen = render(HealthView);

  // Both counts render together, in the exact Copywriting Contract shape —
  // the unknown clause is NEVER omitted when unknown > 0, even though
  // breached === 0 here. A regression that renders "0 breached" alone (with
  // unknown hidden/absent) would fail this exact-name lookup.
  await expect
    .element(screen.getByRole('button', { name: '0 breached · 2 unknown' }))
    .toBeInTheDocument();

  // The card never claims "All clear" on an unresolved/all-failed sweep.
  await expect.element(screen.getByText('All clear')).not.toBeInTheDocument();
});

// ---------------------------------------------------------------------------
// (b) never-false-"All clear" while the sweep is in flight
// ---------------------------------------------------------------------------

test('(b) "All clear" hero never renders while the breach sweep is in flight (T-31-04b)', async () => {
  setMockConfigFlags({ hibpEntryScanEnabled: true });

  // Boxed (not a bare `let`) so TS doesn't narrow the property to `null`
  // across the opaque HealthView-internal ensureBreachAuditFresh() call —
  // mirrors breachAudit.test.ts's own established pattern (31-02, D-Deviation 1).
  const box: { resolve: ((v: string) => void) | null } = { resolve: null };
  vi.mocked(hibpInvoke).mockImplementation(
    () =>
      new Promise<string>((resolve) => {
        box.resolve = resolve;
      }),
  );

  // A single, strong, non-stale entry — all 4 healthAudit buckets are clear,
  // isolating this assertion to the breach dimension alone.
  await vaultSession.addEntry({ title: 'Site A', password: strongPw(1) });

  const screen = render(HealthView);

  // Mid-flight: the scanning affordance shows, digits are withheld, and the
  // hero must NOT claim "All clear" even though every other bucket is empty.
  await expect.element(screen.getByText('Checking passwords…')).toBeInTheDocument();
  await expect.element(screen.getByText('All clear')).not.toBeInTheDocument();

  expect(box.resolve).not.toBeNull();

  // Resolve to "no match" (safe) — the sweep settles.
  box.resolve?.('');

  // Now that the sweep has genuinely settled to all-safe, "All clear" MAY
  // appear — proving this is a completion gate, not a permanent suppression.
  await expect.element(screen.getByText('All clear')).toBeInTheDocument();
});

// ---------------------------------------------------------------------------
// (c) consent OFF: CTA-only card, no toggle, deep-links to Settings
// ---------------------------------------------------------------------------

test('(c) consent OFF: 5th card is a CTA-only explainer that deep-links to Settings', async () => {
  setMockConfigFlags({ hibpEntryScanEnabled: false });

  // Seed one weak entry so the existing 4-bucket isAllClear is false and the
  // card grid (rather than the "All clear" hero) actually renders — the
  // widened isAllClear stays UNAFFECTED by breach status when consent is OFF
  // (per UI-SPEC Interaction Contract §3), so an otherwise-clean vault would
  // legitimately show the hero and hide every card, including this one.
  await vaultSession.addEntry({ title: 'Weak Site', password: '123456' });

  const screen = render(HealthView);

  await expect.element(screen.getByText('Breach checking is off')).toBeInTheDocument();
  const cta = screen.getByRole('button', { name: 'Turn on breach checking →' });
  await expect.element(cta).toBeInTheDocument();

  // Never a second consent-granting surface — no switch/toggle in the card.
  await expect.element(screen.getByRole('switch')).not.toBeInTheDocument();

  expect(view.current).not.toBe('settings');
  await cta.click();
  expect(view.current).toBe('settings');

  // hibp_range_lookup is never invoked while consent is off.
  expect(hibpInvoke).not.toHaveBeenCalled();
});

// ---------------------------------------------------------------------------
// (d) breach drill-down expands without crashing; breached jump-to-fix wires ui state
// ---------------------------------------------------------------------------

test('(d) breach drill-down expands without crashing; breached "Fix" sets ui.selectedEntryId + ui.openGeneratorFor (D-12)', async () => {
  setMockConfigFlags({ hibpEntryScanEnabled: true });

  const breachedPw = strongPw(101);
  const safePw = strongPw(102);
  const unknownPw = strongPw(103);

  const breachedEntry = await vaultSession.addEntry({ title: 'Breached Co', password: breachedPw });
  await vaultSession.addEntry({ title: 'Safe Co', password: safePw });
  await vaultSession.addEntry({ title: 'Unknown Co', password: unknownPw });

  // Real sha1Hex/matchesSuffix logic decides the outcome per-prefix — this
  // mock only fakes the network round trip, never the k-anonymity matching.
  const { sha1Hex } = await import('@cryptiq/core');
  const breachedHash = sha1Hex(breachedPw);
  const unknownHash = sha1Hex(unknownPw);
  vi.mocked(hibpInvoke).mockImplementation(async (_cmd: string, args: { prefix: string }) => {
    if (args.prefix === breachedHash.slice(0, 5)) {
      return `${breachedHash.slice(5)}:1\r\n`;
    }
    if (args.prefix === unknownHash.slice(0, 5)) {
      throw new Error('mock hibp failure for the unknown-bucket entry');
    }
    return ''; // safe / no match
  });

  const screen = render(HealthView);

  const cardButton = screen.getByRole('button', { name: '1 breached · 1 unknown' });
  await expect.element(cardButton).toBeInTheDocument();

  // Expand the drill-down — completing this without an uncaught runtime error
  // is the proof that 'breached' never reached the generic CARDS.find(...)!
  // path (which has no 'breached' bucket and would throw at runtime).
  await cardButton.click();

  const fixButton = screen.getByRole('button', { name: 'Fix Breached Co' });
  await expect.element(fixButton).toBeInTheDocument();

  // The unknown-bucket entry has no Fix action (nothing to fix).
  await expect
    .element(screen.getByRole('button', { name: 'Fix Unknown Co' }))
    .not.toBeInTheDocument();

  await fixButton.click();

  expect(ui.selectedEntryId).toBe(breachedEntry.id);
  expect(ui.openGeneratorFor).toBe(breachedEntry.id);
  expect(view.current).toBe('main');
});

// ---------------------------------------------------------------------------
// (e) CR-01: a post-sweep addition prevents a false "All clear"
// ---------------------------------------------------------------------------

test('(e) a breached/unknown entry added AFTER the sweep prevents "All clear" (CR-01)', async () => {
  setMockConfigFlags({ hibpEntryScanEnabled: true });
  vi.mocked(hibpInvoke).mockResolvedValue(''); // everything swept so far resolves safe

  await vaultSession.addEntry({ title: 'Site A', password: strongPw(1) });

  const screen = render(HealthView);

  // First sweep settles all-clear.
  await expect.element(screen.getByText('All clear')).toBeInTheDocument();

  // A new entry is added AFTER the one-time sweep — its password hash was never
  // queried, so it must surface as 'unknown' via reconcileBreachAudit, NOT be
  // silently absent, and NOT let "All clear" keep rendering.
  await vaultSession.addEntry({ title: 'Site B (post-sweep)', password: strongPw(2) });

  await expect.element(screen.getByText('All clear')).not.toBeInTheDocument();
  await expect
    .element(screen.getByRole('button', { name: '0 breached · 1 unknown' }))
    .toBeInTheDocument();

  // No re-arm of the network sweep on the post-sweep mutation — reconcile is
  // cache-only. Exactly the calls from the initial sweep (1), never more.
  expect(hibpInvoke).toHaveBeenCalledTimes(1);
});
