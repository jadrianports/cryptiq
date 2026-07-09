// apps/desktop/src/tests/TotpCodeRing.spec.ts
//
// Layer-2 component tests for TotpCodeRing.svelte (TOTP-04, D-04/D-05/D-14).
//
// Covers:
//   (a) Displayed code equals generateTotpCode(totp, nowMs).code, digit-grouped.
//   (b) The code auto-rolls when the fake clock crosses the period boundary.
//   (c) The ring/seconds color switches to attention (amber) at <=5s remaining.
//   (d) The interval is cleared on unmount (no leaked ticks — vi.getTimerCount()).
//   (e) Tapping the code calls the non-sensitive copyField(value, 'other') path
//       (never joins SENSITIVE_COPY_FIELDS / the Rust sensitive-clipboard path)
//       and shows the checkmark swap for ~1500ms.
//
// Deviation from the 29-04-PLAN.md-specified path
// (`apps/desktop/src/lib/components/__tests__/TotpCodeRing.test.ts`): the actual
// live browser-mode harness (`vitest.browser.config.ts`) only includes
// `src/tests/**/*.spec.ts` — the node-environment `vitest.config.ts` matches
// `src/**/__tests__/**/*.test.ts` instead, which has no DOM and would fail to
// mount a Svelte component. Placed here to match the REAL working harness
// (mirrors purge.spec.ts / generator.spec.ts), per Rule 3 (blocking issue).
//
// This test does NOT need a vault session — TotpCodeRing takes `totp` as a
// plain prop and has no vaultSession/CRUD dependency.

import { test, expect, beforeEach, afterEach, vi } from 'vitest';
import { render } from 'vitest-browser-svelte';
import TotpCodeRing from '../lib/components/TotpCodeRing.svelte';
import { generateTotpCode } from '@cryptiq/core';
import type { EntryTotp } from '@cryptiq/core';

vi.mock('../lib/util/copyField', () => ({
  copyField: vi.fn(async () => {}),
}));

import { copyField } from '../lib/util/copyField';

// RFC 6238 Appendix B SHA1 seed (20 bytes) — a real, valid Base32 secret.
const TOTP: EntryTotp = {
  secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
  algorithm: 'SHA1',
  digits: 6,
  period: 30,
};

function groupedCode(code: string): string {
  const mid = Math.ceil(code.length / 2);
  return `${code.slice(0, mid)} ${code.slice(mid)}`;
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

test('(a) displayed code equals generateTotpCode(totp, nowMs).code, digit-grouped', async () => {
  vi.setSystemTime(0);
  const expected = generateTotpCode(TOTP, 0);

  const screen = render(TotpCodeRing, { totp: TOTP });

  await expect
    .element(screen.getByRole('button', { name: 'Copy 2FA code' }))
    .toHaveTextContent(groupedCode(expected.code));
});

test('(b) the code auto-rolls at the period boundary', async () => {
  vi.setSystemTime(0);
  const first = generateTotpCode(TOTP, 0);

  const screen = render(TotpCodeRing, { totp: TOTP });
  const codeButton = screen.getByRole('button', { name: 'Copy 2FA code' });

  await expect.element(codeButton).toHaveTextContent(groupedCode(first.code));

  // Advance a full period — fake timers advance Date.now() in lockstep.
  await vi.advanceTimersByTimeAsync(TOTP.period * 1000);
  const second = generateTotpCode(TOTP, TOTP.period * 1000);

  await expect.element(codeButton).toHaveTextContent(groupedCode(second.code));
});

test('(c) ring + seconds switch to the attention color at <=5s remaining', async () => {
  // 25s into a 30s period leaves 5s remaining.
  vi.setSystemTime(25_000);
  const result = generateTotpCode(TOTP, 25_000);
  expect(result.secondsRemaining).toBeLessThanOrEqual(5);

  const screen = render(TotpCodeRing, { totp: TOTP });

  await expect
    .element(screen.getByRole('img'))
    .toHaveAttribute('aria-label', `${result.secondsRemaining} seconds remaining`);

  const attentionArc = screen.container.querySelector('.stroke-cryptiq-attention');
  expect(attentionArc).not.toBeNull();
  const accentArc = screen.container.querySelector('.stroke-cryptiq-accent');
  expect(accentArc).toBeNull();
});

test('(c2) ring + seconds stay accent while >5s remain', async () => {
  vi.setSystemTime(0);
  const result = generateTotpCode(TOTP, 0);
  expect(result.secondsRemaining).toBeGreaterThan(5);

  const screen = render(TotpCodeRing, { totp: TOTP });

  const accentArc = screen.container.querySelector('.stroke-cryptiq-accent');
  expect(accentArc).not.toBeNull();
  const attentionArc = screen.container.querySelector('.stroke-cryptiq-attention');
  expect(attentionArc).toBeNull();
});

test('(d) the interval is cleared on unmount (no leaked ticks)', async () => {
  vi.setSystemTime(0);
  const screen = render(TotpCodeRing, { totp: TOTP });

  expect(vi.getTimerCount()).toBeGreaterThan(0);

  screen.unmount();

  expect(vi.getTimerCount()).toBe(0);
});

test('(e) tapping the code copies via copyField(value, "other") and swaps to a checkmark', async () => {
  vi.setSystemTime(0);
  const expected = generateTotpCode(TOTP, 0);

  const screen = render(TotpCodeRing, { totp: TOTP });
  const codeButton = screen.getByRole('button', { name: 'Copy 2FA code' });

  await codeButton.click();

  expect(vi.mocked(copyField)).toHaveBeenCalledWith(expected.code, 'other');
  expect(vi.mocked(copyField)).toHaveBeenCalledTimes(1);

  await vi.waitFor(() => {
    const el = screen.container.querySelector('button[aria-label="Copy 2FA code"]');
    expect(el?.className.includes('text-cryptiq-success')).toBe(true);
  });

  await vi.advanceTimersByTimeAsync(1500);

  const el = screen.container.querySelector('button[aria-label="Copy 2FA code"]');
  expect(el?.className.includes('text-cryptiq-success')).toBe(false);
});
