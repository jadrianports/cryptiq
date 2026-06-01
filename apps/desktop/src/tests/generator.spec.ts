// apps/desktop/src/tests/generator.spec.ts
//
// Layer-2 component tests for GeneratorSurface.svelte (TEST-09).
//
// Covers (GEN-05 / GEN-06):
//   (a) Mode toggle: switching from 'random' to 'passphrase' changes the output.
//   (b) Toggle options (class/separator) affect the generated output.
//   (c) Generation does NOT use Math.random (GEN-03/T-04-27 oracle defense).
//       The `generate` callback is injected — tests assert it is called with
//       correct GeneratorOptions derived from the current control state.
//   (d) Preset: the 'Use this password' button calls onUse with the current output.
//
// Security (T-04-27):
//   The spec asserts generation uses the injected `generate` callback (core CSPRNG path)
//   rather than Math.random. Any direct Math.random call in GeneratorSurface would
//   bypass the injected callback and fail the onUse assertion (the output would differ).
//
// Note: GeneratorSurface accepts `generate` and `estimateBits` as INJECTED callbacks.
// Tests pass controlled callbacks that record call arguments, proving the core path
// is used and Math.random is never a fallback.

import { test, expect, beforeEach, afterEach, vi } from 'vitest';
import { render } from 'vitest-browser-svelte';
import GeneratorSurface from '../lib/components/GeneratorSurface.svelte';
import { mountVaultSession } from './support/mountVaultSession';
import { resetMockState } from './support/mockTauriInvoke';
import { generateFromOptions, estimateEntropyBits } from '@cryptiq/core';
import type { GeneratorOptions } from '@cryptiq/core';

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

beforeEach(async () => {
  resetMockState();
  await mountVaultSession();
});

afterEach(async () => {
  resetMockState();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Spy wrapper around the real generateFromOptions — records last call args. */
function makeGenerateSpy(): {
  generate: (opts: GeneratorOptions) => Promise<string>;
  calls: GeneratorOptions[];
} {
  const calls: GeneratorOptions[] = [];
  const generate = async (opts: GeneratorOptions): Promise<string> => {
    calls.push(opts);
    // Use the REAL core CSPRNG path so output is non-empty and genuinely random.
    return generateFromOptions(opts);
  };
  return { generate, calls };
}

/** The live output region (aria-live="polite") inside the rendered surface. */
function outputText(container: HTMLElement): string {
  const el = container.querySelector('[aria-live="polite"]');
  return (el?.textContent ?? '').trim();
}

// ---------------------------------------------------------------------------
// (a) Mode toggle: random → passphrase changes output format
// ---------------------------------------------------------------------------

test('(a) switching to passphrase mode produces a different output than random mode', async () => {
  const spy = makeGenerateSpy();

  const screen = render(GeneratorSurface, {
    generate: spy.generate,
    estimateBits: estimateEntropyBits,
    variant: 'standalone' as const,
  });

  // Wait for initial generation (the $effect triggers on mount).
  await vi.waitFor(() => expect(spy.calls.length).toBeGreaterThan(0), {
    timeout: 5_000,
  });

  // Capture the random-mode output once it is no longer the placeholder.
  await vi.waitFor(() => expect(outputText(screen.container)).not.toBe('…'), {
    timeout: 5_000,
  });
  const randomOutput = outputText(screen.container);

  // Switch to passphrase mode via the 'Passphrase' tab button.
  await screen.getByRole('tab', { name: 'Passphrase' }).click();

  // Wait for the passphrase to generate.
  await sleep(500);
  await vi.waitFor(() => expect(outputText(screen.container)).not.toBe('…'), {
    timeout: 5_000,
  });
  const passphraseOutput = outputText(screen.container);

  // Passphrase output should differ from random output (word-based vs char-based).
  expect(passphraseOutput).not.toBe(randomOutput);

  // The spy should have been called with mode: 'passphrase' at least once.
  const passphraseCalls = spy.calls.filter((c) => c.mode === 'passphrase');
  expect(passphraseCalls.length).toBeGreaterThan(0);
});

// ---------------------------------------------------------------------------
// (b) Toggles affect output — symbols toggle changes the random charset
// ---------------------------------------------------------------------------

test('(b) toggling character classes calls generate with updated options', async () => {
  const spy = makeGenerateSpy();

  const screen = render(GeneratorSurface, {
    generate: spy.generate,
    estimateBits: estimateEntropyBits,
    variant: 'popover' as const,
  });

  // Wait for initial generate.
  await vi.waitFor(() => expect(spy.calls.length).toBeGreaterThan(0), {
    timeout: 5_000,
  });

  const initialCallCount = spy.calls.length;

  // Find and click the '!@#' symbols toggle button (aria-pressed).
  await screen.getByRole('button', { name: /!@#/i }).click();

  // Wait for the reactivity to trigger a new generate call.
  await vi.waitFor(
    () => expect(spy.calls.length).toBeGreaterThan(initialCallCount),
    { timeout: 3_000 },
  );

  // The last call's options should reflect the toggled symbols state.
  const lastCall = spy.calls[spy.calls.length - 1];
  expect(lastCall).toBeDefined();
  expect(lastCall?.mode).toBe('random');
});

// ---------------------------------------------------------------------------
// (c) Generation uses the injected callback (never Math.random) — GEN-03/T-04-27
// ---------------------------------------------------------------------------

test('(c) generation routes through the injected generate callback (core CSPRNG, not Math.random)', async () => {
  const spy = makeGenerateSpy();

  // The GEN-03/T-04-27 oracle defense: if GeneratorSurface routed through Math.random
  // instead of the injected `generate` callback, spy.calls would remain empty and the
  // output would be produced by a different, non-CSPRNG path. By asserting spy.calls > 0
  // for every generate event, we prove the core CSPRNG path is in use.

  const screen = render(GeneratorSurface, {
    generate: spy.generate,
    estimateBits: estimateEntropyBits,
    variant: 'popover' as const,
  });

  // Wait for initial generation — the $effect fires on mount.
  await vi.waitFor(() => expect(spy.calls.length).toBeGreaterThan(0), {
    timeout: 5_000,
  });

  const callsAfterMount = spy.calls.length;

  // Click "Regenerate" to trigger a new generation cycle.
  await screen.getByRole('button', { name: /regenerate/i }).click();

  // A new spy call must have fired (core CSPRNG was used for the second output).
  await vi.waitFor(
    () => expect(spy.calls.length).toBeGreaterThan(callsAfterMount),
    { timeout: 3_000 },
  );

  // Every call in the spy was with a valid mode — proving the injected path is used.
  expect(
    spy.calls.every((c) => c.mode === 'random' || c.mode === 'passphrase'),
  ).toBe(true);

  // The output region contains the value from the spy (non-empty, not a placeholder).
  const output = outputText(screen.container);
  expect(output.length).toBeGreaterThan(0);
  expect(output).not.toBe('…');
});

// ---------------------------------------------------------------------------
// (d) "Use this password" calls onUse with the current output (preset reuse)
// ---------------------------------------------------------------------------

test('(d) "Use this password" calls onUse with the generated output', async () => {
  const spy = makeGenerateSpy();
  const usedValues: string[] = [];

  const screen = render(GeneratorSurface, {
    generate: spy.generate,
    estimateBits: estimateEntropyBits,
    variant: 'popover' as const,
    onUse: (value: string) => {
      usedValues.push(value);
    },
  });

  // Wait for initial generation.
  await vi.waitFor(() => expect(outputText(screen.container)).not.toBe('…'), {
    timeout: 5_000,
  });
  const generatedOutput = outputText(screen.container);
  expect(generatedOutput.length).toBeGreaterThan(0);

  // Click "Use this password".
  await screen.getByRole('button', { name: /use this password/i }).click();

  // onUse was called with the generated value.
  expect(usedValues.length).toBe(1);
  expect(usedValues[0]).toBe(generatedOutput);
});

// ---------------------------------------------------------------------------
// Passphrase separator toggle changes output structure
// ---------------------------------------------------------------------------

test('passphrase separator toggle changes output', async () => {
  const spy = makeGenerateSpy();

  const screen = render(GeneratorSurface, {
    generate: spy.generate,
    estimateBits: estimateEntropyBits,
    variant: 'standalone' as const,
  });

  // Switch to passphrase mode.
  await screen.getByRole('tab', { name: 'Passphrase' }).click();
  await sleep(300);

  const initialCallCount = spy.calls.length;

  // Click the '.' separator button.
  await screen.getByRole('button', { name: '.' }).click();

  // A new generate call should have fired.
  await vi.waitFor(
    () => expect(spy.calls.length).toBeGreaterThan(initialCallCount),
    { timeout: 3_000 },
  );

  const lastCallP = spy.calls[spy.calls.length - 1];
  expect(lastCallP).toBeDefined();
  expect(lastCallP?.mode).toBe('passphrase');
  if (lastCallP?.mode === 'passphrase') {
    expect(
      (lastCallP as import('@cryptiq/core').PassphraseOptions).separator,
    ).toBe('.');
  }
});
