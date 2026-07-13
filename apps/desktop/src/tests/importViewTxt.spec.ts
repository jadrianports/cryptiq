// apps/desktop/src/tests/importViewTxt.spec.ts
//
// Layer-2 component test proving the .txt import front door (IMPORT-09/10/11,
// 32-02-PLAN.md Task 3 acceptance criteria).
//
// Covers:
//   (a) selecting a .txt file drives step -> column-map, NEVER preview directly
//       (no confidently-sniffed fast path)
//   (b) the detected-format pill row renders with the sniffed default selection
//   (c) clicking a different pill re-tokenizes csvHeaders (visible via the
//       "Detected columns: ..." hint and the re-derived candidate description)
//   (d) reaching preview requires the explicit "Preview import" click, and the
//       ragged line from the messy fixture lands in the malformed report (D-04)
//
// Test environment: Vitest browser mode (see vitest.browser.config.ts — this
// file lives at src/tests/*.spec.ts, the ONLY glob the browser config
// includes). File upload uses page.elementLocator(...).upload(FIXTURE_PATH) —
// a file-path STRING, not a constructed `File` object. A `File` instance built
// from a string/byte Blob part was found (via an isolated debug harness that
// bypassed readTxtFile entirely) to arrive corrupted in the browser realm: a
// fixed-length garbage prefix gets prepended to the decoded text, regardless
// of content or length, and is reproducible with both chrome-headless-shell
// and full Chromium — a pre-existing defect in this pinned vitest ^3.2.4
// browser-mode File-object RPC transfer, NOT in this plan's production code
// (packages/core/src/import/sniff.ts's Node-environment unit suite proves the
// sniff/tokenize logic is correct on identical bytes). Uploading by file path
// instead (Playwright reads the path directly in the browser context — no
// RPC-serialized File payload) avoids the corruption entirely.
import { test, expect, beforeEach, afterEach } from 'vitest';
import { render } from 'vitest-browser-svelte';
import { page } from '@vitest/browser/context';
import ImportView from '../lib/screens/ImportView.svelte';
import { mountVaultSession } from './support/mountVaultSession';
import { resetMockState } from './support/mockTauriInvoke';
import { vaultSession } from './support/testState';

// Mirrors the content of apps/desktop/src/tests/fixtures/txt-sample.txt
// (dummy passwords, SEC-10). Two well-formed "key=value" lines (3 fields each
// — url/user/pass) sniff to kv-equals, plus one deliberately messy line that
// matches neither the kv-equals model nor a 3-column positional model — a
// ragged row (D-04).
const FIXTURE_PATH = 'src/tests/fixtures/txt-sample.txt';

beforeEach(async () => {
  resetMockState();
  await mountVaultSession();
});

afterEach(async () => {
  if (vaultSession.isUnlocked) {
    await vaultSession.lock();
  }
  resetMockState();
});

test('(a) selecting a .txt file reaches column-map, never preview directly (IMPORT-11)', async () => {
  const screen = render(ImportView);

  const fileInputEl = screen.container.querySelector('input[type="file"]');
  expect(fileInputEl).not.toBeNull();
  await page.elementLocator(fileInputEl as HTMLInputElement).upload(FIXTURE_PATH);

  await expect
    .element(screen.getByText('Map your columns to Cryptiq fields.'))
    .toBeInTheDocument();
  await expect.element(screen.getByText('Review your import.')).not.toBeInTheDocument();
});

test('(b) the detected-format pill row renders with the sniffed default selection', async () => {
  const screen = render(ImportView);

  const fileInputEl = screen.container.querySelector('input[type="file"]');
  await page.elementLocator(fileInputEl as HTMLInputElement).upload(FIXTURE_PATH);

  await expect
    .element(screen.getByText('Detected: key=value pairs, 3 fields'))
    .toBeInTheDocument();
  await expect.element(screen.getByText('key=value', { exact: true })).toBeInTheDocument();
  await expect.element(screen.getByText('Whitespace', { exact: true })).toBeInTheDocument();
  await expect
    .element(screen.getByText('Detected columns: url, user, pass'))
    .toBeInTheDocument();
});

test('(c) clicking a different pill re-tokenizes csvHeaders (Detected columns updates)', async () => {
  const screen = render(ImportView);

  const fileInputEl = screen.container.querySelector('input[type="file"]');
  await page.elementLocator(fileInputEl as HTMLInputElement).upload(FIXTURE_PATH);

  await expect
    .element(screen.getByText('Detected columns: url, user, pass'))
    .toBeInTheDocument();

  await screen.getByText('Whitespace', { exact: true }).click();

  await expect
    .element(screen.getByText('Detected columns: Column 1, Column 2, Column 3'))
    .toBeInTheDocument();
  await expect
    .element(screen.getByText('Detected: whitespace-separated, 3 columns'))
    .toBeInTheDocument();
  // Still on column-map — a pill click never advances the wizard step.
  await expect
    .element(screen.getByText('Map your columns to Cryptiq fields.'))
    .toBeInTheDocument();
});

test('(d) reaching preview requires the explicit Preview-import click; the ragged line lands in the malformed report (D-04)', async () => {
  const screen = render(ImportView);

  const fileInputEl = screen.container.querySelector('input[type="file"]');
  await page.elementLocator(fileInputEl as HTMLInputElement).upload(FIXTURE_PATH);

  // Still on column-map — no fast path, even though every candidate is visible.
  await expect.element(screen.getByText('Review your import.')).not.toBeInTheDocument();

  // Map Title -> 'url' (index 0), Password -> 'pass' (index 2) — the default
  // kv-equals headers, no pill click needed for this assertion.
  await screen.getByLabelText('Title *').selectOptions('0');
  await screen.getByLabelText('Password *').selectOptions('2');

  await screen.getByText('Preview import', { exact: true }).click();

  await expect.element(screen.getByText('Review your import.')).toBeInTheDocument();
  await expect
    .element(screen.getByText('no key/value pairs matched the detected format', { exact: false }))
    .toBeInTheDocument();
});
