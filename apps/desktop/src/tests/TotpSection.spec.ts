// apps/desktop/src/tests/TotpSection.spec.ts
//
// Layer-2 component tests for TotpSection.svelte's ingestion half
// (TOTP-01/02/03/06, D-02/D-03/D-07/D-08/D-10).
//
// Covers:
//   (a) Empty state shows the smart-paste placeholder + "Add from image".
//   (b) A valid raw-Base32 paste shows the parse preview + the one-basket
//       disclosure, and "Save code" calls onSave with the parsed EntryTotp.
//   (c) A garbage paste shows the verbatim fail-closed error and onSave is
//       never called (D-10).
//   (d) A QR image that decodes to null (mocked decodeQrToOtpauthUri) shows
//       the verbatim QR-fail error and onSave is never called (D-10).
//
// Deviation from the 29-04-PLAN.md-specified path
// (`apps/desktop/src/lib/components/__tests__/TotpSection.test.ts`): see the
// identical note in TotpCodeRing.spec.ts — the live vitest.browser.config.ts
// only includes src/tests/**/*.spec.ts. Placed here to match the REAL working
// harness (Rule 3 blocking-issue fix).
//
// decodeQrToOtpauthUri is mocked to isolate the "null decode" branch from a
// real QR-image fixture (this test only needs to prove the UI's fail-closed
// wiring, not jsQR's own decode correctness — that's covered by
// packages/core/src/totp/__tests__/qr.test.ts). parsePastedTotp and every
// other @cryptiq/core export stay REAL via importOriginal.

import { test, expect, beforeEach, afterEach, vi } from 'vitest';
import { render } from 'vitest-browser-svelte';
import { page } from '@vitest/browser/context';
import TotpSection from '../lib/components/TotpSection.svelte';
import type { EntryTotp } from '@cryptiq/core';

vi.mock('@cryptiq/core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cryptiq/core')>();
  return {
    ...actual,
    decodeQrToOtpauthUri: vi.fn(() => null),
  };
});

// A well-known, minimal valid 1x1 transparent PNG — createImageBitmap() needs
// a real decodable image to reach the (mocked) decodeQrToOtpauthUri call.
const ONE_PX_PNG_BASE64 =
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=';

function onePixelPngFile(): File {
  const binary = atob(ONE_PX_PNG_BASE64);
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return new File([bytes], 'qr.png', { type: 'image/png' });
}

// RFC 4648 Base32 alphabet, valid alphabet — routes through the raw-Base32
// branch of parsePastedTotp (resolves SHA1/6/30 defaults, no issuer/label).
const VALID_BASE32_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  vi.restoreAllMocks();
});

test('(a) empty state shows the smart-paste placeholder + "Add from image"', async () => {
  const screen = render(TotpSection, {
    entryId: null,
    totp: undefined,
    onSave: () => {},
    onRemove: () => {},
  });

  await expect
    .element(screen.getByPlaceholder('Paste otpauth:// link or setup key'))
    .toBeVisible();
  await expect
    .element(screen.getByRole('button', { name: 'Add from image' }))
    .toBeVisible();
  await expect.element(screen.getByText('No 2FA code yet')).toBeVisible();
});

test('(b) a valid Base32 paste shows the preview + disclosure; Save code calls onSave', async () => {
  let saved: EntryTotp | null = null;

  const screen = render(TotpSection, {
    entryId: null,
    totp: undefined,
    onSave: (totp: EntryTotp) => {
      saved = totp;
    },
    onRemove: () => {},
  });

  const input = screen.getByPlaceholder('Paste otpauth:// link or setup key');
  await input.fill(VALID_BASE32_SECRET);
  (input.element() as HTMLInputElement).blur();

  // Preview rows + one-basket disclosure appear.
  await expect.element(screen.getByText('SHA1')).toBeVisible();
  await expect.element(screen.getByText('every 30s')).toBeVisible();
  await expect
    .element(screen.getByText(/one vault/i))
    .toBeVisible();

  await screen.getByRole('button', { name: 'Save code' }).click();

  expect(saved).not.toBeNull();
  expect((saved as unknown as EntryTotp).secret).toBe(VALID_BASE32_SECRET);
  expect((saved as unknown as EntryTotp).algorithm).toBe('SHA1');
  expect((saved as unknown as EntryTotp).digits).toBe(6);
  expect((saved as unknown as EntryTotp).period).toBe(30);

  // Preview clears back to the empty state after save.
  await expect.element(screen.getByText('No 2FA code yet')).toBeVisible();
});

test('(c) a garbage paste shows the fail-closed inline error; onSave is never called (D-10)', async () => {
  const onSave = vi.fn();

  const screen = render(TotpSection, {
    entryId: null,
    totp: undefined,
    onSave,
    onRemove: () => {},
  });

  const input = screen.getByPlaceholder('Paste otpauth:// link or setup key');
  await input.fill('not a valid otpauth link or secret!!!');
  (input.element() as HTMLInputElement).blur();

  await expect
    .element(
      screen.getByText("That doesn't look like an otpauth:// link or a Base32 setup key."),
    )
    .toBeVisible();

  expect(onSave).not.toHaveBeenCalled();
  // Fail-closed: no preview was set, still the empty state.
  await expect.element(screen.getByText('No 2FA code yet')).toBeVisible();
});

test('(d) a QR image that decodes to null shows the QR-fail error; onSave is never called (D-10)', async () => {
  const onSave = vi.fn();

  const screen = render(TotpSection, {
    entryId: null,
    totp: undefined,
    onSave,
    onRemove: () => {},
  });

  const fileInputEl = screen.container.querySelector('input[type="file"]');
  expect(fileInputEl).not.toBeNull();

  await page.elementLocator(fileInputEl as HTMLInputElement).upload(onePixelPngFile());

  await expect
    .element(screen.getByText("Couldn't find a TOTP QR code in that image."))
    .toBeVisible();

  expect(onSave).not.toHaveBeenCalled();
  await expect.element(screen.getByText('No 2FA code yet')).toBeVisible();
});

// ---------------------------------------------------------------------------
// Filled/view-mode state (29-05: TotpCodeRing mount + seed reveal + remove-
// confirm + editable label/issuer + persistent inline disclosure,
// D-04/D-06/D-07/D-11/D-12, TOTP-04/06).
// ---------------------------------------------------------------------------

const FILLED_TOTP: EntryTotp = {
  secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
  algorithm: 'SHA1',
  digits: 6,
  period: 30,
  label: 'alice@example.com',
  issuer: 'Example Corp',
};

test('(e) filled state renders TotpCodeRing and masks the raw secret by default', async () => {
  const screen = render(TotpSection, {
    entryId: 'entry-1',
    totp: FILLED_TOTP,
    onSave: () => {},
    onRemove: () => {},
  });

  // TotpCodeRing is present (its tap-to-copy code button is a stable anchor).
  await expect.element(screen.getByRole('button', { name: 'Copy 2FA code' })).toBeVisible();

  // The raw secret is NOT in the DOM until revealed.
  await expect.element(screen.getByText(FILLED_TOTP.secret)).not.toBeInTheDocument();
  await expect.element(screen.getByText('hold to peek')).toBeVisible();

  // Toggling reveal shows the raw secret as read-only text (never an <input>).
  await screen.getByRole('button', { name: 'Show setup key' }).click();
  await expect.element(screen.getByText(FILLED_TOTP.secret)).toBeVisible();
  const revealedSecretEl = screen.container.querySelector(`input[value="${FILLED_TOTP.secret}"]`);
  expect(revealedSecretEl).toBeNull();

  // The persistent inline one-basket disclosure is present (CVV-precedent class match).
  const disclosureEl = screen.getByText(/one vault/i).element();
  expect(disclosureEl.className).toContain('text-cryptiq-fg-subtle');
});

test('(f) Remove opens a confirm modal; confirming calls onRemove', async () => {
  const onRemove = vi.fn();

  const screen = render(TotpSection, {
    entryId: 'entry-1',
    totp: FILLED_TOTP,
    onSave: () => {},
    onRemove,
  });

  await expect.element(screen.getByRole('alertdialog')).not.toBeInTheDocument();

  await screen.getByRole('button', { name: 'Remove 2FA code' }).click();

  await expect.element(screen.getByRole('alertdialog')).toBeVisible();
  await expect.element(screen.getByText('Remove 2FA code?')).toBeVisible();
  expect(onRemove).not.toHaveBeenCalled();

  // Confirm button inside the modal shares its accessible name with the
  // trigger — scope to the dialog to click the actual confirm action.
  await screen
    .getByRole('alertdialog')
    .getByRole('button', { name: 'Remove 2FA code' })
    .click();

  expect(onRemove).toHaveBeenCalledOnce();
});

test('(g) label/issuer edits call onSave with secret/algorithm/digits/period unchanged (D-12)', async () => {
  let saved: EntryTotp | null = null;

  const screen = render(TotpSection, {
    entryId: 'entry-1',
    totp: FILLED_TOTP,
    onSave: (totp: EntryTotp) => {
      saved = totp;
    },
    onRemove: () => {},
  });

  const issuerField = screen.getByRole('textbox', { name: 'TOTP issuer' });
  await issuerField.fill('New Issuer');
  (issuerField.element() as HTMLInputElement).blur();

  expect(saved).not.toBeNull();
  const savedIssuer = saved as unknown as EntryTotp;
  expect(savedIssuer.issuer).toBe('New Issuer');
  expect(savedIssuer.label).toBe(FILLED_TOTP.label);
  expect(savedIssuer.secret).toBe(FILLED_TOTP.secret);
  expect(savedIssuer.algorithm).toBe(FILLED_TOTP.algorithm);
  expect(savedIssuer.digits).toBe(FILLED_TOTP.digits);
  expect(savedIssuer.period).toBe(FILLED_TOTP.period);
});
