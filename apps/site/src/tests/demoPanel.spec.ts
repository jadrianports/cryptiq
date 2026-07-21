// apps/site/src/tests/demoPanel.spec.ts
//
// Phase 39 Plan 02, Task 3. Closes the UI-level falsifiability gap: 39-01
// proved the Worker itself (real Argon2id/AEAD, real postMessage boundary);
// this spec proves the UI WIRING ON TOP of it, driven through the actual
// rendered App/DemoPanel/HexGrid components — never a mock, never a
// typecheck-only proof.
//
// Two describe blocks:
//   1. Structural locks — type="text", no <form>/submit, credential-token-
//      free name/id, the printed core-SHA link shape. Fast, no real crypto.
//   2. A single real derive → derive-complete, reused for BOTH a real
//      hex-cell tamper (asserting the REAL VaultCorruptError/VAULT_CORRUPT —
//      never AeadAuthError, which does not exist in packages/core) and a
//      real encrypt-twice (asserting the two rendered grids visibly differ,
//      DEMO-06) — one 256 MiB derivation pays for both assertions.

import { describe, expect, it, vi } from 'vitest';
import { render } from 'vitest-browser-svelte';
import App from '../App.svelte';

describe('demo panel — structural locks (DEMO-10, D-19)', () => {
  it('passphrase input is type=text, credential-token-free, no form/submit; SHA link is well-formed', () => {
    const { container } = render(App);

    const input = container.querySelector('input[type="text"]');
    expect(input).not.toBeNull();
    expect(input?.getAttribute('name')).toBe('demo-vault-value');
    expect(input?.getAttribute('id')).toBe('demo-vault-value');
    expect(input?.getAttribute('autocomplete')).toBe('off');

    // Credential-token-free — including "pass" itself (demo-passphrase-* would fail this).
    const credentialTokens = /user|email|pass|login|secret|identifier/i;
    expect(credentialTokens.test(input?.getAttribute('name') ?? '')).toBe(false);
    expect(credentialTokens.test(input?.getAttribute('id') ?? '')).toBe(false);

    // No <form>, no submit control anywhere on the full page (re-run of the
    // Phase-38 structural lock against the fuller hero DOM).
    expect(container.querySelectorAll('form').length).toBe(0);
    expect(
      container.querySelectorAll('button[type="submit"], input[type="submit"]').length,
    ).toBe(0);

    // No "Unlock" verb anywhere in the rendered text (DEMO-10/D-19).
    expect(container.textContent ?? '').not.toMatch(/unlock/i);

    // Commit SHA credit — font-mono <a> with a 40-hex segment, /tree/, /packages/core.
    const shaLink = Array.from(container.querySelectorAll('a')).find((a) =>
      /\/tree\/[0-9a-f]{40}\/packages\/core/.test(a.getAttribute('href') ?? ''),
    );
    expect(shaLink).toBeDefined();
    expect(shaLink?.className).toContain('font-mono');
  });

  it('the Derive button is present and click-only (no <form>/submit needed to fire it)', () => {
    const screen = render(App);
    const deriveButton = screen.getByRole('button', { name: 'Derive' });
    expect(deriveButton.element()).toBeTruthy();
  });
});

describe('demo panel — real derive drives a real tamper + a real encrypt-twice (DEMO-05/06)', () => {
  it(
    'one real derive, reused for both a rendered hex-cell tamper (VAULT_CORRUPT) and encrypt-twice (two different grids)',
    async () => {
      const screen = render(App);

      // D-17: the post-demo CTA must NOT be rendered before a real
      // derive+tamper cycle has actually happened.
      expect(screen.container.textContent ?? '').not.toContain("Convinced it's real?");

      // The passphrase is pre-filled (D-04) — click Derive directly.
      const deriveButton = screen.getByRole('button', { name: 'Derive' });
      await deriveButton.click();

      // Real ~1s Argon2id derivation — wait for the Encrypt button to appear.
      const encryptButton = screen.getByRole('button', { name: 'Encrypt' });
      await expect.element(encryptButton, { timeout: 20_000 }).toBeVisible();

      await encryptButton.click();

      // DEMO-06: two rendered hex grids, visibly different byte content.
      await vi.waitFor(
        () => {
          const groups = screen.container.querySelectorAll('[role="group"]');
          expect(groups.length).toBe(2);
        },
        { timeout: 10_000 },
      );

      const groups = screen.container.querySelectorAll('[role="group"]');
      const grid1Text = groups[0]?.textContent ?? '';
      const grid2Text = groups[1]?.textContent ?? '';
      expect(grid1Text.length).toBeGreaterThan(0);
      expect(grid1Text).not.toBe(grid2Text);

      // DEMO-05: a real hex-cell click through the rendered HexGrid flips a
      // real byte and re-decrypts through the real Worker — surfacing the
      // REAL VaultCorruptError/VAULT_CORRUPT (never a mock, never
      // AeadAuthError, which does not exist in packages/core).
      const firstCell = groups[0]?.querySelector('button');
      expect(firstCell).not.toBeNull();
      firstCell?.click();

      await vi.waitFor(
        () => {
          const text = screen.container.textContent ?? '';
          expect(text).toContain('VAULT_CORRUPT');
          expect(text).toContain('VaultCorruptError');
        },
        { timeout: 10_000 },
      );

      // The post-demo CTA (D-17) is earned — only after this real
      // derive+tamper cycle just completed.
      expect(screen.container.textContent ?? '').toContain("Convinced it's real?");
    },
    30_000,
  );
});
