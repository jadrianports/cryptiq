// apps/site/src/tests/frontDoor.spec.ts
//
// Phase 39 Plan 03, Task 3. DOM proofs for the download front door + verify
// section (DEMO-09/12/13) — render(App) + querySelector, mirroring
// containment.spec.ts's render+assert shape (39-PATTERNS.md).
//
//   - DEMO-09: the Windows download href matches the tag-generated
//     release-asset pattern and points ONLY at github.com/jadrianports/cryptiq
//     — never a re-hosted binary (D-12).
//   - DEMO-13: the copy-ready `gh attestation verify` command and the live
//     SHA256SUMS link are both present, and NO 64-hex SHA-256 digest is baked
//     anywhere in the rendered page (D-13, 39-RESEARCH.md Pitfall 5 — a
//     verification PROCEDURE, never a stale baked hash).
//   - D-11/D-15: the macOS "coming soon" slot is non-interactive (no <a>/
//     <button>), and the extension "coming" slot is present.
//   - DEMO-12: 2-4 labeled real-app screenshot placeholder slots exist.

import { describe, expect, it } from 'vitest';
import { render } from 'vitest-browser-svelte';
import App from '../App.svelte';

describe('front door — download links, verify procedure, screenshot placeholders (DEMO-09/12/13)', () => {
  it('download link href matches the tag-generated release-asset URL and is github.com-only', () => {
    const { container } = render(App);

    const link = container.querySelector<HTMLAnchorElement>('a[href*="/releases/download/"]');
    expect(link).not.toBeNull();
    const href = link?.getAttribute('href') ?? '';

    expect(href.startsWith('https://github.com/jadrianports/cryptiq/releases/download/')).toBe(
      true,
    );
    expect(href).toContain('Cryptiq_');
    expect(href).toMatch(/_x64-setup\.exe$/);

    // Never a re-hosted binary — the only host in this href is github.com.
    expect(new URL(href).host).toBe('github.com');
  });

  it('the verify section shows the gh attestation verify command + the live SHA256SUMS link, with NO baked hex digest', () => {
    const { container } = render(App);
    const text = container.textContent ?? '';

    expect(text).toContain('gh attestation verify <downloaded-file> --repo jadrianports/cryptiq');

    const sha256sumsLink = Array.from(container.querySelectorAll<HTMLAnchorElement>('a')).find(
      (a) => (a.getAttribute('href') ?? '').includes('/releases/latest/download/SHA256SUMS'),
    );
    expect(sha256sumsLink).toBeDefined();
    expect(sha256sumsLink?.getAttribute('href')).toBe(
      'https://github.com/jadrianports/cryptiq/releases/latest/download/SHA256SUMS',
    );

    // DEMO-13/Pitfall 5: no baked 64-hex SHA-256 digest anywhere on the page
    // (the printed core commit SHA is a 40-hex git SHA, not a 64-hex SHA-256
    // checksum, so this pattern does not false-positive on it).
    expect(text).not.toMatch(/\b[0-9a-f]{64}\b/i);
  });

  it('macOS renders as a non-interactive "coming soon" slot; the extension "coming" slot is present', () => {
    const { container } = render(App);
    // Collapse whitespace/newlines from the rendered template's own line
    // breaks so this assertion isn't sensitive to incidental JSX formatting.
    const text = (container.textContent ?? '').replace(/\s+/g, ' ').trim();

    expect(text).toContain('macOS — coming soon');
    expect(text).toContain(
      'Browser extension — click-to-fill via a local bridge, never the network. Standalone install: coming soon.',
    );

    // macOS must never be an <a>/<button> — it's a plain, non-interactive div.
    const macOsInteractive = Array.from(
      container.querySelectorAll<HTMLElement>('a, button'),
    ).find((el) => (el.textContent ?? '').includes('macOS'));
    expect(macOsInteractive).toBeUndefined();

    // Mobile desktop-only line (D-11).
    expect(text).toContain(
      "Desktop-only today, by design — the live demo above still runs on your phone.",
    );
  });

  it('2-4 labeled real-app screenshot placeholder slots exist (DEMO-12)', () => {
    const { container } = render(App);
    const placeholders = Array.from(container.querySelectorAll('div')).filter((el) =>
      (el.textContent ?? '').trim() === '[Screenshot coming soon]',
    );
    expect(placeholders.length).toBeGreaterThanOrEqual(2);
    expect(placeholders.length).toBeLessThanOrEqual(4);
  });
});
