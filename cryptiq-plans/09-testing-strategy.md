# 09 — Testing Strategy

A password manager does not fail because a button was misaligned. It fails because the
crypto had a subtle bug and silently exposed every secret. So testing effort is
deliberately **unequal**: relentless on the security-critical core, reasonable on the UI,
light on the fully-assembled native app. This document defines that split so tests are
built in from Milestone 1, not bolted on later.

## The three layers

Coffer's architecture (`01-architecture.md`) splits cleanly, and testing follows the split:

| Layer | What it is | How it is tested | How hard we test it |
|---|---|---|---|
| `core` | Pure-TS crypto, vault format, entries, generator, audit, import | **Vitest** unit tests — no browser, no Tauri | Relentlessly |
| UI components | Svelte components (screens, forms, lists) | **Playwright** or Vitest browser mode, against components in a browser harness | Reasonably |
| Whole native app | The assembled Tauri app — real window, Rust file IO, OS clipboard | **Tauri WebDriver** (`tauri-driver` + WebdriverIO), or careful manual testing | Lightly for v1 |

## Layer 1 — `core` (Vitest) — this is where testing effort goes

`core` is pure TypeScript with zero UI and zero platform code, so it is tested directly
with **Vitest** — no browser, no Tauri shell, no Playwright. This is ~80% of the real
testing value and it is where attention belongs.

Required `core` test coverage (this is the definition of done for the crypto — see
`02-security-design.md` and `06-build-plan.md` Milestone 1):

- **Round-trip:** create -> save -> load -> unlock -> data is byte-identical.
- **Wrong secret:** wrong master password and wrong recovery key each fail cleanly.
- **Tamper detection:** flipping any byte of ciphertext, nonce, or header causes a
  detected authentication failure — never silent garbage.
- **Padding:** vaults with very different entry counts produce the same file size, and
  padding strips back to the exact original data.
- **Recovery path:** vault opens via recovery key; master-password change re-wraps
  correctly and leaves data intact.
- **Migration:** sample vaults from every past format version still open and upgrade; the
  back-up / migrate-a-copy / verify / swap pattern is exercised.
- **Known-answer checks:** libsodium primitives behave as expected on the target platform.
- **Entry logic:** CRUD, tombstones, `passwordHistory` cap, `needsSiteUpdate`,
  `generatorPreset`, derived password age.
- **Generator:** correct length/character-class behavior; passphrase mode; presets.
- **Audit:** weak / reused / stale detection flags the right entries.
- **CSV import:** known browser formats map correctly; the generic fallback works;
  duplicates are detected.

If a `core` behavior is not covered by a test, it is not done.

## Layer 2 — UI components (Playwright / Vitest browser mode)

Svelte components are just web components — they can be rendered and driven in a
browser-like harness *without* the Tauri shell existing. A Playwright MCP genuinely helps
here: render the unlock screen, the entry list, the generator, the setup flow, and assert
behavior (typing, clicking, "this appeared", "purge asked for confirmation").

Worth covering: unlock success/failure, the first-run explainer flow, entry create/edit,
search filtering, the generator and presets, the confirm-on-purge dialog, the
master-password re-prompt. These need a fast harness, not the full app.

Note: the UI calls into `core` and a storage adapter. In component tests, use an in-memory
fake storage adapter so tests are fast and deterministic.

## Layer 3 — whole native app (Tauri WebDriver, or manual)

**Important constraint:** standard Playwright drives *browsers* (Chromium/Firefox/WebKit).
A Tauri app is a native window using the OS webview, launched by a Rust process —
Playwright does not attach to it out of the box. Tauri's own end-to-end path uses
**WebDriver** via `tauri-driver` with a runner like WebdriverIO. That is a different tool
from Playwright.

For v1, full native-app end-to-end automation is **optional** — it is reasonable to keep
this layer light and rely on careful manual testing of the assembled app (does it really
write the file, does the OS clipboard really clear, does auto-lock really fire). If/when
deeper native E2E is wanted, use the Tauri WebDriver path, not Playwright.

## What to test per milestone (build it in, do not defer)

- **Milestone 1-2 (`core`):** the full Vitest suite above. Non-negotiable; the phase is
  not done without it.
- **Milestone 3 (storage adapter):** test load/save/exists and backup rotation against a
  temp directory.
- **Milestone 4-8 (UI):** add Layer-2 component tests alongside each screen as it is
  built — not in a separate "testing milestone" at the end.
- **Milestone 9 (release):** CI runs the full `core` + component suites on every build;
  a red suite blocks a release.

## Principle

Test `core` relentlessly. Test the UI reasonably. Test the native app lightly. Effort
follows risk — and in a password manager, the risk is the crypto.

## Caveat on tooling

Exact capabilities of any specific Playwright MCP plugin may have changed; check its
current docs for any added Tauri/WebView support before relying on it. The stable fact:
Playwright drives browsers; full Tauri end-to-end needs WebDriver.
