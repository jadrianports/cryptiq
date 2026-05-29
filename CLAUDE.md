<!-- GSD:project-start source:PROJECT.md -->

## Project

**Cryptiq**

Cryptiq is a local-first, self-built desktop password manager. Your passwords live
in a single encrypted file (`.cryptiq`) on your own machine — no account, no
server, no subscription, no company. You built it, so you can audit it.

The user is the primary target: someone tired of password-manager subscription
paywalls who wants a tool they fully understand and trust. Friends installing
Cryptiq keep their own separate vault — Cryptiq never shares secrets between
users.

**Core Value:** **Passwords off plaintext notes and into strong, auditable, free-forever
encryption — without renting it from anyone.** If everything else is broken or
delayed, the encrypted vault file with correct crypto is what must work.

### Constraints

- **Tech stack (locked):** Tauri v2 shell, Svelte 5 (runes) + TypeScript + Vite UI, Tailwind CSS for styling, pure-TS `core` library with `libsodium-wrappers-sumo` (WASM) for all crypto, `zxcvbn-ts` for password strength, `papaparse` for CSV, EFF long wordlist bundled.
- **Tooling:** pnpm + pnpm workspaces, Vitest for `core` tests, ESLint + Prettier, GitHub Actions + `tauri-action` for cross-platform installer builds.
- **Testing (locked):** Vitest for `core` (relentless — non-negotiable), Playwright MCP for Layer-2 Svelte component tests, `tauri-driver` + WebdriverIO for Layer-3 native E2E (Windows + Linux in v1; macOS native E2E is manual until tauri-driver maturity improves).
- **Dev environment:** Windows-first (developer's machine). macOS and Linux builds via CI only — no macOS dev machine.
- **Repo:** Local-only git for now. Public/open-source decision deferred to v1.5 when the auto-updater needs it. Licensing choice (MIT vs GPL) deferred until going public.
- **Cost:** $0 to build and run. OS code-signing (~$99-300/yr) explicitly skipped for v1 — installs show "unidentified developer" warning; user and friends click through.
- **Crypto rules (non-negotiable):** libsodium only; no hand-rolled crypto; CSPRNG only (`Math.random` banned near secrets); fresh nonce every encryption; fail closed; no plaintext secrets to disk or logs ever; lockfile committed; deps pinned and minimized.
- **Core purity rule:** `packages/core` may not import Svelte, Tauri, or Node `fs`. It receives bytes and returns bytes. Storage is supplied via the `VaultStorageAdapter` interface.

<!-- GSD:project-end -->

<!-- GSD:stack-start source:research/STACK.md -->

## Technology Stack

## TL;DR — what to pin

| Layer | Pin | Confidence |
|---|---|---|
| Tauri JS API | `@tauri-apps/api@^2.11.0` | HIGH |
| Tauri CLI | `@tauri-apps/cli@^2.11.2` | HIGH |
| Tauri Rust plugins | `tauri-plugin-*@2` (use `^2`) | HIGH |
| Svelte | `svelte@^5.55.9` (runes, stable) | HIGH |
| Vite | `vite@^7.0.0` or `^6.x` (Tauri v2 supports both; Tauri starter uses v6) | HIGH |
| Tailwind | **`tailwindcss@^4.1.7`** + `@tailwindcss/vite@^4.1.7` (see decision below) | HIGH |
| libsodium | `libsodium-wrappers-sumo@^0.7.15` (stable line; do **not** chase `0.8.x`) | HIGH |
| zxcvbn-ts | `@zxcvbn-ts/core@^3.0.4` + `@zxcvbn-ts/language-common` + `@zxcvbn-ts/language-en` | HIGH |
| papaparse | `papaparse@^5.5.3` + `@types/papaparse` | HIGH |
| pnpm | `pnpm@^10` (current `latest: 10.x`; corepack pin in `package.json#packageManager`) | HIGH |
| Vitest | `vitest@^3.2.4` (stable) — v4 ships now too but pin to 3.x for the crypto suite | HIGH |
| WebdriverIO | `webdriverio@^9.x` (v9 is current `latest`) | HIGH |
| tauri-driver | `cargo install tauri-driver --locked` (latest from crates.io) | HIGH |

## Recommended Stack

### Core Technologies

| Technology | Version | Purpose | Why Recommended |
|------------|---------|---------|-----------------|
| **Tauri** (JS API) | `^2.11.0` | App shell, IPC, capability/permission system, OS integration | Tauri 2.0 went stable Oct 2024; the 2.x line is now at 2.11.x (`@tauri-apps/api`, May 2026). Small binaries, OS-native WebView (Chromium on Win, WKWebView on macOS, WebKitGTK on Linux), explicit capability allowlist, real mobile path later. (Context7: `/websites/v2_tauri_app`) |
| **Tauri CLI** | `^2.11.2` | `tauri dev` / `tauri build` / `tauri info` | Pair with the JS API minor; CLI moves slightly ahead of the api package. (npm dist-tags) |
| **Svelte** | `^5.55.9` | UI framework with runes API (`$state`, `$derived`, `$effect`) | Svelte 5 stable since late 2024; runes replace the legacy reactive `let`/store model and work cleanly in `.svelte` and `.svelte.js`/`.svelte.ts` modules. (Context7: `/sveltejs/svelte`) |
| **Vite** | `^7.0.0` (or `^6.x` if matching the Tauri starter) | Frontend dev server + bundler | First-class with Tauri; the official `create-tauri-app` Svelte template uses Vite. v7 is current `latest` per npm dist-tags. v6 still supported. |
| **Tailwind CSS** | **`^4.1.7`** (v4) | Utility-first styling | Decision resolved below — v4 is the correct pick for Cryptiq. |
| **libsodium-wrappers-sumo** | `^0.7.15` | All crypto: Argon2id, XChaCha20-Poly1305 IETF, BLAKE2b, CSPRNG | The `-sumo` build is the **only** variant exposing `crypto_pwhash_*` (Argon2id). The standard `libsodium-wrappers` build *omits* it. (Verified: jedisct1/libsodium.js README). Pin `^0.7.x` — see version-compatibility note below. |
| **pnpm** | `^10` | Package manager + workspaces | Required for the monorepo layout in `01-architecture.md`. Pin via `package.json#packageManager` and `corepack enable`. |

### Supporting Libraries

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `@tauri-apps/plugin-fs` | `^2.5.1` | Scoped filesystem access for the vault file + backups | Phase 1 scaffold; scope must be locked to the chosen vault directory only (no `$HOME/*` blanket). |
| `@tauri-apps/plugin-clipboard-manager` | `^2.3.2` | Read/write/clear clipboard (auto-clear ~25s) | Phase 5+ when per-field copy lands. Enable only `clipboard-manager:allow-write-text` and `clipboard-manager:allow-clear`. **Deny** `read-text` (Cryptiq never needs to read the clipboard). |
| `@tauri-apps/plugin-process` | `^2.3.1` | `relaunch()` after updater installs | v1.5 (updater). Keep out of v1 capabilities. |
| `@tauri-apps/plugin-updater` | `^2.10.1` (Rust crate `tauri-plugin-updater@2`) | Signed auto-updates | v1.5 only. Pair with `plugin-process`. |
| `@tauri-apps/plugin-os` | `^2.3.2` | Platform detection (os version, arch) | Optional. Only if needed for telemetry-free debugging. |
| `@tauri-apps/plugin-stronghold` | (Rust crate `tauri-plugin-stronghold@2`) | Encrypted secret store on the Rust side | **NOT recommended for Cryptiq v1.** Stronghold is its own vault format; Cryptiq's whole point is its own well-defined vault file. Keep crypto in TS `core`. For v1.5 OS-keychain unlock, use a small custom keyring plugin (Windows Credential Manager / macOS Keychain) — Stronghold would be a duplicate vault. |
| `@zxcvbn-ts/core` | `^3.0.4` | Password strength scoring (master password meter + entry audit "weak" flag) | Phase 4 setup screen + Phase 6 audit. v4 beta exists; stay on v3 stable. |
| `@zxcvbn-ts/language-common` + `language-en` | matching `^3.x` | Wordlist + translation packs for zxcvbn | Bundle with core. |
| `papaparse` | `^5.5.3` | CSV import for Chrome/Edge, Firefox, Bitwarden + generic | Phase 7 (import). Pure-JS, browser-safe, RFC 4180 compliant. |
| `@types/papaparse` | latest | TypeScript types | dev dep; papaparse ships no built-in types. |
| `vitest` | `^3.2.4` | Crypto suite (round-trip, tamper, KAT) — node env | Phase 2 crypto suite. v4 is out (`4.1.7` latest) but pin to **v3** for the crypto layer because v3 is the maturity peak; consider v4 upgrade *after* Phase 2 ships. |
| `@vitejs/plugin-svelte` | `^5.x` (matches Svelte 5) | Vite plugin for Svelte | Required by Vite setup. |
| EFF Long Wordlist | Bundled JSON | Passphrase generation | Static file `packages/core/src/generator/eff-long.json`. Source: https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt (7,776 words). One-time copy with attribution comment in source; no runtime fetch. |

### Development Tools

| Tool | Purpose | Notes |
|------|---------|-------|
| `tauri-driver` (cargo) | WebDriver bridge for native E2E | Install: `cargo install tauri-driver --locked`. Linux uses `WebKitWebDriver` (apt: `webkit2gtk-driver`); Windows uses `Microsoft Edge Driver` (auto-fetched). **macOS not supported by tauri-driver in v2** — manual E2E only on macOS (matches the constraint already in `09-testing-strategy.md`). |
| `webdriverio` | E2E test runner against tauri-driver | v9 is current. Use `framework: 'mocha'` per the Tauri docs sample. |
| `mocha` + `chai` | E2E test harness (BDD + assertions) | `mocha@^11`, `chai@^5`. Per the official `v2.tauri.app/develop/tests/webdriver/example/webdriverio` page. |
| `tauri-action` (GitHub Actions) | Cross-platform installer build in CI | Park until the repo goes online (per project plan). |
| `eslint` + `prettier` | Lint + format | Use Svelte plugin + svelte-check; pin in v1 scaffold. |
| `@tailwindcss/vite` | Tailwind v4 Vite plugin | Replaces the v3 PostCSS pipeline entirely. |
| `corepack` | Lock package manager via Node | Pin `pnpm` version in `package.json#packageManager`. |

## Installation (Phase 1 scaffold target)

# Create the Tauri v2 + Svelte 5 + TS skeleton (the official template is current and uses Vite)

# Move into the workspace and install root-level dev deps

# Frontend (apps/desktop) deps

# Core package — pure TS, only crypto/utility deps

# Native E2E (root-level, separate package)

## Open Question Answers (the heart of this brief)

### Q1 — Tauri v2: current versions + capability/permission API stability

- `@tauri-apps/api` → **2.11.0**
- `@tauri-apps/cli` → **2.11.2** (Tauri 2.0.0 shipped Oct 2024; the 2.x line is mature)
- `@tauri-apps/plugin-fs` → **2.5.1**
- `@tauri-apps/plugin-clipboard-manager` → **2.3.2**
- `@tauri-apps/plugin-updater` → **2.10.1**
- `@tauri-apps/plugin-process` → **2.3.1**
- `@tauri-apps/plugin-os` → **2.3.2**

### Q2 — Svelte 5 runes pattern for the decrypted-vault in-memory state

### Q3 — Tailwind v3 vs v4: **DECISION — Use v4 (`tailwindcss@^4.1.7`)**

| v3 | v4 |
|---|---|
| `@tailwind base; @tailwind components; @tailwind utilities;` in CSS | `@import "tailwindcss";` |
| PostCSS plugin `tailwindcss` + `autoprefixer` | `@tailwindcss/vite` plugin (or `@tailwindcss/postcss` if not using Vite) |
| `tailwind.config.js` auto-detected | JS config still works but must be opted in via `@config "./tailwind.config.js";` |
| `theme(colors.red.500)` in CSS | Prefer `var(--color-red-500)` (all theme values exposed as CSS vars automatically) |
| `corePlugins`, `safelist`, `separator` in JS config | Not supported in JS config; use `@source inline()` for safelisting |
| Implicit `@layer base` reset | More restrained reset; some classes (e.g. default border colors) changed defaults |
| `text-opacity-*` / `bg-opacity-*` utilities | Removed; use opacity modifiers like `bg-black/50` |

### Q4 — libsodium-wrappers-sumo + Argon2id calibration

- libsodium's Argon2id **requires `opslimit >= 3`** — Cryptiq's plan-doc default `3` is the floor, not a "low" value. Confirmed at Context7 `/jedisct1/libsodium-doc` ("Notes" section).
- The plan-doc value of `MEMLIMIT = 268435456` (256 MiB) is the **minimum** Cryptiq accepts. Use it as the calibration floor — never drop below. Faster machines push memlimit up; slow machines stay at floor and accept the ~1s+ unlock as the security guarantee.
- libsodium-wrappers-sumo's `crypto_pwhash` returns the derived bytes directly (no return code; throws on failure). Constants like `crypto_pwhash_SALTBYTES` (16), `crypto_pwhash_ALG_ARGON2ID13` (= 2), and `crypto_pwhash_OPSLIMIT_INTERACTIVE` are exposed on the module.
- The constants `crypto_pwhash_OPSLIMIT_INTERACTIVE` (= 2 ops, 64 MiB) and `crypto_pwhash_OPSLIMIT_SENSITIVE` (= 4 ops, 1024 MiB) are reference points only — Cryptiq calibrates, doesn't use these constants directly. Note: `INTERACTIVE` = 2 ops would actually be **rejected** by libsodium for Argon2id (min 3) and is more relevant to the older Argon2i — another reason to calibrate explicitly rather than use the named constants.
- **Store the calibrated `{ opsLimit, memLimit, algorithm, salt }` in the vault header**, as the plan-doc already specifies, so the same machine (or a faster one) can unlock without re-calibration.
- Calibration timing can vary 10–30% on a busy machine. The tolerance band (`TARGET_TOLERANCE_MS = 200`) lets `measure` settle. Optionally average 2 samples in production — kept single-sample here for clarity.

### Q5 — Vitest + Svelte 5 + libsodium WASM

| Surface | Vitest env | Provider |
|---|---|---|
| `packages/core` (crypto, vault, entries, generator, audit, import) | **`node` environment** | none — pure ESM + WASM |
| `apps/desktop` Svelte components | **Browser Mode** | `playwright` provider via `@vitest/browser-playwright` + `vitest-browser-svelte` |

- `pool: 'forks'` (default in Vitest 3) avoids worker-thread WASM init quirks.
- `singleFork: true` serializes tests so each `crypto_pwhash` call gets its 256+ MiB without OOMing parallel workers. Cryptiq's crypto suite isn't time-critical (run on CI + locally) so single-fork is the safe call.
- `testTimeout: 30_000` accommodates the calibration test that intentionally walks the memlimit ladder.

### Q6 — tauri-driver + Tauri v2: still current?

### Q7 — pnpm workspaces + Tauri v2 gotchas

## Alternatives Considered

| Recommended | Alternative | When to Use Alternative |
|-------------|-------------|-------------------------|
| Tauri v2 | Electron | Never for this project (binary size, attack surface). Tauri v2 was chosen for explicit reasons in the plan. |
| Svelte 5 (runes) | Svelte 4 (stores) | If you find Svelte 5's compiler-level type checking insufficient or hit a paid library that's runes-incompatible. Cryptiq has no such constraints. |
| Tailwind v4 | Tailwind v3.4 LTS | If you must target Safari ≤16.3 (e.g. legacy macOS users still on Big Sur). Cryptiq targets current OSes. |
| libsodium-wrappers-sumo | Web Crypto API + a separate Argon2 lib (e.g. `hash-wasm`) | Never — splitting crypto across two libs **increases** attack surface. PROJECT.md rules this out. |
| libsodium-wrappers-sumo `0.7.x` | `0.8.x` | After 0.8 has 6+ months in the wild. Cryptiq cannot eat regressions in a crypto suite. |
| `@zxcvbn-ts/core` v3 | dropbox/zxcvbn (original JS) | Never — the original is unmaintained (~2017), no types, browser-only quirks. |
| Vitest 3 (core) | Vitest 4 | Migrate after Phase 2 ships green. v4 changed the browser-provider import shape (`@vitest/browser-playwright` is now a separate package) — not a problem for `core` tests, but no upside to bumping mid-phase. |
| WebdriverIO + tauri-driver | Playwright | Playwright cannot drive Tauri windows (no CDP in WKWebView/WebKitGTK). Confirmed in `09-testing-strategy.md` and re-verified here. |
| pnpm | npm | npm doesn't enforce strict isolation; cheaper deps slip in. pnpm's isolation aligns with Cryptiq's "minimize/audit deps" rule. |
| pnpm | bun | Bun's pkg manager is fast but young; the project doesn't need bun's perf, and pnpm's lockfile format + workspaces are battle-tested. |

## What NOT to Use

| Avoid | Why | Use Instead |
|-------|-----|-------------|
| `libsodium-wrappers` (non-sumo) | Missing `crypto_pwhash_*` — Argon2id is not exposed | `libsodium-wrappers-sumo` |
| `bcrypt` / `scrypt` for KDF | Not memory-hard / weaker than Argon2id; bcrypt has a 72-byte password truncation footgun | Argon2id via libsodium |
| `crypto.subtle.deriveBits` with PBKDF2 | Web Crypto has no Argon2 — PBKDF2 is the wrong tool for password storage in 2026 | libsodium Argon2id |
| Tauri v1 (`@tauri-apps/api@^1`) | v1 has the old monolithic API surface; capability system is fundamentally different | Tauri v2 |
| `plugin-stronghold` for vault storage | Would duplicate Cryptiq's own vault format and confuse the threat model | Cryptiq's own vault file via `plugin-fs` |
| Svelte stores (`writable`/`readable`) for new code | Legacy; runes are the official Svelte 5 model | `$state` in `.svelte.ts` modules |
| Tailwind v3 + JS config for new project | v4 supersedes; v3 is maintenance-only | Tailwind v4 + CSS `@theme {}` |
| `Math.random()` anywhere near secrets | Not a CSPRNG | `sodium.randombytes_buf(...)` (already a project hard rule) |
| `nodeLinker: hoisted` in pnpm | Defeats isolation; widens accidental-import attack surface | Default isolated linker |
| Global `fs:` scope (e.g. `$HOME/*`) | Tauri capability anti-pattern; the whole point of v2 capabilities is least privilege | `fs:scope` with `{ allow: [{ path: "$APPDATA/Cryptiq/*" }] }` |
| `clipboard-manager:allow-read-text` | Cryptiq never reads the clipboard; granting it expands attack surface for no reason | Only `allow-write-text` + `allow-clear` |

## Version Compatibility

| Package A | Compatible With | Notes |
|-----------|-----------------|-------|
| `@tauri-apps/api@^2.11` | `@tauri-apps/cli@^2.11` | Keep major + minor aligned; the API and CLI move together. |
| `@tauri-apps/api@2.x` | `tauri-plugin-*@2.x` (Rust) + `@tauri-apps/plugin-*@2.x` (JS) | Always use `^2` floors for both Rust and JS sides; they're versioned independently per-plugin but share the v2 contract. |
| `svelte@^5` | `@sveltejs/vite-plugin-svelte@^5` | Svelte 5 *requires* the v5 vite plugin (v4 doesn't understand runes). |
| `vite@^7` | `@sveltejs/vite-plugin-svelte@^5` + `@tailwindcss/vite@^4` | All current. v6 also fine; v5 too old for the latest plugin features. |
| `tailwindcss@^4` | `@tailwindcss/vite@^4` (NOT the v3 PostCSS plugin) | Hard pairing — `tailwindcss@4` + `tailwindcss@3` toolchain will silently misbehave. |
| `libsodium-wrappers-sumo@^0.7.15` | Node ≥18; modern browsers | WASM bundled in JS; no separate `.wasm` file. |
| `vitest@^3` | `@vitest/coverage-v8@^3` + `vitest-browser-svelte@^1` | Use the v3 line; v4 changed browser-provider package shape. |
| `webdriverio@^9` | `mocha@^11` + `chai@^5` + `tauri-driver` (latest from cargo) | Per the official Tauri v2 WebdriverIO example. |
| `pnpm@^10` | Node ≥20 | pnpm 10 dropped Node 18 support; use Node 20 LTS or 22 LTS. |
| `@zxcvbn-ts/core@^3` | `@zxcvbn-ts/language-common@^3` + `@zxcvbn-ts/language-en@^3` | Major must match across the three packages. |

## Sources

- `/websites/v2_tauri_app` — capability/permission system, CSP, clipboard plugin, fs plugin, updater plugin, WebdriverIO example, onFocusChanged API, Tauri 2.0 stable release announcement, core-permissions migration (beta→RC).
- `/tauri-apps/plugins-workspace` — Rust crate versions and plugin install patterns for `tauri-plugin-fs`, `-clipboard-manager`, `-updater`, `-stronghold`, `-os`.
- `/sveltejs/svelte` — Svelte 5 runes (`$state`, `$derived`, `$effect`), classes with reactive state, shared state via `.svelte.js`/`.svelte.ts` modules, `createContext` pattern, v5 migration guide.
- `/websites/tailwindcss` — v4 upgrade guide (CSS `@import`, `@tailwindcss/vite`, `@theme` blocks, JS-config opt-in via `@config`), browser compatibility floor (Chrome 111 / Safari 16.4 / Firefox 128).
- `/jedisct1/libsodium-doc` — `crypto_pwhash` signature, OPSLIMIT/MEMLIMIT constants and minimums (`opslimit >= 3` for Argon2id), parameter-selection guidance ("set memlimit to target, opslimit=3, measure, adjust"), `crypto_pwhash_str_needs_rehash`.
- `/vitest-dev/vitest` — Browser Mode setup with Playwright provider, environment options, WASM testing, framework integration (`@sveltejs/vite-plugin-svelte`).
- `/vitest-community/vitest-browser-svelte` — `render` API for Svelte components in Browser Mode.
- `/zxcvbn-ts/zxcvbn` — install, factory-class API, v3.x migration from singleton options.
- `/mholt/papaparse` — install, parse options, worker support.
- `/pnpm/pnpm` — `Config` interface (`nodeLinker`, `minimumReleaseAge`, `allowBuilds`), workspace YAML, hoisting patterns.
- https://v2.tauri.app/blog/tauri-20 — Tauri 2.0 stable release (Oct 2024).
- https://v2.tauri.app/reference/webview-versions/ — WebView2/WKWebView/WebKitGTK 4.1 versions.
- https://v2.tauri.app/develop/tests/webdriver/example/webdriverio — current WebdriverIO E2E example.
- https://v2.tauri.app/security/capabilities — capability system reference.
- https://v2.tauri.app/security/csp — CSP hardening guide.
- https://tailwindcss.com/docs/compatibility — browser support floor.
- https://github.com/jedisct1/libsodium.js (README) — `-sumo` vs non-sumo difference, init pattern.
- `npm view <pkg> dist-tags time` for: `libsodium-wrappers-sumo`, `tailwindcss`, `@tauri-apps/api`, `@tauri-apps/cli`, `@tauri-apps/plugin-{fs,clipboard-manager,updater,process,os}`, `svelte`, `vite`, `vitest`, `pnpm`, `@zxcvbn-ts/core`, `papaparse`, `webdriverio`, `mocha`, `chai`.

<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->

## Conventions

Patterns landed in Phase 1 (Scaffold, capabilities, CSP):

- **Workspace layout:** pnpm workspace with `apps/desktop` (Tauri v2 + Svelte 5 + Vite + Tailwind v4 frontend) and `packages/core` (pure-TS library). `@tauri-apps/cli` lives in `apps/desktop/package.json#devDependencies`, NEVER at workspace root (Pitfall 6 defense).
- **Core purity:** `packages/core` must not import `@tauri-apps/*`, `svelte`, `svelte/*`, `node:fs`, `fs`, `node:path`, or `path`. ESLint `no-restricted-imports` block in `eslint.config.js` enforces.
- **No `console.*` in `packages/core`:** ESLint `no-console: 'error'` override on `packages/core/**/*.ts`; test files (`packages/core/**/__tests__/**/*.ts`) are relaxed. Test files are the ONLY allowed console-use site inside core.
- **No `Math.random` anywhere:** ESLint `no-restricted-properties` + `no-restricted-syntax` bans `Math.random` project-wide. Use `sodium.randombytes_buf(...)` even for non-security UI randomness.
- **Underscore-prefix convention for intentionally-unused params/locals:** both `tsconfig.base.json` (`noUnusedParameters`, `noUnusedLocals`) and the project ESLint config (`@typescript-eslint/no-unused-vars` with `argsIgnorePattern: '^_'`) honor `_`-prefixed names.
- **Capability JSON:** `apps/desktop/src-tauri/capabilities/` contains `default.json` (main capability, post-path-choice) + `bootstrap.json` (pre-path-choice, dialog-only). Both have explicit `platforms: ["windows", "macOS"]` (note exact macOS casing per Tauri docs). fs scopes use LITERAL paths only — zero single-`*` segments (defends GHSA-6mv3-wm7j-h4w5). Each `*:default` token is forbidden except `core:default`.
- **CSP:** `tauri.conf.json` `app.security.csp` is the production block (strict: `default-src 'self'`, `script-src 'self' 'wasm-unsafe-eval'`, no localhost:PORT, no `'unsafe-inline'` in script-src); `app.security.devCsp` is a separate dev-relaxed block. Dev relaxations must NEVER appear in production CSP (lint: `scripts/lint/lint-csp.mjs`). Tauri internal protocol hosts `http://asset.localhost` and `http://ipc.localhost` are required in production and recognized by the lint.
- **CI workflows:** `.github/workflows/*.yml` — every `uses:` is a 40-char SHA followed by `# <human-readable-tag>` comment (defends CVE-2025-30066). Dependabot registers the `github-actions` ecosystem in `.github/dependabot.yml` and automatically maintains the SHA-pin format when new releases ship — there is NO config field for it (auto-detection of the format triggers maintenance). Enforcement: `scripts/lint/lint-workflow-sha-pins.mjs`.
- **Single-instance:** `tauri-plugin-single-instance` registered FIRST in `apps/desktop/src-tauri/src/lib.rs`. Second-launch handler calls `set_focus()` + `unminimize()` on the `"main"` webview window.
- **Plugin order in `lib.rs`:** single-instance FIRST, then `tauri_plugin_fs::init()` BEFORE `tauri_plugin_persisted_scope::init()` (per official Tauri docs). Both single-instance and persisted-scope inside `#[cfg(desktop)]` blocks AND gated in `Cargo.toml` `[target.'cfg(any(target_os = "macos", windows))']` (belt-and-braces; Linux excluded per D-15).
- **In-memory vault state:** `apps/desktop/src/lib/state/vault.svelte.ts` exports a module-scoped `VaultSession` singleton with `$state.raw`-backed fields (NOT deep `$state` — defends Pitfall 7 where Svelte's reactive proxy could leak secrets via DevTools). Vault key is a NON-reactive private field (`#vaultKey`). Phase 2 fills the method bodies; the shape is locked.
- **Boot self-test (dev only):** `apps/desktop/src/lib/dev/boot-self-test.ts` runs in dev only via `if (import.meta.env.DEV) { import('./lib/dev/boot-self-test').then(...) }` in `main.ts`. Vite's static replacement of `import.meta.env.DEV` strips this entire dynamic import from production bundles. Verified at end of Phase 1: production `apps/desktop/dist/` contains zero `boot-self-test` / `runBootSelfTest` strings.
- **Custom Node lints:** `scripts/lint/lint-*.mjs` (workflow SHA pins, capability globs, capability platforms, CSP, supply chain). Each is pure Node 20+ stdlib (no external deps), runs in <500ms, and is wired into root `pnpm lint`. CI runs each as a separate job for fail-fast attribution.
- **Lockfile committed:** `pnpm-lock.yaml` AND `apps/desktop/src-tauri/Cargo.lock` are committed. `package-lock.json` and `yarn.lock` are gitignored (Pitfall 6 — Tauri CLI mis-detection visibility).
- **No git operations by agents:** the user runs all git commands. Agents surface commit-worthy moments and suggested commands; the user executes.
- **Phase-completion CLAUDE.md update:** per D-16, every phase's closing step updates this Conventions section + the Architecture section with patterns landed that phase. This is non-optional.

Patterns landed in Phase 2 (Crypto core + vault file format):

- **Single libsodium entry — `getSodium()` (no raw `sodium-wrappers-sumo` imports):** every crypto module imports the WASM handle ONLY via `packages/core/src/crypto/sodium.ts`'s `getSodium()` (awaits `sodium.ready`). Direct `import sodium from 'libsodium-wrappers-sumo'` is BANNED everywhere except `sodium.ts` itself (ESLint `no-restricted-imports`). This guarantees one initialized instance and one place to audit. The Vitest config + the demo `_hooks.mjs` both alias the bare specifier to the working CJS build (the published `.mjs` is broken — imports an unshipped `./libsodium-sumo.mjs` sibling).
- **Combined-mode XChaCha20-Poly1305 IETF only; data blob bound to `VAULT_AD`:** `crypto/aead.ts` seals/opens the entries blob in COMBINED mode (never detached) under associated data `VAULT_AD = "cryptiq-vault\0v1"` (hex `637279707469712d7661756c74007631`), binding the file-format version into the MAC (SEC-06). Key-wrapping (`crypto/wrap.ts`) uses the SAME primitive but with NO associated data — wrapping is key-only, version-binding lives on the data blob. Pinned by KAT-4.
- **DC-3 per-wrap KDF, NO top-level `kdf`:** the Argon2id `{opsLimit, memLimit, salt, algorithm}` live INSIDE each `wrappedKeys[label]` object, never at a vault top level. (Supersedes the top-level `kdf` shown in `cryptiq-plans/03-vault-file-format.md` — enables a future weaker mobile wrap alongside the desktop wrap.) Lint-adjacent: `serialize.test.ts` asserts the serialized doc has no top-level `kdf`.
- **DC-4 open `wrappedKeys` map:** keyed by label; v1 writes `master` (always) + optional `recovery`. The parser TOLERATES unknown labels (future `mobile` / `biometric_<id>`) and refuses to open ONLY on an unknown `version` (VAULT-07). `removeWrappedKey('master')` is refused (would brick the vault).
- **DC-5 generic `tryUnwrap` (no `unlockWithMaster`/`unlockWithRecovery` split):** both unlock paths derive a 32-byte key and hand it to a single `tryUnwrap(wrappedKey, derivationKey)`; a MAC failure returns `null` (a normal branch, not an error) so the unlock flow can try each wrap.
- **DC-6 tiered padding + uint32 LITTLE-ENDIAN length prefix:** the entries JSON is padded to a fixed tier bucket (16 KiB ≤256 KiB, 64 KiB ≤1 MiB, else 256 KiB) before sealing, so the file size leaks only a coarse tier (entry-count hiding). The first 4 bytes are the real length via `DataView.setUint32(0, n, true)` — LE is mandatory and pinned by a padding KAT (`true` on BOTH set and get).
- **DC-7 hand-rolled Crockford Base32 recovery key (version byte + check char, FLAT 54-char contract):** `crypto/recovery.ts` encodes `[0x01 version][32 CSPRNG bytes]` → 53 base32 chars + 1 mod-37 check char = the canonical FLAT 54-char string. The recovery wrap-key is `BLAKE2b(crypto_generichash, 32, raw, domain16="cryptiq-recovery-v1")` — no Argon2id (so `wrappedKeys.recovery.kdf` stores `opsLimit/memLimit = 0` as a domain marker, NOT re-derive params). Decode normalizes (uppercase, strip non-alphanumerics, map look-alikes I/L→1 O→0 U→V), verifies the check char BEFORE the key bytes, then the version byte. **DASH GROUPING IS A PHASE-4 (UI) CONCERN — NOT a crypto invariant**; decode is dash-agnostic.
- **DC-8 verb-first public API; state lives in the CALLER:** `vault/vault.ts` exposes `createVault / unlockVault / saveVault / changeMasterPassword / addWrappedKey / removeWrappedKey`. `UnlockedVault` is PLAIN DATA (no methods, NO vault key) — the 32-byte vault key is returned SEPARATELY and the caller (`VaultSession`) owns its lifecycle + memzero (SEC-09, via the exported `secureWipe`). `unlockVault`'s `secret` is the open union `{ masterPassword } | { recoveryKey }` (DC-10).
- **DC-9 typed errors in `packages/core/src/errors.ts` (single source of truth):** `WrongPasswordError`, `WrongRecoveryKeyError`, `KdfResourceError`, `UnknownVaultVersionError`, `MigrationFailedError`, `VaultCorruptError` — each with a stable readonly `code`. Fail-closed discipline: every decryption/auth/derivation/parse failure surfaces one of these, NEVER a bare `Error` and NEVER partial data (SEC-08). DC-11 tamper tests prove all 9+2 byte regions surface a typed error, never a crash.
- **Calibration: hard FLOOR (256 MiB / 3 ops), NO CEILING (DC-1 deliberate deviation):** `calibrateArgon2id` ramps memory-first at ops=3 then bumps ops at max memory, settling at ≥800 ms; it removes ROADMAP/STATE decision-8's 512 MiB/10-ops ceiling and mitigates via DC-2 `portabilityWarning` (memLimit > 512 MiB). DUAL-PATH OOM: a thrown error OR an all-zeros buffer (libsodium.js #235) is treated as OOM → `KdfResourceError`; a zero buffer is NEVER accepted as a key.
- **Migration: back-up → migrate-copy → VERIFY-BY-COLD-DECRYPT → swap (`vault/migrations/`):** `loadAndMigrate` writes a never-rotated pre-migration backup BEFORE any transform, then verifies the migrated bytes by re-parsing + re-decrypting them with a freshly re-derived key (not a JSON parse, not the original) — a buggy migration that corrupts the ciphertext fails the cold-decrypt and throws `MigrationFailedError` (the original is NOT swapped). v1's production registry is empty (vault starts at v1); the scaffold is exercised with a synthetic v0→v1 migration.
- **Decision 27 — explicit base64 variant on EVERY byte field:** every `sodium.to_base64`/`from_base64` passes `sodium.base64_variants.ORIGINAL` (standard alphabet WITH padding) explicitly — NEVER the libsodium default (URLSAFE_NO_PADDING). Applies to salt, nonce, ciphertext, and all wire-format byte fields.
- **`@cryptiq/core/internal` subpath for demos + KATs:** the `.` public entry re-exports only the verb-first vault API + typed errors; `./internal` (`packages/core/src/internal.ts`) re-exports the crypto primitives for the per-checkpoint demo scripts (`scripts/demo/02-<N>-*.mjs`) and KAT tests without enlarging the public surface.
- **Vitest crypto-suite test seam — fixed floor `kdfParams`:** `createVault`/`changeMasterPassword` accept an optional `kdfParams` (256 MiB / 3 ops floor) so tests skip the ~1s adaptive calibration ladder per call (real Argon2id, just not auto-tuned); production omits it → calibrates. Suite runs under `pool: 'forks'` + `singleFork: true` (serializes the 256 MiB+ Argon2id allocations). Build expensive vaults ONCE per file (`beforeAll`) and reuse the bytes across tamper regions to keep derivation count down. Property tests use bare `fc.assert(fc.asyncProperty(...))` (no `@fast-check/vitest` adapter); the ~100-pair payload fuzz derives the vault key ONCE and varies only the entries (no per-run Argon2id), with a small-`numRuns` full-path property covering arbitrary passwords.

Patterns landed in Phase 3 (Entries, generator, storage adapter, file IO):

- **InnerDoc schema (P3-01):** `createVault` now seals `{ schemaVersion: 1, entries: Entry[], settings: { generator: GeneratorOptions } }` (was `{ entries: [] }`); `EMPTY_ENTRIES` in `vault/vault.ts` upgraded. `entries/crud.ts` `asInnerDoc()` is the SINGLE Pitfall-3 cast site — idempotently upgrades pre-existing Phase-2 `{entries:[]}` dev vaults in place. The Phase-2 wire/outer format is UNCHANGED (guardrail) — only the inner doc shape evolved.
- **Entry CRUD (P3-02):** verbs in `entries/crud.ts` (`addEntry/updateEntry/softDeleteEntry/purgeEntry/listEntries/getEntry/derivePasswordAge/regenerateFromPreset`) mutate `vault.entries` IN PLACE and return the affected Entry; the caller (`VaultSession`, `$state.raw`) reassigns `#vault = { ...vault }` to trigger Svelte reactivity (no deep `$state` proxy — Pitfall 7).
- **Entry IDs (P3-03):** `entries/uuid.ts` `uuidV4FromBytes(sodium.randombytes_buf(16))` — RFC-4122 v4 from CSPRNG bytes; never `Math.random`/`crypto.randomUUID`.
- **Password history (ENTRY-07/09):** single `pushHistory` helper — newest-first `unshift` + cap 10; shared by `updateEntry` and `regenerateFromPreset` (single source for the generatorPreset↔passwordHistory interaction the Phase-3 spec note required to lock).
- **Generator (GEN-01..04, P3-05/06):** `generator/{random,passphrase,entropy}.ts` — `generateRandom`/`generatePassphrase` use `sodium.randombytes_uniform` (modulo-bias-free) + Fisher-Yates; `AMBIGUOUS_CHARS = {l,1,I,O,0}` in `generator/types.ts`; `generateFromOptions(options)` dispatcher (re-exported via index) for preset regen/UI. EFF long wordlist (7,776 words, CC-BY-3.0) bundled at `generator/eff-long.json`. `estimateEntropyBits`/`computePoolSize` are the single entropy source (generator↔estimator kept in sync; module-load `SYMBOLS.length===30` guard).
- **Lock seam (VAULT-09, P3-08/09/10):** `storage/lockLogic.ts` is PURE (`evaluateLock`, `isOlderThan30Min`) — PID-liveness injected as a boolean (the Tauri side computes it); decision union `acquire-free | take-over-stale | cross-host-warn | locked-by-live`. No IO/PID syscalls in core.
- **New typed errors (DC-9):** `EntryNotFoundError` (`ENTRY_NOT_FOUND`), `GeneratorError` (`GENERATOR_INVALID_OPTIONS`) in `errors.ts`.
- **Rust storage commands (`src-tauri/src/commands/vault.rs`):** `vault_write_atomic` = temp-in-same-dir → `sync_all` → **COPY** primary → `.bak.1` (rotate .bak.1–5) → atomic `rename` temp→primary → dir fsync. The COPY (not move) keeps the primary present through a crash (CR-01 crash-safety — the vault file is never absent). `max_backups==0` ⇒ no rotation (content-hash dedup path). `vault_write_named` (pre-migration backup) and all path-taking commands enforce `resolve_confined_path` (reject paths escaping the vault dir). `vault_lock_acquire/check/release` = advisory lock; hostname via `COMPUTERNAME`/`HOSTNAME` env (zero-dep — NO `hostname` crate, per deps-minimized rule); PID liveness via `OpenProcess`/`libc::kill`. Registered in `lib.rs` `generate_handler!` (plugin order preserved).
- **Capabilities (default.json):** new LITERAL-path scopes for `.lock` + `.bak.1`–`.bak.5` slots, plus `fs:allow-remove` + `fs:allow-stat`; still ZERO single-`*` segments; `platforms` preserved.
- **TS storage adapter:** `apps/desktop/src/lib/adapters/TauriVaultStorageAdapter.ts` implements `VaultStorageAdapter` over the Rust commands (+ plugin-fs reads). Promise-chain **save-mutex** (P3-12, per-save error isolation — chain never poisons; `isSaving` getter). **FNV-1a content-hash dedup** (P3-11, `contentHash.ts`): unchanged hash ⇒ `maxBackups=0` (no spurious backup). Payload bytes sent as `Array.from(bytes)` (no base64 of the vault payload).
- **VaultSession (`vault.svelte.ts`):** `unlock` acquires the advisory lock + seeds the content hash; `lock()` awaits the save-mutex before `secureWipe` (Pitfall 4); CRUD-through-session reassigns `#vault` for `$state.raw` reactivity; `#vaultKey` stays NON-reactive.
- **Desktop tests:** `apps/desktop` now has Vitest (`vitest@^3.2.4` + `apps/desktop/vitest.config.ts`); run via `pnpm --filter @cryptiq/desktop test`.
<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->

## Architecture

Top-level layout after Phase 1:

```
cryptiq/
├── package.json                  # pnpm workspace root; packageManager: pnpm@10.x; type: module
├── pnpm-workspace.yaml           # minimumReleaseAge: 1440 (excludes @tauri-apps/* + @sveltejs/*)
├── eslint.config.js              # flat config; forbidden imports + Math.random + console.* rules
├── tsconfig.base.json            # shared strict TS options (strict, noUncheckedIndexedAccess, exactOptionalPropertyTypes, …)
├── .github/
│   ├── workflows/ci.yml          # Windows-only matrix; all D-09 + D-10 jobs SHA-pinned
│   ├── dependabot.yml            # github-actions + npm + cargo ecosystems (Dependabot auto-maintains SHA-pin format)
│   └── CODEOWNERS                # placeholder; update before going public
├── scripts/lint/                 # 5 custom Node lints (zero external deps)
│   ├── lint-workflow-sha-pins.mjs    # DIST-03 / Pitfall 14
│   ├── lint-capability-globs.mjs     # SEC-12 / Pitfall 1
│   ├── lint-capability-platforms.mjs # Pitfall 17 / D-15
│   ├── lint-csp.mjs                  # SEC-13
│   ├── lint-supply-chain.mjs         # SEC-15
│   └── README.md
├── packages/core/                # pure TypeScript — no Svelte/Tauri/node:fs
│   └── src/
│       ├── index.ts                        # `.` public entry: verb-first vault API + typed errors
│       ├── internal.ts                     # `@cryptiq/core/internal`: primitives for demos + KATs
│       ├── errors.ts                       # DC-9 typed errors (single source of truth)
│       ├── storage/VaultStorageAdapter.ts  # interface (re-exports VaultCorruptError); Phase 3 implements
│       ├── config/{types,config}.ts        # CryptiqConfig parse/serialize
│       ├── crypto/                         # Phase 2 primitives — all go through getSodium()
│       │   ├── sodium.ts                   # the ONLY libsodium import site (getSodium)
│       │   ├── kdf.ts                      # DC-1 Argon2id calibrate/derive (floor, no ceiling, dual-OOM)
│       │   ├── aead.ts                     # combined-mode seal/open under VAULT_AD (SEC-06)
│       │   ├── wrap.ts                     # envelope wrapKey/tryUnwrap (DC-3/DC-5, no AD)
│       │   ├── recovery.ts                 # DC-7 Crockford Base32 + BLAKE2b recovery wrap-key
│       │   ├── padding.ts                  # DC-6 tiered padding + uint32 LE prefix
│       │   └── __tests__/                  # sodium, kdf (KAT-1), aead (KAT-2), wrap, recovery (KAT-3), padding
│       ├── vault/                          # the file-format + verb-first API tier
│       │   ├── format.ts                   # VaultDocumentV1 + WrappedKeyV1 types + format constants
│       │   ├── serialize.ts                # parseOuter/serializeOuter + encryptInner/decryptInner
│       │   ├── vault.ts                    # DC-8 createVault/unlockVault/saveVault/changeMasterPassword/…
│       │   ├── migrations/{types,index}.ts # back-up → migrate → verify-by-cold-decrypt → swap scaffold
│       │   └── __tests__/                  # serialize, round-trip (KAT-4), tamper (9+2), property, migration
│       └── __tests__/sanity.test.ts        # Vitest 3 harness wired
└── apps/desktop/
    ├── package.json              # @tauri-apps/cli HERE (not at root — Pitfall 6)
    ├── vite.config.ts            # Svelte + Tailwind v4 + WASM-ready plugins (Pitfall 5 defenses)
    ├── src/
    │   ├── App.svelte            # branded placeholder + sodium.ready gate
    │   ├── app.css               # Tailwind v4 + @theme tokens (cryptiq- prefix)
    │   ├── lib/
    │   │   ├── state/vault.svelte.ts        # VaultSession singleton — Phase 2 filled the method bodies ($state.raw + #vaultKey, secureWipe on lock)
    │   │   ├── config/config-adapter.ts     # Tauri wrapper around @cryptiq/core config
    │   │   └── dev/boot-self-test.ts        # dev-only diagnostic (stripped in prod)
    │   └── main.ts               # DEV-gated dynamic boot-self-test import
    └── src-tauri/                # Tauri v2 Rust shell
        ├── Cargo.toml            # desktop plugins gated to (macos, windows) — Linux excluded
        ├── tauri.conf.json       # productName "Cryptiq", window 1100×780, strict prod CSP + dev CSP
        ├── src/lib.rs            # plugin order: single-instance FIRST → fs → persisted-scope
        └── capabilities/
            ├── default.json      # main; literal-path fs scopes; platforms ["windows","macOS"]
            └── bootstrap.json    # dialog-only pre-path-choice
```

### Tier responsibilities

- `packages/core` — pure TS, bytes in / bytes out. Owns `VaultStorageAdapter` interface, config parsing, and (Phase 2) the full crypto/vault layer: `crypto/*` primitives (via the single `getSodium()` entry), `vault/*` file format + verb-first API, `errors.ts` typed errors, and the `migrations/` scaffold. The `.` entry exports the verb-first vault API + errors; `./internal` exports primitives for demos/KATs.
- `apps/desktop/src` — Svelte 5 renderer. Owns UI, in-memory `VaultSession` singleton, config-adapter (Tauri-side wrapper).
- `apps/desktop/src/lib/dev/` — dev-only diagnostics; stripped from production via `import.meta.env.DEV`.
- `apps/desktop/src-tauri/` — Rust shell. Owns capability allowlist, CSP, plugin wiring, atomic save (Phase 3), single-instance enforcement, persisted-scope.
- `scripts/lint/` — custom Node lints enforcing JSON/YAML invariants that ESLint can't see.

### Decision boundaries (locked by Phase 1 — change only via explicit cross-phase decision)

- Capability JSON shape (literal paths, explicit `platforms`, two-file split) — locked by SEC-11/SEC-12 + Pitfall 1/17.
- Production CSP block — locked by SEC-13.
- pnpm@10 + `minimumReleaseAge: 1440` + `@tauri-apps/*` excluded — locked by SEC-15.
- Single-instance plugin registration order (first; fs before persisted-scope) — locked by SEC-16 + Tauri docs.
- `$state.raw` (not `$state`) for vault state — locked by Pitfall 7 / ARCHITECTURE.md §5.2.
- Linux excluded structurally (`platforms` field + `Cargo.toml` target gate) — locked by D-15.
- Vault file format (`VaultDocumentV1`): `format` discriminator + `version` gate + DC-3 per-wrap `kdf` (no top-level kdf) + DC-4 open `wrappedKeys` map + `data` blob sealed under `VAULT_AD` — locked by Phase 2 / VAULT-01/02/07, pinned by KAT-4. **Do not change the wire format after Phase 2 ships** (project guardrail).
- Crypto parameters: combined-mode XChaCha20-Poly1305 IETF, Argon2id floor 256 MiB / 3 ops with no ceiling, BLAKE2b recovery wrap-key, DC-6 padding tiers, uint32-LE length prefix, decision-27 base64 ORIGINAL variant — locked by Phase 2 / SEC-03/04/06/08, pinned by KAT-1..4. **Do not modify after Phase 2 ships** (project guardrail).
- DC-9 typed-error set + fail-closed contract — locked by Phase 2; every parse/auth/decrypt/derive failure surfaces a typed error, never a crash or partial data.

### Phase 3 addendum — new locations

- `packages/core/src/entries/` — `types.ts`, `uuid.ts`, `crud.ts` (+ `__tests__/`)
- `packages/core/src/generator/` — `types.ts`, `random.ts`, `passphrase.ts`, `entropy.ts`, `eff-long.json` (+ `__tests__/`)
- `packages/core/src/storage/lockLogic.ts` (+ `__tests__/`) — pure lock-decision logic; no IO
- `apps/desktop/src-tauri/src/commands/mod.rs` + `vault.rs` — atomic write, backup rotation, advisory lock, confined-path guard
- `apps/desktop/src/lib/adapters/TauriVaultStorageAdapter.ts` + `contentHash.ts` (+ `__tests__/`) — TS storage adapter with save-mutex + FNV-1a dedup
- `apps/desktop/vitest.config.ts` — desktop Vitest config (run: `pnpm --filter @cryptiq/desktop test`)
<!-- GSD:architecture-end -->

<!-- GSD:skills-start source:skills/ -->

## Project Skills

No project skills found. Add skills to any of: `.claude/skills/`, `.agents/skills/`, `.cursor/skills/`, `.github/skills/`, or `.codex/skills/` with a `SKILL.md` index file.
<!-- GSD:skills-end -->

<!-- GSD:workflow-start source:GSD defaults -->

## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:

- `/gsd-quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd-debug` for investigation and bug fixing
- `/gsd-execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->

<!-- GSD:profile-start -->

## Developer Profile

> Profile not yet configured. Run `/gsd-profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->
