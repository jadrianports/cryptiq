<!-- GSD:project-start source:PROJECT.md -->

## Project

**Cryptiq** — a local-first, self-built desktop password manager. Passwords live in a
single encrypted file (`.cryptiq`) on the user's machine: no account, no server, no
subscription. The user built it, so they can audit it. Friends who install it keep
their own separate vault; Cryptiq never shares secrets between users.

**Core value:** strong, auditable, free-forever encryption you don't rent from anyone.
If everything else breaks, the encrypted vault file with correct crypto is what must work.

### Constraints

- **Stack (locked):** Tauri v2, Svelte 5 (runes) + TS + Vite, Tailwind v4, pure-TS `core`
  with `libsodium-wrappers-sumo` (WASM) for all crypto, `zxcvbn-ts`, `papaparse`, bundled EFF wordlist.
- **Tooling:** pnpm workspaces, Vitest (`core`), Playwright (components), tauri-driver + WebdriverIO (E2E), ESLint + Prettier.
- **Dev env:** Windows-first. macOS/Linux build via CI only (no macOS dev machine). Linux structurally excluded from v1 desktop plugins.
- **Cost:** $0. OS code-signing skipped for v1 (installs show "unidentified developer").
- **Crypto rules (non-negotiable):** libsodium only; no hand-rolled crypto; CSPRNG only
  (`Math.random` banned near secrets); fresh nonce per encryption; fail closed; never
  write plaintext secrets to disk or logs; lockfile committed; deps pinned and minimized.
- **Core purity:** `packages/core` may not import Svelte, Tauri, or Node `fs`/`path`. Bytes
  in, bytes out. Storage is injected via the `VaultStorageAdapter` interface.

<!-- GSD:project-end -->

<!-- GSD:stack-start source:research/STACK.md -->

## Technology Stack

Pinned versions (full rationale, alternatives, and sources in `.planning/research/STACK.md`):

| Layer | Pin |
|---|---|
| Tauri JS API / CLI | `@tauri-apps/api@^2.11.0` / `@tauri-apps/cli@^2.11.2` (CLI in `apps/desktop`, never root) |
| Tauri plugins | `tauri-plugin-*@2` / `@tauri-apps/plugin-*@^2` |
| Svelte / Vite | `svelte@^5.55.9` + `@sveltejs/vite-plugin-svelte@^5` / `vite@^7` (or `^6`) |
| Tailwind | `tailwindcss@^4.1.7` + `@tailwindcss/vite@^4.1.7` (NOT the v3 PostCSS plugin) |
| Crypto | `libsodium-wrappers-sumo@^0.7.15` (stay on 0.7.x — do not chase 0.8.x) |
| Strength / CSV | `@zxcvbn-ts/{core,language-common,language-en}@^3` / `papaparse@^5.5.3` |
| Pkg mgr / tests | `pnpm@^10` (Node ≥20) / `vitest@^3.2.4` (pin 3.x for crypto suite) |
| E2E | `webdriverio@^9` + `mocha@^11` + `chai@^5` + `tauri-driver` (cargo) |

**Never use:** `libsodium-wrappers` (non-sumo — no Argon2id) · `bcrypt`/`scrypt`/PBKDF2 for the
KDF · Tauri v1 · `plugin-stronghold` for vault storage (duplicates our format) · Svelte stores
for new code · `Math.random()` near secrets · `nodeLinker: hoisted` · global `fs:` scope
(`$HOME/*`) · `clipboard-manager:allow-read-text` (Cryptiq never reads the clipboard).

<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->

## Conventions

**Workspace & purity**
- pnpm workspace: `apps/desktop` (Tauri + Svelte frontend) + `packages/core` (pure TS). `@tauri-apps/cli` lives in `apps/desktop`, never root.
- `packages/core` cannot import `@tauri-apps/*`, `svelte`, `node:fs`/`fs`, `node:path`/`path` — enforced by ESLint `no-restricted-imports`.
- No `console.*` in `packages/core` (tests exempt). No `Math.random` anywhere — use `sodium.randombytes_buf`.
- `_`-prefixed names = intentionally unused (honored by tsconfig + ESLint).
- Lockfiles committed: `pnpm-lock.yaml` + `Cargo.lock`. `package-lock.json`/`yarn.lock` gitignored.
- **Agents never run git.** Surface commit-worthy moments with a suggested command; the user runs it.

**Crypto / vault (Phase 2 — LOCKED, do not modify the wire format or params)**
- Single libsodium entry: every crypto module gets the handle via `crypto/sodium.ts` `getSodium()`. Raw `libsodium-wrappers-sumo` imports banned outside `sodium.ts`.
- AEAD: combined-mode XChaCha20-Poly1305 IETF only. Data blob sealed under `VAULT_AD` ("cryptiq-vault\0v1"); key-wrapping uses the same primitive with no AD.
- KDF: Argon2id, hard floor 256 MiB / 3 ops, NO ceiling (DC-1). Per-wrap `{opsLimit,memLimit,salt,algorithm}` inside each `wrappedKeys[label]` — no top-level `kdf`. Dual-path OOM (throw or all-zeros buffer) → `KdfResourceError`; zero buffer never accepted as key.
- `wrappedKeys` is an open map keyed by label (`master` always, optional `recovery`); parser tolerates unknown labels, refuses only on unknown `version`. `removeWrappedKey('master')` refused. Single `tryUnwrap` for all paths (MAC failure → `null`).
- Padding: tiered (16/64/256 KiB) + uint32 **little-endian** length prefix. Recovery key: hand-rolled Crockford Base32, 54-char flat contract, BLAKE2b wrap-key (no Argon2id). base64: always `sodium.base64_variants.ORIGINAL` explicitly.
- Verb-first API in `vault/vault.ts` (`createVault/unlockVault/saveVault/changeMasterPassword/add|removeWrappedKey`). `UnlockedVault` is plain data; the 32-byte key is returned separately and the caller owns its lifecycle + `secureWipe`.
- Typed errors in `errors.ts` (single source). Every parse/auth/decrypt/derive failure surfaces a typed error with a stable `code` — never a bare `Error`, never partial data.
- Migration: back-up → migrate-copy → verify-by-cold-decrypt → swap. A failed cold-decrypt throws `MigrationFailedError` and does NOT swap the original.

**Entries / generator / storage (Phase 3)**
- InnerDoc: `{ schemaVersion, entries[], settings }`. `asInnerDoc()` is the single upgrade/cast site. Entry CRUD mutates in place + returns the affected entry; `VaultSession` reassigns `#vault` for `$state.raw` reactivity.
- Entry IDs: `uuidV4FromBytes(randombytes_buf(16))` — never `Math.random`/`crypto.randomUUID`. Password history: newest-first, capped 10, via `pushHistory`.
- Generator uses `randombytes_uniform` (bias-free) + Fisher-Yates. `estimateEntropyBits`/`computePoolSize` are the single entropy source.
- Lock decision logic (`storage/lockLogic.ts`) is pure — PID-liveness injected as a boolean; no IO/PID syscalls in core.
- Rust `vault_write_atomic`: temp-in-dir → `sync_all` → COPY primary→`.bak.1` (rotate 1–5) → atomic rename → dir fsync. COPY (not move) keeps primary present through a crash. All path commands enforce `resolve_confined_path`.
- TS `TauriVaultStorageAdapter`: promise-chain save-mutex + FNV-1a content-hash dedup (unchanged hash ⇒ no backup).

**Frontend / security**
- In-memory vault state uses `$state.raw` (NOT deep `$state` — proxy could leak secrets via DevTools). Vault key is a non-reactive `#vaultKey`.
- Capabilities (`src-tauri/capabilities/`): `default.json` + `bootstrap.json`, both with explicit `platforms: ["windows","macOS"]`. fs scopes use LITERAL paths only — zero single-`*` segments. No `*:default` token except `core:default`.
- CSP: strict production block in `tauri.conf.json#app.security.csp`; dev relaxations only in `devCsp` and never in production.
- Plugin order in `lib.rs`: single-instance FIRST → `fs` → `persisted-scope`. Desktop plugins gated to `(macos, windows)`.
- CI: every workflow `uses:` is a 40-char SHA + `# tag` comment (CVE-2025-30066). Custom Node lints in `scripts/lint/*.mjs` enforce the JSON/YAML invariants ESLint can't see; wired into `pnpm lint`.
- Dev-only diagnostics (`lib/dev/`) are DEV-gated dynamic imports, stripped from production bundles by Vite.

**Phase close:** append a short (≤3 bullet) summary of patterns landed to Conventions + Architecture. Full prose lives in `.planning/` — keep this file lean.

<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->

## Architecture

```
cryptiq/
├── package.json / pnpm-workspace.yaml   # workspace root; pnpm@10; minimumReleaseAge: 1440
├── eslint.config.js / tsconfig.base.json # forbidden-imports + Math.random + console rules; strict TS
├── .github/{workflows,dependabot.yml}    # Windows CI matrix; SHA-pinned actions
├── scripts/lint/*.mjs                    # 5 custom zero-dep Node lints (sha-pins, globs, platforms, csp, supply-chain)
├── packages/core/src/                    # pure TS — no Svelte/Tauri/node:fs
│   ├── index.ts / internal.ts            # public verb-first API + errors / primitives for demos+KATs
│   ├── errors.ts                         # typed errors (single source)
│   ├── crypto/                           # sodium (only import site), kdf, aead, wrap, recovery, padding
│   ├── vault/                            # format, serialize, vault (verb API), migrations/
│   ├── entries/                          # types, uuid, crud
│   ├── generator/                        # types, random, passphrase, entropy, eff-long.json
│   ├── storage/                          # VaultStorageAdapter (interface), lockLogic (pure)
│   └── config/                           # CryptiqConfig parse/serialize
└── apps/desktop/
    ├── vite.config.ts / vitest.config.ts
    ├── src/lib/state/vault.svelte.ts     # VaultSession singleton ($state.raw + non-reactive #vaultKey)
    ├── src/lib/adapters/                 # TauriVaultStorageAdapter + contentHash
    └── src-tauri/                        # Rust shell
        ├── src/lib.rs                    # plugin order: single-instance → fs → persisted-scope
        ├── src/commands/vault.rs         # atomic write, backup rotation, advisory lock, confined-path guard
        ├── tauri.conf.json               # strict prod CSP + dev CSP
        └── capabilities/{default,bootstrap}.json  # literal fs scopes; platforms [windows, macOS]
```

**Tier responsibilities**
- `packages/core` — pure crypto/vault/entries logic, bytes in/out; owns the `VaultStorageAdapter` interface and typed errors.
- `apps/desktop/src` — Svelte renderer; owns UI + in-memory `VaultSession`.
- `apps/desktop/src-tauri` — Rust shell; owns capabilities, CSP, plugin wiring, atomic save, single-instance.

**Locked decision boundaries** (change only via explicit cross-phase decision)
- Vault wire format (`VaultDocumentV1`: `format` discriminator + `version` gate + per-wrap `kdf` + open `wrappedKeys` + `data` sealed under `VAULT_AD`) — **do not change after Phase 2**.
- Crypto params (combined XChaCha20-Poly1305 IETF, Argon2id 256 MiB/3 ops floor no ceiling, BLAKE2b recovery key, tiered padding + uint32-LE prefix, base64 ORIGINAL) — **do not modify after Phase 2**; pinned by KAT-1..4.
- Capability JSON shape (literal paths, explicit `platforms`, two-file split), production CSP block, pnpm minimumReleaseAge, single-instance plugin order, `$state.raw` for vault state, Linux structurally excluded, typed-error fail-closed contract.

<!-- GSD:architecture-end -->

<!-- GSD:skills-start source:skills/ -->

## Project Skills

No project skills found. Add skills under `.claude/skills/` (or `.agents/`, `.cursor/`, `.github/`, `.codex/`) with a `SKILL.md` index.

<!-- GSD:skills-end -->

<!-- GSD:workflow-start source:GSD defaults -->

## GSD Workflow Enforcement

Before using Edit/Write, start work through a GSD command so planning artifacts stay in sync:
`/gsd-quick` (small fixes/docs), `/gsd-debug` (investigation), `/gsd-execute-phase` (planned work).
Don't make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.

<!-- GSD:workflow-end -->

<!-- GSD:profile-start -->

## Developer Profile

> Profile not yet configured. Run `/gsd-profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.

<!-- GSD:profile-end -->
