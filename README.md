# Cryptiq

Local-first password manager. Your passwords live in a single encrypted file (`.cryptiq`) on your own machine — no account, no server, no subscription.

## Dev

```sh
pnpm install
pnpm dev          # opens the Tauri window
pnpm test         # vitest run
pnpm lint         # eslint + custom workflow / capability / CSP / supply-chain lints
pnpm typecheck    # svelte-check + tsc --noEmit across workspace
pnpm tauri build  # cross-platform installers (Windows + macOS)
```

## Stack

See [`CLAUDE.md`](./CLAUDE.md) for the full pinned-version table and rationale.

- **Shell:** Tauri v2 (stable) — small binary, OS-native WebView, capability-based permissions
- **UI:** Svelte 5 (runes) + Vite + Tailwind v4 + TypeScript
- **Crypto:** `libsodium-wrappers-sumo` (WASM) — Argon2id + XChaCha20-Poly1305 IETF + BLAKE2b + CSPRNG
- **Test:** Vitest 3 for `packages/core`; Playwright + tauri-driver + WebdriverIO for desktop E2E
- **Package manager:** pnpm 10 + pnpm workspaces (`apps/*`, `packages/*`)

## Layout

```
apps/desktop/      # Tauri + Svelte 5 frontend (Vite)
packages/core/     # Pure-TS crypto + vault + storage-adapter — no Svelte, no Tauri, no node:fs
scripts/lint/      # Custom Node lint scripts (workflow SHA pins, capability globs, CSP, supply chain)
.github/workflows/ # CI on Windows runners — every uses: is SHA-pinned (DIST-03)
```

`packages/core` may not import Svelte, Tauri, or Node `fs`. It receives bytes and returns bytes. Storage is supplied via the `VaultStorageAdapter` interface.

## License

TBD — public/open-source decision is deferred to v1.5 when the auto-updater needs signed releases.
