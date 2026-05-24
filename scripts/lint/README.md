# Cryptiq Custom Lint Scripts

Five `.mjs` scripts that enforce security and supply-chain invariants ESLint cannot inspect (JSON capability files, YAML workflow files, cross-file CSP constraints).

**No external dependencies — pure Node 20+ stdlib.** Each runs in well under a second. CI (Plan 01-06) wires each as a separate job so a failure points at the specific invariant that broke.

Run the full chain (ESLint + all 5) via `pnpm lint` from the workspace root. Run only the custom lints via `pnpm lint:custom`. Each can also be invoked standalone.

## Scripts

### `lint-workflow-sha-pins.mjs` — DIST-03 + Pitfall 14

Walks `.github/workflows/*.yml` (recursive) and asserts every `uses:` reference is a 40-character commit SHA, not a version tag. Defends against CVE-2025-30066 (tj-actions/changed-files retag attack) and the general "tag-pinned actions can be rewritten" supply-chain class.

Skip rules: commented-out lines, local actions (`./`, `../`), `docker://` actions. Handles both YAML forms (`uses: foo@bar` and the list-item form `- uses: foo@bar`).

If `.github/workflows/` doesn't exist yet, exits 0 with a notice (Plan 01-05 ships before Plan 01-06 lands workflows).

```
node scripts/lint/lint-workflow-sha-pins.mjs
```

### `lint-capability-globs.mjs` — SEC-12 + Pitfall 1 + GHSA-6mv3-wm7j-h4w5

Walks `apps/desktop/src-tauri/capabilities/*.json` and asserts no path in any `fs:*` permission's `allow` list contains a single-`*` path segment. A `*` segment is a path-traversal wildcard that opens the entire parent directory. `**` (recursive) and file-internal wildcards like `vault.cryptiq.bak.*` are allowed; only an exact `*` segment is rejected.

```
node scripts/lint/lint-capability-globs.mjs
```

### `lint-capability-platforms.mjs` — Pitfall 17 + D-15

Walks `apps/desktop/src-tauri/capabilities/*.json` and asserts every capability has an explicit, non-empty `platforms` array. Omitting `platforms` in Tauri v2 defaults to ALL platforms (including mobile), so a future Android/iOS target build would silently inherit desktop capabilities.

Every platform string must be in the Tauri v2 allowed set `{macOS, windows, linux, android, iOS}` AND in the Cryptiq v1 target set `{windows, macOS}` (Linux dropped per D-15).

```
node scripts/lint/lint-capability-platforms.mjs
```

### `lint-csp.mjs` — SEC-13

Parses `apps/desktop/src-tauri/tauri.conf.json` and asserts:

- `app.security.csp` (production) exists and contains `default-src 'self'`.
- `app.security.devCsp` (dev) exists as a separate field and differs from `csp`.
- Production `script-src` contains no `'unsafe-inline'` or `'unsafe-eval'`. (`'wasm-unsafe-eval'` is allowed — required for libsodium WASM.)
- Production `csp` contains no `ws://`, no `127.0.0.1`, no `localhost:PORT`, and no `http://...` origin OTHER than the Tauri internal protocol hosts `http://asset.localhost` and `http://ipc.localhost` (used by the asset loader and IPC scheme, not real network endpoints).

```
node scripts/lint/lint-csp.mjs
```

### `lint-supply-chain.mjs` — SEC-15 + Pitfall 6

Asserts:

- `package.json#packageManager` matches `pnpm@10.x`.
- `package.json#engines.node` allows Node ≥ 20.
- `pnpm-workspace.yaml` contains `minimumReleaseAge: 1440` (24-hour embargo on fresh npm releases).
- `pnpm-workspace.yaml` lists `'@tauri-apps/*'` under `minimumReleaseAgeExclude` (per Snippet 1 discretion).
- Workspace root `.gitignore` contains the line `package-lock.json` (Pitfall 6 — Tauri CLI mis-detection visibility).

```
node scripts/lint/lint-supply-chain.mjs
```

## Self-test discipline

Each script was validated by injecting a deliberate violation into a real file (then reverting) and confirming exit code 1. Plan 01-05 SUMMARY records which violation each lint caught.

If you add a new lint, follow the same pattern: write the script, then verify it catches the thing it exists to catch by introducing a controlled violation.
