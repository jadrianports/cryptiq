# 01 — Architecture

## Guiding principle

**The vault file is the contract. Everything else is replaceable.**

If the file format is well-defined and the security-critical logic lives in one
platform-agnostic place, then the UI framework, the OS wrapper, and the sync mechanism all
become interchangeable parts. This is what makes "desktop now, phone later" — and even
"local now, hosted maybe" — cost almost nothing.

## Monorepo layout

```
coffer/
├── package.json            # workspace root (pnpm workspaces)
├── pnpm-workspace.yaml
├── packages/
│   └── core/               # pure TypeScript — the brain
│       ├── src/
│       │   ├── crypto/     # KDF, AEAD, envelope wrap/unwrap, RNG
│       │   ├── vault/      # file format, (de)serialize, version migration
│       │   ├── entries/    # entry model, CRUD, validation
│       │   ├── generator/  # password + passphrase generation
│       │   ├── audit/      # weak/reused password analysis
│       │   ├── import/     # CSV parsing + field mapping
│       │   └── index.ts    # public API surface
│       └── tests/          # heavy unit tests, esp. crypto + vault
└── apps/
    └── desktop/            # Tauri v2 application
        ├── src/            # Svelte + TypeScript + Vite UI
        ├── src-tauri/      # thin Rust layer: file IO + OS integration
        └── ...
```

Use **pnpm workspaces**. `apps/desktop` depends on `packages/core`; `core` depends on
nothing from `apps/`.

## The `core` package — hard rules

`core` is the only place security-critical logic may live. It must:

- **Contain zero UI code** — no Svelte, no DOM, no components. The Svelte-vs-anything-else
  decision must never reach into `core`.
- **Contain zero platform code** — no Tauri APIs, no Node `fs`, no file paths. `core`
  never touches a disk. It receives bytes and returns bytes.
- **Be deterministic and testable** — pure functions wherever possible; the only
  non-determinism is the CSPRNG, which is injected/wrappable for tests.
- **Be publishable on its own** — in principle `core` could be an npm package. Treat it
  that way; it keeps the boundary honest.

### `core` public API (shape, not final signatures)

```ts
// vault lifecycle
createVault(masterPassword: string, opts?: CreateOpts): Promise<VaultBytes>
unlockVault(bytes: VaultBytes, secret: MasterPassword | RecoveryKey): Promise<UnlockedVault>
saveVault(vault: UnlockedVault): Promise<VaultBytes>
changeMasterPassword(vault: UnlockedVault, oldPw, newPw): Promise<UnlockedVault>
addRecoveryKey(vault: UnlockedVault): Promise<{ vault: UnlockedVault; recoveryKey: string }>

// entries (operate on an in-memory UnlockedVault)
listEntries / getEntry / addEntry / updateEntry / softDeleteEntry / purgeEntry

// utilities
generatePassword(opts) / generatePassphrase(opts)
auditVault(vault) -> { reused: [...], weak: [...] }
parseCsv(text) -> { columns, rows }  /  importRows(vault, mappedRows)
```

`UnlockedVault` is an in-memory object holding the decrypted entries plus the live vault
key. It is **never serialized to disk in plaintext**.

## The storage adapter — how `core` stays platform-free

`core` defines an interface; each app implements it.

```ts
interface VaultStorageAdapter {
  load(): Promise<VaultBytes>;            // read the encrypted file
  save(bytes: VaultBytes): Promise<void>; // write it (with backup rotation)
  exists(): Promise<boolean>;
}
```

- The **Tauri desktop app** implements this against the real filesystem (Rust side).
- A future **browser build** implements it against the File System Access API.
- A future **phone app** implements it against the platform's document storage.
- A future **hosted version** implements it against a server — the adapter uploads and
  downloads the *already-encrypted* blob. The server never sees plaintext or the master
  password. (See `07-decisions-log.md` on zero-knowledge hosting.)

`core` orchestrates *when* to load/save; the adapter decides *how*. This interface is also
exactly where v2 LAN sync slots in — a smarter adapter detects the file changed and
triggers a merge.

## The Tauri app — keep the Rust side thin

`src-tauri` (Rust) is responsible for **only**:

- File IO: read/write the vault file at a user-chosen path.
- Backup rotation: before each save, copy the current file to a rotating backup slot.
- OS integration: clipboard access, idle-time detection (for auto-lock), the updater
  (v1.5), and the OS keychain for biometric unlock (v1.5).

All crypto, all vault logic, all entry handling stays in TypeScript `core`. Rust does no
crypto. Rationale: if crypto lived in Rust, `core` would be permanently chained to Tauri
and a browser build would be impossible. The cost — running Argon2id in WASM — is
negligible for a once-per-unlock operation.

## UI layer (`apps/desktop/src`)

- **Svelte + TypeScript + Vite.** Tauri supports this stack well.
- See `04-features-v1.md` for screens and flows.
- The UI calls `core` for everything and the storage adapter for load/save. The UI holds
  no crypto logic of its own.
- Keep the decrypted vault in a single in-memory Svelte store. Auto-lock clears that store.
- Styling: Tailwind CSS. Aim: clean, legible, predictable — a security tool earns trust by
  being obvious, not flashy (see `04-features-v1.md`).

## Why this shape pays off later

| Future want | What changes | What does NOT change |
|---|---|---|
| Desktop app for friends | Already done (this is it) | — |
| Phone app | New `apps/mobile` + a storage adapter | `core` |
| Browser build | New `apps/web` + an FS-Access adapter | `core` |
| LAN sync | A smarter storage adapter; merge logic in `core/vault` | File format, entry IDs |
| Hosted version | A server + an HTTP storage adapter | `core`, the crypto, the file format |

Every row leaves `core` and the file format untouched. That is the whole point.
