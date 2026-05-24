# 06 — Build Plan

This is the build order, written for the implementer (you, or Claude Code). Build the
milestones **in order** — each depends on the ones before it. The ordering is deliberate:
**the security core is built and tested before any UI exists.**

Each milestone has a definition of done. Do not move on until it is met.

## Phase discipline — definition of done per phase

Every phase (v1, v1.5, v2, mobile, extension) ends with a **"Definition of Done"
checklist**. The rule: **a phase is not finished, and the next phase does not begin, until
every box is ticked.** This is the structural defense against scope creep — a finish line
written down in advance is much harder to quietly move. New ideas that surface mid-phase
go into `05-roadmap.md` as a future-phase item; they are NOT added to the current phase.

---

# PHASE v1 — the secure manual desktop vault

## Milestone 0 — Scaffold

- Create the pnpm-workspace monorepo from `01-architecture.md`: `packages/core` and
  `apps/desktop`.
- Initialize the Tauri v2 app with a Svelte + TypeScript + Vite template.
- Confirm the app builds and launches a blank window on the **Windows** dev machine.
- Initialize a **private** GitHub repo (public/open-source is deferred — see
  `07-decisions-log.md`). Commit a lockfile. Set up CI that installs deps, builds `core`,
  and runs `core` tests.
- Add lint/format config. Add a lint rule (or documented convention) against logging
  secret-typed values.

**Done when:** `pnpm install && pnpm build` works; the Tauri app opens; CI is green.

## Milestone 1 — Crypto & vault format (the core) -- most important milestone

Build in `packages/core` only. **No UI.**

- Integrate `libsodium-wrappers-sumo`. Wrap the primitives from `02-security-design.md`:
  Argon2id KDF, XChaCha20-Poly1305 AEAD, CSPRNG, BLAKE2b.
- Implement **envelope encryption**: random vault key; wrap under `master_key`; optional
  wrap under a recovery-derived key.
- Implement the **vault file format** from `03-vault-file-format.md`: serialize/parse the
  outer JSON, encrypt/decrypt the `data` payload (with **file-size padding** — pad to a
  fixed bucket before encrypting, strip after decrypting via a length prefix), version as
  AEAD associated data.
- Implement `core` lifecycle: `createVault`, `unlockVault` (master password + recovery key
  paths), `saveVault`, `changeMasterPassword`, `addRecoveryKey`.
- Generate the recovery key and its grouped-Base32 display encoding.

**Tests (part of done — see `02-security-design.md`):** round-trip; wrong master password;
wrong recovery key; tamper detection on every region; recovery unlock; master-password
change preserves data; KDF parameters honored from the header; **padding** — vaults with
very different entry counts produce the same file size, and padding strips back to the
exact original data.

Also implement and test the **migration framework** scaffold here (even though v1 is
format version 1): the load path must be structured for versioned, one-step-at-a-time
migrations with the back-up / migrate-a-copy / verify / swap safety pattern from
`03-vault-file-format.md`. Getting the framework right now makes the v2 card-type
migration safe later.

**Done when:** a vault can be created, saved, reloaded, and unlocked by both secrets; every
test passes; tampering is always detected.

## Milestone 2 — Entry model & generator (core)

Still `packages/core`, still no UI.

- Implement the entry schema and entries document from `03-vault-file-format.md`: UUID
  assignment, `modifiedAt` updates, `deletedAt` tombstones, the (initially empty)
  `passwordHistory` array, the `needsSiteUpdate` flag, and the optional `generatorPreset`.
- Implement entry operations: list / get / add / update / softDelete / purge.
- Implement the password generator: random-string and passphrase modes, CSPRNG-backed,
  with saveable presets (global defaults + optional per-entry `generatorPreset`).
- Implement derived **password age** (from `modifiedAt` / `passwordHistory`) for the audit.

**Done when:** entries can be CRUD'd in an in-memory unlocked vault and persist through a
save/load cycle; generator output is correct and configurable; unit tests cover all of it.

## Milestone 3 — Storage adapter & file IO (Tauri/Rust)

- Define the `VaultStorageAdapter` interface in `core`.
- Implement it in `apps/desktop` against the real filesystem via the thin Rust layer.
- Implement **rotating encrypted backups** (keep last 5) on every save.
- Implement the **vault picker**: track known vault file paths + labels in non-secret app
  config; support open-existing and create-new.

**Done when:** the app creates a vault file on disk, reloads it across restarts, rotates
backups; the picker works; no secret material is written outside the encrypted vault file.

## Milestone 4 — Core UI (Svelte)

- First-run setup + **focused explainer** (`04-features-v1.md`): the unrecoverable-password
  warning must be unmissable; master password with `zxcvbn-ts` strength meter; the opt-in
  recovery-key flow (display once, printable, confirm-saved gate).
- Unlock screen, including the recovery-key path and post-recovery master-password reset.
- Main view: entry list (with generated visual identity per entry), search (debounced +
  virtualized list; designed empty-state and no-results state), entry detail/edit, masked
  password with show/hide, per-field copy, open-URL, inline generate, the
  **"needs changing on the website"** toggle + filter, soft-delete + "recently deleted",
  and **explicit confirm before permanent delete (purge)**.
- A clear, visible **"saved" confirmation** whenever a change is persisted.
- Standalone generator screen, including saveable **presets** and the **"save as new
  entry"** action.

**Done when:** a user can set up, lock, unlock, and fully manage entries through the UI;
all persistence goes through `core` + the storage adapter.

## Milestone 5 — Lock & clipboard safety

- Auto-lock on idle (default 5 min), on window close/minimize (configurable), on system
  sleep. Locking clears the in-memory vault and keys.
- Clipboard auto-clear after ~25s, only clearing Coffer's own copied value.
- **Re-prompt for the master password** on sensitive actions (reveal a password, change
  the master password, export a backup) — a per-action guard, distinct from auto-lock.
- Settings screen wiring for auto-lock, clipboard, and generator-default preferences.
- The opt-in **"fetch real favicons"** toggle (off by default) lives in Settings.

**Done when:** the vault reliably re-locks and the in-memory store clears; clipboard clears
as specified; settings persist.

## Milestone 6 — Recovery polish & master-password change

- Wire `changeMasterPassword` into Settings (require current password first).
- Ensure the full recovery-key lifecycle is solid end to end.

**Done when:** master-password change is fast and lossless; recovery key fully works.

## Milestone 7 — CSV import

- Integrate `papaparse`. Auto-map Chrome/Edge, Firefox, Bitwarden CSV formats; generic
  column-mapping fallback. Preview, duplicate detection (url+username), and a post-import
  reminder to securely delete the source CSV.

**Done when:** a real browser password export imports correctly with sensible mapping and
duplicate handling.

## Milestone 8 — Health check & encrypted backup export

- Implement the audit in `core/audit`: reused-password grouping, weak-password scoring,
  and **stale-password (age) detection**.
- Build the Health view (weak / reused / stale / needs-site-update) with one-tap
  jump-to-fix.
- Implement the **"export encrypted backup copy"** action (`04-features-v1.md`): copy the
  already-encrypted vault file to a user-chosen location.

**Done when:** the audit correctly flags reused/weak passwords and the fix flow works; the
backup export produces a valid, openable copy of the vault at the chosen path.

## Milestone 9 — Installers & release pipeline

- Configure `tauri build` for Windows installers (primary). Add the GitHub Actions
  workflow (`tauri-action`) that builds Windows, macOS, and Linux and publishes a Release
  on a version tag — macOS/Linux are built by CI so the dev's Mac stays a non-dev machine.
- Add an honest About/Security screen (threat model summary, version, repo link).

**Done when:** tagging a release produces downloadable installers for all three platforms
via CI.

## --- DEFINITION OF DONE: PHASE v1 ---

v1 ships, and no v1.5 work begins, until ALL of these are true:

- [ ] A vault can be created, locked, unlocked, and used end to end.
- [ ] Crypto test suite (Milestone 1) fully passes, including all tamper AND padding tests.
- [ ] The versioned migration framework exists, with the back-up/copy/verify/swap pattern.
- [ ] Entry CRUD, search, generator (incl. presets + save-as-new-entry) all work.
- [ ] Search is debounced and the list virtualized; empty/no-results states are designed.
- [ ] Auto-lock and clipboard auto-clear work and are configurable.
- [ ] Master-password re-prompt guards reveal / change-master / backup-export.
- [ ] Opt-in recovery key works: setup, printable, unlock-with, post-recovery reset.
- [ ] CSV import works for at least one real browser export.
- [ ] Weak/reused/stale audit works with jump-to-fix.
- [ ] The "needs changing on site" flag and its filter work.
- [ ] Visible save confirmation shows on persist; permanent delete requires confirmation.
- [ ] Generated visual identity shows per entry; real-favicon fetch is off by default.
- [ ] Encrypted backup export produces a valid openable copy.
- [ ] Multi-vault picker works.
- [ ] First-run explainer exists and the unrecoverable-password warning is unmissable.
- [ ] CI produces installers for Windows, macOS, and Linux.
- [ ] No secret is ever written to disk or logs outside the encrypted vault file.
- [ ] The implementer has personally migrated their real passwords into Coffer and is
      using it. (The project's actual goal — not a nice-to-have.)

---

# PHASE v1.5 — fast-follows

Build: biometric unlock (OS keychain as an extra unwrap-path, with an explicit clean
fallback to master password on any biometric failure / unavailability / new device);
password-history population (cap 10); the Tauri auto-updater (guard the signing key —
`02-security-design.md`; revisit repo public/private status; ensure a bad-update recovery
path so a broken release never bricks the app).

## --- DEFINITION OF DONE: PHASE v1.5 ---

- [ ] Biometric unlock works on both Touch ID and Windows Hello; master password still works.
- [ ] Biometric failure / unavailability falls back cleanly and silently to master password.
- [ ] Changing a password records the previous one in history; history is capped.
- [ ] An older installed build auto-updates to a newer signed release; a bad-signature
      build is refused.
- [ ] A documented, tested recovery path exists if an update ships broken.

---

# PHASE v2 — bigger pushes

Build (see `05-roadmap.md` for detail): one-time encrypted share (local tier), breach
check (HaveIBeenPwned k-anonymity), card entry type (a real migration — follow the
migration-safety rules), fuller onboarding, themes. (LAN sync is NOT here — it is v2.5.)

## --- DEFINITION OF DONE: PHASE v2 ---

- [ ] One-time share produces an encrypted single-entry blob a recipient can open.
- [ ] Breach check flags known-breached passwords without sending full passwords.
- [ ] Card entry type works; its format migration follows the back-up/verify/swap pattern.
- [ ] Onboarding and themes are in place.

---

# PHASE v2.5 — Cloudless LAN sync (own design round first)

LAN sync is large enough to be its own phase. Do NOT start building from this build plan
alone — it requires its own design round first, resolving: device discovery, device
pairing & trust, transport-channel security, and the full merge rules (create/create,
edit/edit newer-wins-with-history, delete-vs-edit). See `05-roadmap.md`.

## --- DEFINITION OF DONE: PHASE v2.5 ---

- [ ] A design doc for sync exists and has been reviewed before building.
- [ ] Two trusted devices discover and pair securely; an untrusted device cannot join.
- [ ] The vault transfers over an encrypted, authenticated channel.
- [ ] All merge edge cases resolve per the design; an edit overwritten by a sync keeps the
      losing version in password history.

---

# MOBILE BATCH — its own phases, after v2.5 (deliberately loose)

Kept intentionally loose — needs its own design round; detailed planning now is wasted
effort. Decide Tauri-mobile vs. Capacitor at the start. Reuse `core` unchanged. Build a
mobile UI and a mobile storage adapter. Note: mobile biometrics use different OS APIs than
desktop (separate implementation), and OS-level mobile autofill is its own design problem
that likely belongs in this batch.

## --- DEFINITION OF DONE: MOBILE BATCH ---

- [ ] A design round for the mobile batch has happened.
- [ ] `core` runs unchanged on the chosen mobile shell.
- [ ] A vault can be created/unlocked/used on a phone.
- [ ] The mobile UI is a genuine touch redesign, not a stretched desktop layout.

---

# BROWSER EXTENSION PHASE — committed, after the mobile batch (deliberately loose)

Kept intentionally loose — committed, but needs its own dedicated design round. Chromium +
Firefox. Autofill + auto-capture. The security-critical unknown is extension<->app
**pairing and authentication** — the design round must resolve it before building.

## --- DEFINITION OF DONE: EXTENSION PHASE ---

- [ ] A design round, centered on extension<->app pairing/auth, has happened.
- [ ] The extension securely pairs with and authenticates to the desktop app.
- [ ] Autofill fills known logins on the correct site only (no wrong-site leakage).
- [ ] Auto-capture offers to save new logins on signup.
- [ ] Works on both Chromium and Firefox.

---

## Cross-cutting expectations (every milestone, every phase)

- **Honor the implementer rules in `02-security-design.md`** — no hand-rolled crypto, no
  plaintext secrets on disk or in logs, CSPRNG only, fail closed, minimal pinned deps.
- **`core` stays pure** — no Svelte, no Tauri, no `fs` inside `packages/core`.
- **Test as you go** — `core` carries real unit tests. The Milestone 1 crypto tests are
  non-negotiable.
- **Commit small, commit often.**
- **Do not pull later-phase items forward.** New ideas go to `05-roadmap.md`, not into the
  current phase.

## Suggested first prompt to Claude Code

> "Read all of `coffer-plan/`. Then execute Milestone 0, then Milestone 1, from
> `06-build-plan.md`. For Milestone 1, follow `02-security-design.md` and
> `03-vault-file-format.md` exactly, and do not start any UI until Milestone 1's tests all
> pass. Stop after Milestone 1 and show me the test results."
