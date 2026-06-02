# 05 — Roadmap

v1 is deliberately small so it can be finished, trusted, and actually used. This document
records the full phase plan and what was *consciously deferred* — so future-you does not
re-debate settled questions, and so v1 does not quietly absorb later work.

**Every phase has a "definition of done" — see `06-build-plan.md`. A phase is not finished,
and the next phase does not start, until its checklist is fully met.** This is the primary
defense against scope creep (see `07-decisions-log.md`).

## v1 — the secure manual desktop vault

A feature-complete, single-desktop password manager. Fully manual: open app, search, copy,
paste. No network, no sync, no browser integration. This is the real first build and it
already fully solves the core problem — passwords off a plaintext note and into strong
encryption. Detailed spec in `04-features-v1.md`. Summary: vault create/unlock, entry CRUD,
password generator (incl. presets and "save as new entry"), search, copy + clipboard
auto-clear, auto-lock, opt-in recovery key, CSV import, weak/reused/stale audit, focused
first-run explainer, multi-vault picker, encrypted-backup export, file-size padding,
visible save confirmation, confirm-on-purge, master-password re-prompt on sensitive
actions, per-entry "needs updating on site" flag, generated visual identity per entry.
Windows-first dev; macOS/Linux builds via CI.

## v1.5 — cheap, high-value fast-follows

Small additions that sharpen daily use. None require infrastructure.

- **Biometric unlock** — Touch ID (macOS) and Windows Hello (Windows). Implemented as an
  extra envelope unwrap-path via the OS keychain; per-device; master password remains the
  backstop. See `02-security-design.md`. **Failure path must be explicit:** if biometrics
  fail, are unavailable, the OS changes, or it is a new device, the app falls back cleanly
  and silently to master-password unlock. Biometrics are a convenience layer over the
  master password, never a replacement for it.
- **Password history** — populate the `passwordHistory` field (already in the v1 schema —
  `03-vault-file-format.md`) so changing a password keeps the previous one. Cap at 10.
- **Auto-updater** — the Tauri updater plugin. Checks GitHub Releases for a newer signed
  build. The updater signing key is a critical secret (`02-security-design.md`). NOTE:
  simplest with a public repo; if the repo is still private at this point, the updater
  needs an access token — revisit the repo's public/private status here. **Bad-update
  recovery:** an update can ship a broken build; the design must ensure the user can
  recover — at minimum by reinstalling the last-good version from GitHub Releases, ideally
  via the updater's rollback support. Never leave a user with a bricked, non-updatable app.
- **Plaintext / `.txt` import** — extend the v1 CSV import (Phase 6 / M7) to ingest freeform
  `.txt` exports. Unlike CSV there is no header row and no delimiter contract, so this needs
  format sniffing: detect a likely delimiter (tab / comma / `key: value` / `key=value` lines),
  or offer a "paste a sample and tag the fields" mapping UX, then reuse the existing
  `import/{detect,map,dedup,normalize}` core pipeline and the column-map UI already shipped in
  06-02. Keep the same CSV-injection inertness and fresh-UUID/timestamp assignment; it is
  inherently best-effort, so gate it behind the existing preview-before-commit step. User idea,
  surfaced mid-Phase-6 (2026-06-03).

## v2 — bigger pushes, still no mandatory server

Everything here keeps the local-first, no-backend model. (LAN sync was originally listed
here; it proved large enough to be its own phase — see v2.5 below.)

- **One-time encrypted share (local tier)** — encrypt a single entry into a standalone
  blob with a fresh key; recipient needs the blob + a separate short key, sent over
  different channels. Expiry is advisory (no server to enforce it). A true enforced
  self-destruct version would need the hosted backend — farthest-future.
- **Breach check** — check passwords against HaveIBeenPwned via the k-anonymity range API
  (only a partial hash leaves the device). The v1 local weak/reused audit already covers
  the offline half of password hygiene.
- **Card entry type** — a dedicated structured entry type (card number, cardholder,
  expiry, CVV, billing zip). The `type` field exists from v1, so this needs no format
  migration. A format migration is still involved (new schema shape) — follow the
  migration-safety rules in `03-vault-file-format.md`. Store-to-reference, not
  spray-into-forms (see `07-decisions-log.md`).
- **Fuller guided onboarding** — tooltips, an interactive "add your first password" coach.
  v1 ships only the focused safety explainer; this is the broader hand-holding layer.
- **Themes / visual polish** — v1 is intentionally "clean and obvious"; themes come here.

These v2 items are genuinely about as small as they sound — no hidden depth.

## v2.5 — Cloudless LAN sync (its own phase, needs its own design round)

LAN sync was deliberately separated from v2 because "a smarter storage adapter plus a
merge rule" badly understates it. It is the second-hardest piece of the project after the
core crypto, and it gets a dedicated design round when it begins. Known sub-problems that
design round must resolve:

- **Device discovery** — how two devices find each other on the local network.
- **Device pairing & trust** — how a device proves it is *allowed* to join your sync, so a
  roommate's laptop on the same Wi-Fi cannot. This is a real security design.
- **Transport security** — the vault is encrypted at rest, but device-to-device transfer
  needs its own secure, authenticated channel and a shared trust relationship between the
  paired devices.
- **Merge rules** — the baseline is record-level last-write-wins by `modifiedAt`, with the
  overwritten version's password preserved in that entry's `passwordHistory` so nothing is
  silently lost. But edge cases need explicit rules: two devices independently *creating*
  entries (keep both), and **delete-vs-edit** (one device tombstones an entry the other
  edited) — tombstones help but the resolution must be specified.

Once built, LAN sync also provides automatic redundancy — a second device is a live
backup against single-drive failure (it does not protect against same-location loss like
fire or theft of both devices; that is what a hosted off-site copy would add).

## Mobile batch — its own set of phases, after v2.5

**Deliberately kept loose.** Detailed planning of this batch is wasted effort now —
decisions will change before it begins. It gets its own design round. What is known:

Tauri v2 targets iOS and Android. The pure-TS `core` ports unchanged (the crypto runs in
WASM on phone webviews) — that is the hard part, already done. Known work and unknowns:

- A genuine mobile UI redesign (touch targets, responsive layout) — not free.
- A mobile storage adapter.
- **Mobile biometrics are NOT free carryover from desktop.** Face ID / Android biometric
  prompts use different OS APIs than Touch ID / Windows Hello; this is a separate
  implementation, though the same envelope-unwrap concept applies.
- **Mobile autofill is its own thing.** iOS and Android have their own OS-level autofill
  systems (separate from any browser extension) — this is how phone password managers
  autofill into apps and browsers. Integrating with them likely belongs in this batch, not
  the browser-extension phase. Its own design round.
- **Open decision, made when this batch starts:** Tauri-mobile vs. Capacitor as the mobile
  shell. Both reuse `core` cleanly.
- **Known risk:** Tauri's mobile support is its newest, least battle-tested area. Plan
  this batch, but hold it loosely — a pivot to Capacitor is possible.
- **iOS cost reality:** putting the app on other people's iPhones requires the Apple
  Developer Program (~$99/yr) — no "open anyway" escape hatch like desktop. Android allows
  direct APK sharing.

## Browser extension phase — committed, after the mobile batch

**This is a committed phase, not a "maybe" — but deliberately kept loose** until it
begins. It gets its own dedicated design round. It delivers the feature the user most
wants: detect the site, autofill the right credentials, capture new passwords on signup.

- Requires a browser extension — a standalone app cannot know what page a browser is on.
- Target browsers: **Chromium (Chrome/Edge) and Firefox.**
- It is effectively a second app: its own codebase, its own security model.
- **The security-critical unknown is extension<->app pairing:** the extension and the
  desktop app must find each other on the same machine *and* the extension must prove it
  is authorized to talk to the vault. "A secured channel" is not a design — the pairing
  and authentication is, and it is what the design round must nail. Done wrong, it is a
  path straight into the vault.
- Covers both **autofill** (fill known logins) and **auto-capture** (offer to save a new
  login on signup) — they are the same capability in two directions.
- Note: this covers account *creation* for Steam/Discord/etc. too, since signup happens in
  a browser — even though native desktop-app autofill is out of scope (see below).

## Farthest-future shelf — genuine "someday, maybe"

Not committed. Recorded so the ideas and their caveats are not lost.

- **Hosted, zero-knowledge sync version** — sync from anywhere + web access + true
  off-site backup. The client still encrypts everything before upload; the server stores
  only ciphertext and never sees the master password. This is the only item on the whole
  roadmap with a real recurring cost (a monthly server bill) and real upkeep/liability —
  which is exactly why other managers push subscriptions. Revisit only with a concrete
  reason.
- **Duress / decoy vault** — a second master password opening a believable fake vault, for
  coercion scenarios. Powerful but sharp-edged: it requires plausible-deniability crypto
  (the file must look identical whether it holds one vault or two), it can backfire if a
  coercer knows the concept exists, the decoy needs upkeep to stay believable, and it
  defends a threat (coercion) explicitly outside the stated threat model. Documented as a
  considered idea for the farthest future; if ever built, it needs a from-scratch crypto
  design round of its own.

## Explicitly NOT planned, at any phase

- **Sharing individual passwords between users.** "Friends using Coffer" means friends run
  their own copy with their own vault — never shared items. True item-sharing needs
  per-item asymmetric crypto (the hardest crypto a password manager can have) and is out
  of scope at every version.
- **Native desktop-app autofill (into Steam, Discord, etc.).** Native apps offer no safe
  extension mechanism; autofilling them means simulating keystrokes or reading other apps'
  windows — fragile and a security risk. Even commercial managers barely do this.
  Copy-paste is the realistic mechanism for native apps; the browser extension covers the
  high-value case (browsers, where logins happen constantly, and signup for all apps).
- **In-app bug reporting / diagnostics / telemetry.** No logging machinery, no crash
  reporters, no analytics. Friends report bugs over chat (Messenger/Discord). This removes
  a whole class of accidental secret-leak risk.

## How to use this roadmap

- **Do not** pull later items into v1 because they seem small. v1's value is being
  finished and trustworthy.
- v1's data model was designed to make later phases cheap: stable entry `id`s,
  `modifiedAt`, tombstones, the `type` field, the `passwordHistory` field, the
  `VaultStorageAdapter` seam. Honor those — they are the down payment on this roadmap.
- New ideas that arrive mid-build go into this document as a future-phase item — they are
  not built now. See the scope-creep note in `07-decisions-log.md`.
