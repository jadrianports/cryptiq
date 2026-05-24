# 04 — Features (v1)

This is the complete v1 scope. Anything not listed here is **out of v1** — see
`05-roadmap.md`. Build only what is here; resist scope creep.

## Design intent — what v1 should feel like

**Clean and obvious.** A password manager earns trust by being legible and predictable:
what is encrypted, when it saved, whether the vault is locked — all obvious at a glance.
This is a deliberate choice, not minimal effort. Use the `frontend-design` skill to make
it genuinely pleasant, but do not chase animation-heavy flashiness — that can undercut the
calm, trustworthy feel and slow the build. Themes and visual polish are v2.

## Screens / flows overview

1. **First-run setup + explainer** — create a vault, set a master password, optionally make a recovery key.
2. **Unlock** — open an existing vault with master password (or recovery key).
3. **Vault picker** — choose between multiple vault files on this machine.
4. **Main view** — searchable list of entries + detail/edit pane.
5. **Generator** — standalone password/passphrase generator.
6. **Health check** — weak/reused password audit.
7. **Import** — CSV import with column mapping.
8. **Settings** — auto-lock, clipboard, generator defaults, change master password, About/Security.

---

## 1. First-run setup + explainer

This doubles as onboarding. The explainer is **focused, not a full tutorial** — a few
clear screens covering only what a non-technical friend genuinely must understand:

- What Coffer is: an encrypted file of passwords on *their* computer; no account, no
  company that can reset anything.
- **The unrecoverable-password warning — this must be unmissable.** A dedicated screen:
  "If you forget this password and have no recovery key, your vault cannot be recovered.
  There is no reset." Do not let the user breeze past it.
- What Coffer does and does not protect against (one screen, plain language).

Then the setup itself:

- User chooses where the vault file lives (a normal "save file" dialog). Suggest a
  sensible default location; encourage somewhere syncable later, but do not require it.
- User sets a master password. Show a **strength meter** (`zxcvbn-ts`) and require it
  entered twice. Warn — do not hard-block — on weak passwords.
- Offer the **optional emergency recovery key** (see `02-security-design.md`): generate
  it, display it once in grouped Base32, offer a printable page, and require an explicit
  "I have saved this" confirmation before finishing. Declining is allowed.

(Fuller guided onboarding — tooltips, an interactive "add your first password" coach — is
v2. v1's job is to make the *dangerous* part impossible to miss.)

## 2. Unlock

- On launch, if a vault exists, show the unlock screen: master password field -> unlock.
- A successful unlock loads the decrypted vault into the in-memory store.
- A failed unlock shows a generic error ("Incorrect master password").
- Provide an "Unlock with recovery key instead" path. After a recovery-key unlock, prompt
  the user to set a new master password.
- No artificial lockout/attempt counter is needed in v1 (the file is offline; Argon2id is
  the brute-force cost). A small increasing delay after repeated failures is an optional
  nicety.

## 3. Vault picker

- The app can manage **multiple vault files** on one machine. A launch-time picker lists
  known vaults (by file path + label) and offers "open another file..." and "create new
  vault".
- This cheaply supports separate work/personal vaults, or two people sharing one computer
  with fully separate vaults.
- The app stores only the *paths and labels* of known vaults in its own non-secret config
  — never any vault contents or keys.

## 4. Main view — entries

### Entry list
- Shows non-deleted entries: title, username, a site icon/initial, favorite indicator.
- Sortable (title, last modified); favorites pinned on top.
- A "Recently deleted" section or filter shows tombstoned entries with restore/purge.

### Search
- Instant filter as the user types. Matches across title, username, url, tags, notes.
- Search runs over the already-decrypted in-memory vault — fast, no crypto per keystroke.
- **Keeping it instant at scale:** filtering an in-memory list of even a few thousand
  entries is sub-millisecond, so search is inherently fast. Sluggishness, if any, comes
  from UI mistakes — re-rendering everything on every keystroke, or laying out thousands
  of rows at once. The implementer should debounce the search input (~100ms) and use a
  virtualized list (render only the visible rows). Both are standard.
- An **empty state** (no entries yet) and a **no-results state** (search matched nothing)
  must be designed, not left blank.

### Entry detail / edit
- Fields: title (required), username, password, url, notes, tags, favorite.
- Password field is masked by default with a show/hide toggle.
- Per-field **copy button**. Copying the password triggers clipboard auto-clear (see
  Settings).
- "Open URL" launches the default browser.
- An inline "generate" button on the password field opens the generator and fills the
  result.
- A **"needs changing on the website"** toggle: the user ticks it to remember that a
  password was changed in Coffer but not yet updated on the actual site. A list filter
  shows all flagged entries. This is a manual reminder only — no automation — and it
  closes the vault-vs-reality lockout gap.
- **Visual identity:** each entry shows an icon. By default this is a *generated* identity
  — a colored tile with the site's first letter — which costs zero privacy. Fetching the
  site's *real* favicon is an **opt-in, off-by-default** setting, because fetching an icon
  makes a request to that site's server (a small metadata leak).
- Create, edit, and soft-delete entries. Editing updates `modifiedAt`. Deleting sets
  `deletedAt` (tombstone). **Permanent delete (purge) requires an explicit confirmation.**
- Every change writes the vault back through the storage adapter (which rotates backups).
  Consider a brief debounce so rapid edits do not thrash the disk. The UI shows a clear,
  visible **"saved" confirmation** so the user is never anxious about whether a change
  persisted.

## 5. Password generator

Two modes, both using the **CSPRNG** (`randombytes_*`) — never `Math.random`.

### Random-string mode
- Configurable length (default **20**).
- Toggles: lowercase, uppercase, digits, symbols (default: all on).
- Option: "avoid ambiguous characters" (excludes e.g. `l 1 I O 0`).
- Guarantee at least one character from each enabled class.

### Passphrase mode
- N words from a bundled wordlist (EFF long wordlist), default **5 words**.
- Configurable separator (default `-`), optional capitalization, optional appended digit.
- Show an entropy estimate so the user can judge strength.

### Generator presets
Generation rules (length, which character classes, whether symbols are allowed) can be
saved. There are sensible global defaults, and an entry can carry its own
`generatorPreset` (see `03-vault-file-format.md`) so that regenerating a password for a
site that rejects symbols or caps length "just works" without re-fiddling the options.

### Save-as-new-entry
The generator has a **"Save as new entry"** action: from a freshly generated password, one
click creates a new vault entry with that password already filled in, prompting only for a
title and username. This is the manual-workflow counterpart to browser auto-capture
(generate a strong password and file it in a single motion, instead of generate -> copy ->
create entry -> paste). The inline generate button on an entry's password field covers the
reverse direction.

Generator defaults are saved in the vault's `settings` block. The generator is reachable
both standalone and inline from the password field.

## 6. Health check — weak / reused audit

A local-only analysis (no network — that is what separates it from v2's breach check).

- **Reused:** group entries by password value; flag every entry whose password is shared
  with at least one other entry.
- **Weak:** score each password (`zxcvbn-ts` or an entropy heuristic); flag those below a
  threshold.
- **Stale (age awareness):** flag passwords that have not changed in a long time, using
  the age derived from `modifiedAt` / `passwordHistory`. A user may have a strong recent
  password on a low-value account and an old one on a high-value account — age awareness
  surfaces exactly that mismatch.
- **Needs-site-update:** also surface entries the user flagged as "changed in Coffer but
  not yet on the website" (see Entry detail).
- Present results as a "Health" view: a list of flagged entries (weak / reused / stale /
  needs-update), each with a one-tap jump to fix it (opens the entry with the generator
  ready).
- Runs entirely over the in-memory decrypted vault.

## 7. CSV import

For migrating browser-saved passwords (and any other CSV).

- Parse CSV with `papaparse`.
- **Recognize common formats** by their headers and auto-map: Chrome/Edge
  (`name,url,username,password,note`), Firefox, and Bitwarden's CSV export.
- **Generic fallback:** if headers are unrecognized, show the detected columns and let the
  user map each to a Coffer field (title/username/password/url/notes).
- Preview the rows before committing.
- Detect likely duplicates (same url+username) and let the user skip or merge.
- Imported entries get fresh UUIDs and timestamps.
- After import, remind the user to **securely delete the source CSV** — a plaintext
  password export in Downloads is dangerous. The app cannot do this for them; it reminds.

## 8. Settings & lock behavior

### Auto-lock
- Lock the vault after **N minutes idle** (default **5**, configurable; allow "never" with
  a clear warning).
- Also lock on: app window close/minimize (configurable), and system sleep.
- Locking **clears the decrypted vault and keys from the in-memory store** and returns to
  the unlock screen.

### Clipboard auto-clear
- After copying a password, clear the clipboard after **~25 seconds** (configurable).
- Only clear if the clipboard still contains the value Coffer placed there.
- The UI states this is best-effort (see `02-security-design.md`).

### Change master password
- Re-derive `master_key` from the new password, re-wrap the vault key, save. Per the
  envelope design this is fast and does not touch the entries blob.
- Require the current master password first.

### Re-prompt for master password on sensitive actions
While the vault is unlocked, certain sensitive actions re-ask for the master password
before proceeding: revealing a password, changing the master password, and exporting a
backup copy. This is a small guard against someone using a briefly-unattended unlocked
vault. It is distinct from auto-lock (which clears the whole session); the re-prompt is a
per-action confirmation.

### Export encrypted backup copy
A one-click **"Export backup copy"** action writes a copy of the vault file to a location
the user picks (USB stick, another folder, a cloud-drive folder they already use). The
exported file is the **already-encrypted** vault — no new crypto, just a file copy to a
chosen path. This is v1's only off-machine backup mechanism: local rotating backups
(`03-vault-file-format.md`) sit next to the vault and die with the drive, and LAN sync
(automatic redundancy) is v2. The UI should gently remind the user to do this periodically.

### About / Security
- A short, honest screen stating the threat model from `02-security-design.md`. Include
  the app version and a link to the public repo.

## Distribution (part of v1)

- `tauri build` produces native installers. **Windows is the primary dev and first build
  target** (`.msi`/`.exe`); macOS (`.dmg`) and Linux builds are produced by **CI** so the
  developer's macOS machine stays a non-dev environment.
- A GitHub Actions workflow using `tauri-action` builds all platforms and publishes a
  GitHub Release on each version tag.
- Code-signing is **not** done in v1 — installs show an "unidentified developer" warning
  and the user clicks through ("open anyway"). Paid OS signing is a documented future
  scale-up, not v1 scope.
- The **auto-updater** is **v1.5**, not v1 — see `05-roadmap.md` and `06-build-plan.md`.

## Explicitly NOT in v1

Biometric unlock, password history population, auto-updater (all v1.5); TOTP/2FA storage,
breach checking, the card entry type, one-time share, themes, fuller onboarding (all v2);
LAN sync (its own phase, v2.5); **custom/arbitrary labeled fields on an entry**
(deliberately YAGNI'd — the `notes` field covers the occasional extra; revisit only when a
real need appears); browser autofill/extension; mobile; any hosted/multi-user server; any
in-app bug-reporting, diagnostics, or telemetry machinery (friends report bugs over chat —
see `07-decisions-log.md`).
