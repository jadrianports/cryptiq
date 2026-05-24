# 07 — Decisions Log

Every significant fork resolved during design, why it went the way it did, and the roads
not taken. Purpose: stop future-you (or any implementer) from silently re-litigating
settled questions. If you want to change one of these, change it deliberately — and update
the other docs to match.

## Scope & model

**Local-first, single encrypted vault file.** Chosen over local-only (too limiting for the
multi-device wish) and over a hosted server (real monthly cost, upkeep, and the liability
of holding others' vaults). The file is designed portable from day one so sync is a later
drop-in, not a rearchitecture.

**"Friends using it" = local distribution, not multi-user hosting.** The user clarified
that friends using Coffer means friends installing their own copy with their own vault —
NOT sharing passwords between people. This deleted the hardest crypto problem in the
project (per-item asymmetric sharing) and removed any need for a server.

**Threat model: "casual snooping / lost laptop."** Strong encryption at rest; explicitly
not defending an already-compromised machine, keylogging, evil-maid, or coercion. This is
the same honest bar KeePass/Bitwarden live with. Stated plainly in-app.

## Stack

**App shell: Tauri v2.** Chosen over Electron (mature but 100MB+ builds, heavier) and Wails
(smaller community, weaker mobile path). For a security tool: small binaries, low resource
use, smaller attack surface, and a real mobile path later. Electron remains the legitimate
"maximum maturity" alternative if that ever matters more than size.

**UI: Svelte + TypeScript + Vite.** The user chose Svelte (less boilerplate, pleasant for
an app this size); Context7 MCP keeps Claude Code current on Svelte docs. React was the
original recommendation purely for tooling familiarity — but because `core` is
framework-agnostic, the choice never touched the security-critical code.

**Crypto: libsodium, not Web Crypto.** Web Crypto lacks native Argon2id. libsodium provides
Argon2id + the AEAD cipher + CSPRNG in one audited package. This layer is fixed: "boring
and proven" outranks everything else here.

**Crypto runs in TypeScript `core` (WASM), not Rust.** If crypto lived in Rust it would
chain `core` to Tauri forever and make a browser build impossible. WASM Argon2id cost is
negligible for a once-per-unlock operation.

## Crypto design

**Envelope encryption.** A random vault key encrypts the data once; that vault key is then
wrapped separately by the master-password key, the recovery key, and (v1.5) the OS-keychain
biometric key. Chosen over deriving the data key directly from the master password because
it makes multiple unlock paths cheap and makes master-password change instant (re-wrap a
small key, never re-encrypt the data).

**Opt-in printable recovery key.** Chosen over pure no-recovery (a setup typo or memory
slip would nuke everything) and over any vendor backdoor (impossible by design — there is
no vendor). Opt-in preserves the maximally-paranoid no-second-secret path for those who
want it. Tradeoff consciously accepted: the recovery key becomes a paper single-point-of-
failure in the other direction.

## Features

**v1 is fully manual** (open app, search, copy, paste). Autofill/auto-capture require a
browser extension and are a later committed phase. v1 being "just" a manual encrypted
vault is the correct first build — it fully solves the actual problem (passwords off a
plaintext note).

**"Save as new entry"** added to the generator (the user's idea). The manual-world version
of auto-capture: generate a strong password and file it as an entry in one motion.

**Weak/reused audit in v1**; breach check (HaveIBeenPwned) deferred to v2. The local audit
needs no network; breach check does. The audit directly attacks the user's stated
password-reuse habit.

**TOTP/2FA storage deferred to v2.** The user uses 2FA on only a few accounts, and
co-locating passwords + 2FA seeds slightly weakens 2FA's value.

**Encrypted backup export in v1.** v1 has no automatic off-machine backup (LAN sync is v2);
the export button is the v1/v1.5-era safety net. It just copies the already-encrypted file
to a user-chosen location — no new crypto.

**App feel: "clean and obvious."** A security tool earns trust by being legible and
predictable. Themes/polish deferred to v2.

**Second-tier v1 polish added during a late planning pass** (all cheap, all fold into
existing v1 surfaces): password **age/stale awareness** in the audit; saveable **generator
presets** (global + per-entry); **generated visual identity** per entry, with real-favicon
fetch opt-in/off-by-default for privacy; **master-password re-prompt** on sensitive
actions; **visible save confirmation** and **confirm-on-permanent-delete**; a per-entry
**"needs changing on the website" flag** to close the vault-vs-reality lockout gap.

**File-size padding added to v1.** The vault file's size leaks a rough entry count even
while contents stay encrypted. Padding to fixed buckets closes this. The leak is minor and
outside the threat model, but padding is in v1 purely because the file format is cheapest
to get right before any real vaults exist.

**Custom/arbitrary labeled fields on an entry: YAGNI'd.** A real feature in mainstream
managers, but the `notes` field covers the occasional extra. Not built until a concrete
need appears.

**Migration safety promoted to a first-class concern.** Format will evolve (v2 card type).
A buggy migration could corrupt real vaults. Rule: back up, migrate a copy, verify it
decrypts, then swap; never transform in place; test against stored old-format sample
vaults. "Start fresh" is rejected — it would destroy user data.

**Onboarding: focused v1 explainer, fuller onboarding v2.** v1 ships a few-screen explainer
whose job is making the unrecoverable-master-password danger unmissable for non-technical
friends. The broader tutorial layer is v2.

## Phasing & process

**Phase order (Option A): v1 -> v1.5 -> v2 -> v2.5 -> mobile batch -> browser extension.**
The user chose to do mobile before the extension. Rationale: the extension benefits from a
hardened `core` and app; mobile work hardens `core` further; mobile directly replaces the
"passwords on my phone" habit. The extension is a COMMITTED phase, not shelved.

**LAN sync split into its own phase (v2.5).** It was originally one bullet inside v2. An
audit of the later phases found that "smarter storage adapter + merge rule" badly
understated it — device discovery, device pairing/trust, transport-channel security, and
non-trivial merge edge cases (delete-vs-edit) make it the second-hardest part of the
project after the core crypto. Splitting it keeps v2 honestly sized and gives sync its own
design round.

**Later phases deliberately kept loose, but honestly labelled.** v1.5 and v2 were tightened
(a late audit found real gaps: biometric-failure fallback, bad-update recovery, the v2
card-type migration). The mobile batch and the extension phase are kept intentionally
under-specified — detailed planning of the distant future is wasted effort — but the
roadmap explicitly labels their known unknowns (mobile uses different biometric APIs and
has its own OS-level autofill; the extension's hard part is extension<->app pairing/auth)
rather than pretending they are simple.

**Per-phase "definition of done" checklists** (in `06-build-plan.md`) for every phase, not
just v1. The user extended this from a v1-only idea. It is the structural defense against
scope creep.

**Scope creep — explicitly named as the project's biggest non-technical risk.** This very
design conversation grew the vision substantially (biometrics, history, sync, share,
mobile, extension all became "real"). That growth was kept safe by *phasing* every idea
rather than dumping it into v1. The discipline going forward: new ideas mid-build go into
`05-roadmap.md` as a future-phase item; they are not built now; v1's frozen scope is
defended. The user's own rule: "Build v1. Actually finish it. Use it."

## Distribution, repo, money

**Repo: private for now; public/open-source deferred.** "Public repo" (a visibility
toggle) and "open source" (attaching a license granting use/modify/redistribute rights)
are different things. The plan: build private, and IF/WHEN going public, first choose a
license (MIT vs. GPL — undecided, no rush) then flip to public. Blocks nothing. Note: the
v1.5 auto-updater is simplest with a public repo; revisit repo status at v1.5.

**Code-signing: skipped for v1.** Unsigned installs show an "unidentified developer"
warning; the user and friends click "open anyway." Paid OS signing (~$99/yr Apple,
~$100-300/yr Windows) is a documented optional future scale-up.

**Monetization: free now; one-time purchase kept as a genuine "someday" goal.** Tension
acknowledged: a public/open-source repo means anyone can compile it free — so what would be
sold is *convenience* (official signed, auto-updating builds), not the code. A one-time
purchase also does not fit a hosted service (servers cost monthly forever). To be resolved
properly alongside the licensing decision, if/when monetization becomes real.

**Cost summary: $0 to build and run v1 through the mobile batch.** The only real money is
optional OS code-signing, and a monthly server bill IF the farthest-future hosted version
is ever built.

## Roads not taken

- **Pure-browser app** (File System Access API) — Chrome/Edge-only for the good version;
  rejected in favor of Tauri.
- **Hosted-first / cloud-first** — rejected: cost, upkeep, liability. Hosted sync is a
  farthest-future maybe, not a near-term plan.
- **Electron** — rejected for build size and attack surface; noted as the maturity fallback.
- **TOTP, breach check, card type, themes in v1** — all deferred to v2 to keep v1 shippable.
- **Native desktop-app autofill (Steam/Discord)** — rejected at every phase: native apps
  offer no safe mechanism; even commercial managers barely do it. Copy-paste is the
  realistic answer; the browser extension covers signup for these apps anyway.
- **In-app bug reporting / diagnostics / telemetry** — rejected entirely. Friends report
  bugs over chat. Removes a class of accidental secret-leak risk.
- **Duress / decoy vault** — considered; shelved to the farthest future. Needs
  plausible-deniability crypto, can backfire against an informed coercer, needs upkeep,
  and defends a threat outside the stated model.

## Known debt / accepted limitations

- JavaScript cannot guarantee wiping secrets from memory; only minimized. Not fixable in
  this stack.
- The recovery key is a paper single-point-of-failure: lose the master password AND the
  recovery key = vault gone. Correct for a zero-knowledge tool; a real sharp edge.
- v1 has no automatic off-machine backup; the export button is manual and depends on the
  user actually using it. LAN sync (v2) adds automatic redundancy.
- Tauri's mobile support is its least-mature area; the mobile batch may need a pivot to
  Capacitor.
- CSV import is messy in practice (browser export formats drift); expect fiddling.
