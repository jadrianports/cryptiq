# Coffer — Build Plan

> **"Coffer" is a working codename** (a coffer is a strongbox / treasure chest). It is a
> placeholder — rename the project to anything you like and do a project-wide find/replace
> before the first commit.

A local-first, self-built password manager. This folder is a **handoff plan**, not code.
Every document here is the resolved output of a deliberate design interview — the
decisions are made and justified, so an implementer (you, or Claude Code) can build
without re-litigating them. The reasoning behind each fork lives in `07-decisions-log.md`;
unfamiliar terms are defined in `08-glossary.md`.

## What Coffer is

A desktop app that keeps your passwords in a **single encrypted file** on your own
machine. You unlock it with one master password. There is no account, no server, no
subscription, no company. You built it, so you can audit it.

## What Coffer is NOT (v1)

- **Not a cloud service.** There is no backend. The vault is a file on your disk.
- **Not a password-sharing tool.** "Friends using it" means friends *install the app* and
  keep *their own separate vault*. Coffer never sends one person's secrets to another.
- **Not a defense against a compromised machine.** If malware or a keylogger is already
  running as you, Coffer cannot save you. See `02-security-design.md`.

## The one-sentence architecture

A pure-TypeScript `core` library does all the security-critical work; a thin Tauri app
wraps it in a Svelte desktop UI and handles reading/writing the file — and because `core`
knows nothing about files, platforms, or UI frameworks, the same core can later power a
phone or browser build without a rewrite.

## Resolved decisions (short version — full reasoning in 07-decisions-log.md)

| Area | Decision |
|---|---|
| Scope | Local-first; single portable encrypted vault file; sync is a later, optional drop-in |
| App shell | Tauri v2 (tiny binaries, low attack surface, a real mobile path later) |
| UI | Svelte + TypeScript + Vite |
| Core | A separate, pure-TS `core` package — zero UI, zero platform code |
| Crypto | Argon2id (key derivation) + XChaCha20-Poly1305 (encryption), via libsodium |
| Key model | Envelope encryption: a random vault key, wrapped by master password and (optionally) a recovery key |
| Recovery | Opt-in printable emergency recovery key |
| Threat model | Strong encryption at rest; not defending an already-compromised device |
| Distribution | Public open-source GitHub repo; native installers; auto-updater (v1.5) |
| Dev environment | Windows-first (the dev machine); macOS builds produced via CI |
| Cost | $0 to build and run. OS code-signing (~$99-300/yr) noted as an optional future scale-up |
| Monetization | Free for now; a one-time-purchase model is a genuine "someday" goal, kept open |

## Phase summary (full detail in 05-roadmap.md)

- **v1** — the real first build: a feature-complete single-desktop password manager.
- **v1.5** — cheap, high-value fast-follows: biometric unlock, password history, auto-updater.
- **v2** — bigger pushes: one-time encrypted share, breach check, card entry type, fuller
  onboarding, themes.
- **v2.5** — cloudless LAN sync, split into its own phase (it needs its own design round).
- **Mobile batch** — its own phase set after v2.5; deliberately loose.
- **Extension phase** — browser autofill/auto-capture, after desktop *and* mobile; loose.
- **Farthest-future shelf** — hosted zero-knowledge version, duress/decoy vault.

## Documents — suggested reading order

1. **`01-architecture.md`** — the monorepo layout and the core/app split.
2. **`02-security-design.md`** — threat model, crypto, recovery, rules the implementer must never break. *Read before writing any crypto.*
3. **`03-vault-file-format.md`** — the exact on-disk format and entry schema.
4. **`04-features-v1.md`** — detailed spec for every v1 feature.
5. **`05-roadmap.md`** — what is deferred, and the full phase plan.
6. **`06-build-plan.md`** — the phased, milestone-by-milestone build order. **Start building here.**
7. **`07-decisions-log.md`** — every fork resolved, and why; the roads not taken.
8. **`08-glossary.md`** — plain-language definitions of the technical terms.
9. **`09-testing-strategy.md`** — what to test, with which tool, and how hard.

## A note on trust

This is a security tool. The reason to build your own is to *fully understand and trust*
it. That only works if it is built carefully: never roll your own crypto, never log
secrets, test the crypto layer hard, keep dependencies minimal and pinned. Those rules are
not optional — they are in `02-security-design.md` and the build plan enforces them.
