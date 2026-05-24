# 08 — Glossary

Plain-language definitions of the technical terms used across this plan. Written so a
non-technical friend (or future-you on a tired day) can follow the other documents.

**AEAD** — "Authenticated Encryption with Associated Data." An encryption method that does
two jobs at once: hides the data, AND stamps it so any later tampering is detected. Coffer
uses an AEAD cipher (XChaCha20-Poly1305) so a modified vault file is caught, not silently
trusted.

**Argon2id** — A "key derivation function": it turns your master password into the actual
encryption key. It is deliberately slow and memory-hungry, which is good — it makes an
attacker's password-guessing attempts slow and expensive.

**Auto-capture** — A password manager noticing you just created an account and offering to
save the new login automatically. Requires a browser extension. Coffer: browser-extension
phase.

**Autofill** — A password manager detecting the site you are on and filling in the login
for you. Requires a browser extension. Coffer: browser-extension phase.

**Base32 / Base64** — Ways of writing raw binary data as ordinary text characters. Coffer
shows the recovery key in Base32 (readable groups of letters/digits) and stores encrypted
bytes in the vault file as Base64.

**Biometric unlock** — Unlocking with a fingerprint or face instead of typing a password
(Touch ID on Mac, Windows Hello on Windows). Coffer: v1.5.

**Brute force** — An attacker trying enormous numbers of password guesses until one works.
Argon2id and a strong master password are what make this impractical.

**Ciphertext** — Data after encryption: unreadable scrambled bytes. The opposite of
plaintext.

**Code-signing** — A paid certificate that proves an app came from you, so the OS does not
show an "unidentified developer" warning on install. Optional; skipped in v1.

**Core (the `core` library)** — The pure-logic heart of Coffer: all the crypto, the vault
format, the entry handling. It has no buttons and no knowledge of files or phones, so the
same `core` can power the desktop app, a future phone app, or a browser build unchanged.

**Credential stuffing** — An attack where, after one website leaks its passwords,
attackers automatically try those same email+password combos on hundreds of other sites.
It only works if you reuse passwords — which is the habit a password manager fixes.

**CSPRNG** — "Cryptographically Secure Pseudo-Random Number Generator." A source of
randomness strong enough for security use. All Coffer keys, salts, and generated passwords
come from one. Ordinary `Math.random` is NOT secure enough and is banned here.

**CSV** — A plain-text spreadsheet-like file format. Browsers export saved passwords as
CSV; Coffer's import reads it.

**End-to-end / zero-knowledge encryption** — A design where data is encrypted on your
device before it ever leaves, so any server storing it only ever holds an unreadable blob
and can never see your passwords or master password. How a well-built cloud password
manager works.

**Envelope encryption** — Coffer's key design. Instead of your master password directly
encrypting your data, a separate random "vault key" encrypts the data once, and that vault
key is itself encrypted ("wrapped") by your master password — and optionally by the
recovery key and biometrics. Lets you have several unlock methods and change your master
password instantly.

**GitHub Actions** — A free automation robot on GitHub that runs tasks when you publish
code — including building the macOS version of Coffer on a Mac in the cloud, so you do not
need a Mac dev setup.

**KDF (Key Derivation Function)** — See Argon2id. The function that converts a password
into an encryption key.

**LAN sync** — Devices on the same local network (home Wi-Fi) syncing directly with each
other, with no server in between. Coffer: v2.

**libsodium** — A well-tested, audited, free cryptography library. Coffer uses it for all
crypto. The golden rule: never invent your own crypto — use a proven library like this.

**Master password** — The single password you memorize that unlocks your vault. Never sent
to any website; exists only on your device. The one secret you must protect and never
forget.

**Metadata leakage** — Information that escapes not through the *contents* of encrypted
data but through its *shape* — file size, timing, count. Coffer pads the vault file so its
size does not leak roughly how many entries it holds.

**Migration (format migration)** — Upgrading a vault file from an older format version to
a newer one when the format changes. Must be done safely (back up, migrate a copy, verify,
then swap) so a bug cannot corrupt a real vault.

**Padding** — Adding meaningless filler to data before encryption so the resulting file
size reveals nothing about how much real data is inside. See "metadata leakage.

**MCP** — "Model Context Protocol." A way for AI tools to connect to external services.
Mentioned only because Context7 (an MCP) helps Claude Code stay current on Svelte docs.

**Monorepo** — One code repository holding multiple related packages (here: `core` and the
desktop app) so they are developed together.

**Nonce** — A random "number used once" included with each encryption operation so that
encrypting the same data twice never produces identical ciphertext. Reusing one is a
crypto mistake; Coffer uses a fresh random nonce every time.

**Open source** — Code published with a license that legally lets others use, modify, and
share it. Note: a "public repo" only means people can SEE the code; it becomes open source
only when you attach such a license.

**Plaintext** — Ordinary readable, unencrypted data. Your passwords in a phone note are
plaintext — the problem Coffer solves.

**Plausible deniability** — A property where you can credibly deny that hidden data exists
at all, because the file looks identical whether or not it is there. Needed for a duress/
decoy vault. Hard to do correctly; Coffer: farthest-future maybe.

**Public / private repo** — A GitHub visibility setting. Public = anyone can see the code.
Private = only you and invitees. Separate from licensing/open source.

**Recovery key** — An optional long random backup code, generated and printed at setup,
that can also unlock your vault if you forget your master password. Coffer never stores the
key itself, only an encrypted copy of the vault key wrapped by it.

**Scope creep** — When a project quietly grows beyond its planned scope through many small
"while I'm here" additions, until it never gets finished. The main non-technical risk to
Coffer; defended against with phasing and per-phase done-checklists.

**Soft delete / tombstone** — Marking an entry as deleted (with a timestamp) instead of
truly removing it. Lets deletions sync correctly across devices later, and lets you restore
something from "recently deleted."

**Storage adapter** — The small piece of code that answers "where does the encrypted vault
file actually go?" — a local file, another device (LAN sync), or a server. Swapping it is
how Coffer reaches new platforms without changing the crypto.

**Tauri** — The framework Coffer is built on: it wraps a web-style UI in a small native app
shell, producing tiny installers for Windows/Mac/Linux (and, later, mobile).

**tauri-action** — A helper that plugs into GitHub Actions and knows how to build Tauri
apps into installers for every platform automatically.

**Threat model** — The explicit list of what a security tool does and does not defend
against. Being honest about the "does not" half is part of being trustworthy.

**TOTP / 2FA** — Two-factor authentication: the rotating 6-digit codes (Google
Authenticator etc.) you enter in addition to a password. Coffer can store the secrets that
generate them — deferred to v2.

**Vault** — Your encrypted collection of passwords. In Coffer it is a single file
(`.coffer`).

**Virtualized list** — A UI technique where only the handful of list rows actually visible
on screen are drawn, not all of them. Keeps a list of thousands of entries scrolling
smoothly.

**WASM (WebAssembly)** — A format that lets non-JavaScript code (like the libsodium crypto
library) run fast inside a web-style environment. It is how Coffer's crypto runs inside the
TypeScript `core`.

**XChaCha20-Poly1305** — The specific AEAD encryption cipher Coffer uses to encrypt the
vault. XChaCha20 does the scrambling; Poly1305 does the tamper-detection stamp.

**Zero-knowledge** — See "end-to-end / zero-knowledge encryption."
