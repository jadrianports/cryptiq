# 02 — Security Design

**Read this before writing a single line of crypto.** A bug here silently exposes every
password the user owns. The guiding discipline: **use well-tested primitives exactly as
intended; never invent crypto.**

## Threat model

### In scope — Coffer must defend against these

- **A stolen vault file.** Someone copies the `.coffer` file. Without the master password
  (or recovery key) it is useless ciphertext.
- **A lost or stolen device.** Same as above — the file at rest is encrypted.
- **An untrusted sync host.** If the user later puts the file in a synced folder, or a
  hosted version is ever built, the storage provider/server sees only ciphertext.
- **Casual local snooping.** A nosy roommate, a borrowed laptop, a shoulder-surfer who
  doesn't know the master password.
- **A tampered vault file.** Modified ciphertext must be *detected*, not silently
  decrypted to garbage.

### Out of scope — Coffer does NOT defend against these (state this honestly to users)

- **A compromised machine.** Malware, a keylogger, or a screen-scraper running as the user
  can capture the master password as typed or secrets while the vault is unlocked.
- **An attacker watching the user type the master password.**
- **"Evil maid" attacks** — physical tampering with the device/OS before use.
- **Coercion** — someone forcing the user to unlock the vault. (A duress/decoy vault was
  considered to address this and deliberately shelved — see `05-roadmap.md` and
  `07-decisions-log.md`.)
- **Memory forensics while unlocked** — see "Known limitations" below.

This out-of-scope list is the *same* one KeePass and Bitwarden live with. It is the honest
standard bar, not a compromise. The app states this plainly in an About/Security screen.

## Cryptographic design

All crypto goes through **libsodium** (`libsodium-wrappers-sumo`, WASM, inside the TS
`core`). No other crypto library. No hand-written crypto. No `Math.random` near secrets.

### Why libsodium and not the Web Crypto API

Web Crypto is fine but does not natively provide Argon2id, the memory-hard function needed
to stretch the master password. libsodium provides Argon2id, the AEAD cipher, and the
CSPRNG in one audited package — fewer moving parts, one trusted dependency.

### Primitives

| Purpose | Primitive | libsodium function |
|---|---|---|
| Key derivation (master password -> key) | Argon2id | `crypto_pwhash` |
| Authenticated encryption | XChaCha20-Poly1305 (IETF) | `crypto_aead_xchacha20poly1305_ietf_*` |
| Random bytes (keys, nonces, recovery key) | CSPRNG | `randombytes_buf` |
| Domain separation for derived wrap-keys | BLAKE2b | `crypto_generichash` |

### Argon2id parameters (v1 defaults)

- Algorithm: Argon2id (`crypto_pwhash_ALG_ARGON2ID13`)
- Ops limit: **3**
- Memory limit: **268435456 bytes (256 MiB)**
- Salt: 16 random bytes, unique per vault

**These parameters are stored in the vault file header**, not hardcoded into unlock logic,
so they are tunable per vault and can be raised over time without breaking old vaults.

### Envelope encryption — the key model

Do **not** derive the data-encryption key directly from the master password. Use an
envelope:

```
                       ┌─────────────────────────────────────┐
master password ──Argon2id──▶ master_key ──┐                  │
                                            ├─ wraps ─▶ wrapped_vault_key_master
                                            │                  │
   vault_key  (32 random bytes) ────────────┘                  │
        │                                                       │
        └── encrypts ──▶ encrypted entries blob                 │
                                            ┌──────────────────┘
recovery key (32 random bytes) ─BLAKE2b─▶ recovery_wrap_key ─ wraps ─▶ wrapped_vault_key_recovery
```

- `vault_key` is 32 random bytes generated once at vault creation. It encrypts the entries
  blob with XChaCha20-Poly1305. The data is encrypted **once**.
- `vault_key` is then **wrapped** (encrypted) by `master_key`; that wrapped copy is stored.
- If the user opts into recovery, `vault_key` is *also* wrapped by a key derived from the
  recovery key, and that second wrapped copy is stored too.
- **Either** wrapped copy unwraps `vault_key` and decrypts the vault.

Biometric unlock (v1.5) is simply a **third unwrap-path**: on a given device, the OS
keychain (macOS Keychain / Windows Credential Manager) stores another wrapped copy of
`vault_key`, released only on a successful Touch ID / Windows Hello check. It is
per-device, never leaves the device, and the master password always remains the backstop.

#### Why this design

- **Multiple access paths without re-encrypting data** — recovery key and biometrics are
  each just another small wrapped key, not another copy of the vault.
- **Instant master-password change** — re-derive `master_key`, re-wrap `vault_key`,
  replace one small field. The entries blob is never touched.
- **Correct-password check is free** — XChaCha20-Poly1305 is authenticated; a wrong
  password fails the Poly1305 tag. No separate, leaky "password verifier" is needed.

### Encryption details

- Every encryption gets its **own fresh random 24-byte nonce** (XChaCha20's large nonce
  makes random nonces safe). Never reuse a nonce under the same key.
- Nonces are stored alongside their ciphertext (they are not secret).
- Use the AEAD's *associated data* parameter to bind the file format version into the
  ciphertext, so a downgrade/format-confusion attack is detected.

## The emergency recovery key

- **Opt-in**, offered during vault setup. Declining is valid — present it neutrally.
- It is **32 random bytes** from the CSPRNG, shown **once**, encoded as grouped uppercase
  Base32 (e.g. `K7QF2-9XM4A-...`).
- Setup must: show it, offer a printable page, and require an explicit "I have saved this"
  confirmation before continuing.
- The app **never stores the recovery key itself** — only `wrapped_vault_key_recovery`.
- Recovery-key unlock is a distinct UI path. After a successful recovery unlock, prompt
  the user to set a new master password.
- Deriving the wrap-key from the recovery key: pass the 32 raw bytes through
  `crypto_generichash` with a fixed application-specific personalization string for domain
  separation; use the 32-byte output as the XChaCha20-Poly1305 key.

## The auto-updater is a security surface — treat it as one (v1.5)

The app will ship an auto-updater (Tauri updater plugin) in v1.5. **Whoever holds the
updater signing private key can push code to every user's machine.** Therefore:

- The updater **private key never leaves a secure location** — ideally a GitHub Actions
  secret used only by the release workflow, never on a daily-driver laptop in plaintext.
- Leaking it = attackers can ship malware as a "Coffer update"; losing it = no more
  updates can ever ship. Treat either as a critical incident.
- The public verification key is compiled into the app; updates failing signature
  verification must be rejected, never installed.

## Rules the implementer must never break

1. **Never roll your own crypto.** Only libsodium primitives, used as documented.
2. **Never write plaintext secrets to disk.** Not entries, not the vault key, not the
   master password — not in files, logs, temp files, or crash dumps.
3. **Never log secrets.** No logging of passwords, keys, or decrypted entries, even in dev
   builds. (Note: Coffer ships no diagnostics/bug-report machinery at all — see
   `07-decisions-log.md` — which removes a whole class of accidental-leak risk.)
4. **CSPRNG only.** All keys, nonces, salts, generated passwords, and the recovery key
   come from `randombytes_*`. `Math.random` is banned for anything security-relevant.
5. **Fresh nonce every time.** Never reuse a nonce under the same key.
6. **Fail closed.** Any decryption/authentication failure aborts and surfaces an error;
   never fall back to partial or unauthenticated data.
7. **Pin and minimize dependencies.** Lockfile committed, versions pinned, dependency
   count low. Each dependency is attack surface.
8. **Zero what you can.** Use `sodium_memzero` on key buffers when finished. (See
   limitations for what this cannot guarantee.)

## Known limitations — document these, do not pretend otherwise

- **JavaScript cannot guarantee memory zeroing.** GC'd strings (the master password,
  decrypted passwords) may linger. `sodium_memzero` helps for libsodium's own
  `Uint8Array` buffers; it cannot scrub GC'd JS strings. Minimize how long secrets live as
  strings; accept that perfect scrubbing is not achievable here, and say so.
- **Clipboard auto-clear is best-effort.** The OS, clipboard managers, or sync features
  may retain copied data. Clearing after a timeout reduces but does not eliminate exposure.
- **The vault is only as strong as the master password.** Argon2id slows brute force; it
  cannot rescue a weak master password. Setup must show a strength meter and encourage a
  strong, unique master password (a passphrase is a good suggestion).

## Testing the crypto (non-negotiable — see `06-build-plan.md`)

Before any UI exists, the crypto and vault-format code must have:
- **Round-trip tests** — create -> save -> load -> unlock -> data identical.
- **Wrong-secret tests** — wrong master password / wrong recovery key fails cleanly.
- **Tamper tests** — flipping any byte of ciphertext, nonce, or header causes a detected
  authentication failure, never silent garbage.
- **Recovery-path tests** — vault opens via recovery key; master-password change works and
  re-wrap leaves data intact.
- **Known-answer sanity checks** — confirm libsodium primitives behave as expected.

A security tool with an untested crypto layer is not trustworthy. This is part of the
definition of "done" for Milestone 1.
