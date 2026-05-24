# 03 — Vault File Format

The vault is **one file**. This document defines its exact layout. The format is the
contract every present and future Coffer client must honor — treat changes to it as
versioned migrations, never silent edits.

## File overview

- Extension: `.coffer`
- Encoding: a **UTF-8 JSON document**. The *outer* structure is plaintext JSON (so the
  file is inspectable and debuggable); all *secret* material inside it is encrypted bytes,
  Base64-encoded.
- The outer JSON being readable leaks **nothing sensitive** — only format version, KDF
  parameters, salts, nonces, and non-secret timestamps. Entry contents are inside the
  encrypted blob.

## Outer file structure

```json
{
  "format": "coffer-vault",
  "version": 1,
  "kdf": {
    "algo": "argon2id",
    "opslimit": 3,
    "memlimit": 268435456,
    "salt": "<base64, 16 bytes>"
  },
  "wrappedKeys": {
    "master": {
      "nonce": "<base64, 24 bytes>",
      "ciphertext": "<base64>"
    },
    "recovery": {
      "nonce": "<base64, 24 bytes>",
      "ciphertext": "<base64>"
    }
  },
  "data": {
    "nonce": "<base64, 24 bytes>",
    "ciphertext": "<base64>"
  },
  "meta": {
    "createdAt": "<ISO 8601>",
    "modifiedAt": "<ISO 8601>",
    "deviceLabel": "<string, optional, non-secret>"
  }
}
```

### Field notes

- `format` / `version` — identify the format. A client that does not recognize `version`
  must refuse to open the file rather than guess. The version is also passed as AEAD
  associated data when encrypting `data`, binding it cryptographically.
- `kdf` — the Argon2id parameters used to derive `master_key`. Stored here so they are
  tunable per vault and can be raised over time.
- `wrappedKeys.master` — the vault key encrypted under `master_key`. Always present.
- `wrappedKeys.recovery` — the vault key encrypted under the recovery-derived key.
  **Present only if the user enabled a recovery key.** Omit the field entirely otherwise.
- (Biometric unlock, v1.5, does **not** add a field here — the OS keychain stores that
  wrapped copy on the device, outside the portable vault file.)
- `data` — the entries document (below), serialized to JSON, **padded** (see "File-size
  padding" below), then encrypted under the vault key.
- `meta` — non-secret bookkeeping. `deviceLabel` is optional and aids future sync UX. Put
  nothing sensitive in `meta`.

## Decrypted `data` payload — the entries document

When `data.ciphertext` is decrypted with the vault key, the plaintext is this JSON:

```json
{
  "schemaVersion": 1,
  "entries": [
    {
      "id": "<uuid v4>",
      "type": "login",
      "title": "GitHub",
      "username": "octocat",
      "password": "<the secret>",
      "url": "https://github.com",
      "notes": "free-form text",
      "tags": ["dev"],
      "favorite": false,
      "needsSiteUpdate": false,
      "generatorPreset": null,
      "passwordHistory": [
        { "password": "<previous secret>", "changedAt": "<ISO 8601>" }
      ],
      "createdAt": "<ISO 8601>",
      "modifiedAt": "<ISO 8601>",
      "deletedAt": null
    }
  ],
  "settings": {
    "autoLockMinutes": 5,
    "clipboardClearSeconds": 25,
    "generatorDefaults": { "...": "see 04-features-v1.md" }
  }
}
```

### Entry schema rules

- `id` — a UUID v4, assigned on creation, **immutable**. The stable identity used for
  editing and, crucially, for future LAN sync/merge. Never reuse or regenerate it.
- `type` — `"login"` for v1. The field exists now so v2 can add `"card"`, `"identity"`,
  `"note"` without a format migration.
- `title`, `username`, `password`, `url`, `notes` — entry content. Only `title` is
  required; the rest may be empty strings. `notes` doubles as a catch-all for things that
  do not fit other fields (v1 has no dedicated secure-note type).
- `tags` — array of strings, may be empty. Used for filtering.
- `favorite` — boolean, for pinning to the top of the list.
- `needsSiteUpdate` — boolean. The user ticks this to mark "I changed this password in
  Coffer but still need to change it on the actual website." A filter surfaces all flagged
  entries. Prevents the vault-vs-reality lockout footgun. Purely a manual reminder — no
  automation.
- `generatorPreset` — optional saved generation rules for this entry (length, character
  classes, whether symbols are allowed), so regenerating a password for a site that
  rejects symbols or caps length "just works." `null` means use the global generator
  defaults.
- **Password age** is not a stored field — it is *derived* from `modifiedAt` (and
  `passwordHistory` timestamps). The Health view uses it to flag stale passwords.
- `passwordHistory` — array of `{ password, changedAt }`. **The field exists in the v1
  schema**, so adding the feature in v1.5 needs no format migration. When a password is
  changed, the old value is pushed here. Cap at the most recent **10** entries. v1 may
  leave this array empty; v1.5 begins populating it. The v2 LAN-sync merge also writes
  here — when two devices edited the same entry, the losing version's password lands in
  history so nothing is silently lost.
- `createdAt` / `modifiedAt` — ISO 8601 timestamps. `modifiedAt` updates on every edit
  and is the tiebreaker for LAN-sync's newer-wins merge.
- `deletedAt` — **tombstone field.** See below.

### Soft deletes (tombstones) — design this in from day one

Deleting an entry sets `deletedAt` to a timestamp instead of removing the object.

- The UI hides entries where `deletedAt` is non-null. A "Recently deleted" view shows them
  and offers restore or permanent purge.
- **Why now, in v1, even though there is no sync yet:** when v2 LAN sync arrives, a hard
  delete is invisible to other devices and the entry resurrects on the next merge.
  Tombstones make deletion a *change that can propagate*. Adding them later would force a
  format migration; adding them now costs nothing.
- "Purge" permanently removes a tombstoned entry from the array.

## File-size padding

Before encryption, the serialized entries document is **padded** up to the next fixed
bucket boundary (e.g. the next multiple of 16 KB) with meaningless filler bytes. The
plaintext records its own real length (a length prefix) so the padding can be stripped
after decryption.

Why: a locked vault file's *size* is not encrypted, and an un-padded file's size roughly
reveals *how many* entries it holds. Padding makes a 12-entry and a 300-entry vault
produce the same file size, closing that metadata leak. The leak is minor (a count, not
contents) and outside the core threat model — but padding is baked into v1 purely because
the file format is far cheaper to get right before any real vaults exist than to migrate
later. Cost is small: a slightly larger file and one length field.

## Backups

The storage adapter keeps **rotating encrypted backups** beside the vault file. Before
every save:

1. Copy the current `vault.coffer` to a rotating slot, e.g. `vault.coffer.bak.1`.
2. Shift older backups down (`bak.1` -> `bak.2`, ...), keeping the most recent **5**.
3. Then write the new vault file.

Backups are byte copies of the encrypted file, so they are inherently encrypted — no extra
crypto needed. This protects against a corrupted write or a bad edit, not against a lost
master password.

## Format migrations — a first-class safety concern

The vault file format will evolve (v2 adds a card entry type, etc.). A migration
transforms an old-format vault to the new format. A buggy migration that overwrites a good
vault with a corrupt one is catastrophic — the vault *is* the product. "Start fresh" (a
new version that cannot read old vaults) is NOT acceptable: it would destroy user data.

Migrations must follow these rules:

1. **Back up before migrating.** Before transforming, copy the vault to a clearly named
   file (e.g. `vault.coffer.pre-v2-backup`). If anything fails, the original is untouched.
2. **Migrate a copy, verify, then swap.** Never transform the file in place. Build the
   new-format version in memory or a temp file, then **open and verify it decrypts and
   parses correctly**, and only then replace the original. If verification fails, abort
   and keep the old file.
3. **Version every format; migrate one step at a time.** A v1->v3 upgrade runs v1->v2 then
   v2->v3 — each step small, simple, individually tested.
4. **Test migrations against real old files.** Keep sample vaults from every past format
   version in the test suite; every build must prove it can still open and upgrade them.

Never open a file of an unknown (future) version — refuse rather than guess. Never write a
file in an old version. Migrations live in `packages/core/src/vault`.
