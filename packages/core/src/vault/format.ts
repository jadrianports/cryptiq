// packages/core/src/vault/format.ts
//
// THE ON-DISK VAULT FILE CONTRACT (VAULT-01, VAULT-02). Types only — no imports of
// sodium/Tauri/fs, no runtime functions. The parse/serialize/encrypt logic lives in
// serialize.ts; this file declares the JSON shape and the format constants.
//
// DC-3 — PER-WRAP KDF, NO TOP-LEVEL kdf (Pitfall B): the Argon2id `{opsLimit, memLimit,
//   salt, algorithm}` live INSIDE each `wrappedKeys[label]` object. There is NO
//   top-level `kdf` field anywhere in VaultDocumentV1. The cryptiq-plans design doc
//   (03-vault-file-format.md) shows a top-level kdf; DC-3 deliberately supersedes it so
//   a future mobile wrap can carry weaker (mobile-safe) params alongside the desktop
//   wrap, both unwrapping the same vault_key. If tempted to hoist `kdf` up — DON'T.
//
// DC-4 — OPEN wrappedKeys MAP: `wrappedKeys` is keyed by label. v1 writes `master`
//   (always) and an optional `recovery`. The parser TOLERATES unknown labels (a future
//   `mobile` / `biometric_<id>`) and never errors on them; it refuses to open ONLY on an
//   unknown vault `version` (VAULT-07). The `[label: string]` index signature encodes
//   this openness in the type.
//
// WrappedKeyV1 is the same shape as crypto/wrap.ts's `WrappedKey` (the runtime that
// produces it). It is re-exported here under the V1 name as the canonical on-disk type
// so the format module and the crypto module never drift apart (single source of shape).
//
// Source: RESEARCH Pattern 7 (VaultDocumentV1 + WrappedKeyV1 + DC-3/DC-4 deviations),
// CONTEXT DC-3/DC-4, VAULT-02 schema, PITFALLS Pitfall B.

import type { WrappedKey } from '../crypto/wrap';

/**
 * On-disk wrapped-key object. Identical to crypto/wrap.ts's runtime `WrappedKey`
 * (DC-3: per-wrap `kdf` nested inside; base64 nonce + ciphertext). Re-aliased here so
 * format.ts is the canonical on-disk type without redeclaring (and risking drift from)
 * the shape `wrapKey()` actually emits.
 */
export type WrappedKeyV1 = WrappedKey;

/**
 * The Cryptiq v1 vault document — the exact UTF-8 JSON written to the `.cryptiq` file.
 * All byte fields are base64 (standard/ORIGINAL variant, decision 27).
 */
export interface VaultDocumentV1 {
  /** Format discriminator. Foreign files (wrong/missing value) are refused at parse. */
  format: 'cryptiq-vault';
  /** File-format version. Bound into AEAD AD on the data blob (SEC-06) and refused at
   *  parse if unknown (VAULT-07). v1 is the only accepted value in this build. */
  version: 1;
  /**
   * DC-4 open map of wrapped vault_keys keyed by label. v1 writes `master` (always) and
   * an optional `recovery`. Unknown labels are tolerated by the parser, never errored.
   * Each value carries its own DC-3 per-wrap kdf params (NO top-level kdf).
   */
  wrappedKeys: {
    master: WrappedKeyV1;
    recovery?: WrappedKeyV1;
    [label: string]: WrappedKeyV1 | undefined;
  };
  /** The encrypted + tiered-padded entries blob (base64). Sealed under VAULT_AD. */
  data: {
    /** base64, 24-byte XChaCha20-Poly1305 nonce. */
    nonce: string;
    /** base64, combined-mode ciphertext of the padded entries JSON. */
    ciphertext: string;
  };
  /** Non-secret metadata. Never contains key material. */
  meta: {
    /** ISO 8601 timestamp of vault creation. */
    createdAt: string;
    /** ISO 8601 timestamp of the last save. */
    modifiedAt: string;
    /** Optional, non-secret human label for the writing device. */
    deviceLabel?: string;
  };
}

/** The only vault format version this build understands. Newer → UnknownVaultVersionError. */
export const CURRENT_FORMAT_VERSION = 1;

/** The `format` discriminator string. Foreign files fail the format check (T-02-11). */
export const FORMAT_IDENTIFIER = 'cryptiq-vault';
