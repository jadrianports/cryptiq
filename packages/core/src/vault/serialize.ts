// packages/core/src/vault/serialize.ts
//
// The vault file (de)serialization layer (VAULT-01, VAULT-02, VAULT-03, VAULT-07, SEC-06).
// Follows config.ts's parse/serialize split: parseOuter(bytes) throws a typed error on
// invalid input; serializeOuter(doc) returns UTF-8 JSON bytes. encryptInner/decryptInner
// coordinate the padding (padding.ts) and AEAD (aead.ts) primitives for the data blob.
//
// OUTER (parseOuter / serializeOuter) — pure sync, no sodium:
//   parseOuter   : UTF-8 JSON → validate format + version → VaultDocumentV1.
//                  Bad JSON / non-object / wrong `format` → VaultCorruptError (T-02-11).
//                  Unknown `version` → UnknownVaultVersionError (VAULT-07, T-02-10) —
//                  refuse to open, never guess. DC-4: unknown wrappedKeys LABELS are
//                  TOLERATED (no error) — only the version gates open/refuse.
//   serializeOuter: VaultDocumentV1 → JSON.stringify (2-space) → UTF-8 bytes.
//
// INNER (encryptInner / decryptInner) — async, uses sodium:
//   encryptInner : padToTieredBucket (DC-6 entry-count hiding) → sealData under VAULT_AD
//                  (SEC-06 version binding) → base64 {nonce, ciphertext}.
//   decryptInner : base64 → openData under VAULT_AD (fail-closed) → unpad → exact bytes.
//
// BASE64 (decision 27 / Pitfall D): every to_base64/from_base64 passes an EXPLICIT
//   sodium.base64_variants.ORIGINAL (standard alphabet WITH padding). NEVER rely on
//   libsodium's default (URLSAFE_NO_PADDING). This matches wrap.ts and the wire-format
//   decision locked at Checkpoint 2 before this wave persists the format.
//
// Source: RESEARCH Pattern 7 (schema) + Pattern 8 (AD), PATTERNS config.ts parse/serialize
//   analog, CONTEXT DC-4 (tolerate unknown labels; refuse only unknown version), decision 27.

import { getSodium } from '../crypto/sodium';
import { sealData, openData, VAULT_AD } from '../crypto/aead';
import { padToTieredBucket, unpad } from '../crypto/padding';
import { VaultCorruptError, UnknownVaultVersionError } from '../errors';
import type { VaultDocumentV1 } from './format';
import { CURRENT_FORMAT_VERSION, FORMAT_IDENTIFIER } from './format';

/**
 * Parse vault file bytes (UTF-8 JSON) into a VaultDocumentV1.
 *
 * Throws:
 *  - VaultCorruptError on invalid JSON, a non-object root, a missing/wrong `format`
 *    discriminator (foreign file — T-02-11), or a missing `wrappedKeys.master`.
 *  - UnknownVaultVersionError on any `version` other than CURRENT_FORMAT_VERSION
 *    (VAULT-07 — refuse to open a future/unknown version, never guess).
 *
 * DC-4: unknown wrappedKeys LABELS are tolerated (never an error) — only the `version`
 * decides open vs. refuse. Migration of old known versions is handled upstream by
 * loadAndMigrate (Wave 4); parseOuter itself only accepts the current version.
 */
export function parseOuter(bytes: Uint8Array): VaultDocumentV1 {
  const text = new TextDecoder('utf-8').decode(bytes);
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (e) {
    throw new VaultCorruptError(`Vault file is not valid JSON: ${(e as Error).message}`);
  }
  if (raw === null || typeof raw !== 'object') {
    throw new VaultCorruptError('Vault file must be a JSON object.');
  }
  const obj = raw as Record<string, unknown>;

  // Format discriminator FIRST (T-02-11 format confusion — a foreign file is corrupt,
  // not an unknown version).
  if (obj.format !== FORMAT_IDENTIFIER) {
    throw new VaultCorruptError(
      `Vault file is not a Cryptiq vault (format=${JSON.stringify(obj.format)}).`,
    );
  }

  // Version gate (VAULT-07 / T-02-10) — refuse unknown versions, never guess.
  if (obj.version !== CURRENT_FORMAT_VERSION) {
    throw new UnknownVaultVersionError(
      `Vault version ${String(obj.version)} is not supported by this build (expected ${CURRENT_FORMAT_VERSION}).`,
    );
  }

  // Structural sanity: master wrap + data blob + meta must be present and object-shaped.
  // DC-4: do NOT inspect or reject unknown wrappedKeys labels.
  const wrappedKeys = obj.wrappedKeys;
  if (wrappedKeys === null || typeof wrappedKeys !== 'object') {
    throw new VaultCorruptError('Vault file: wrappedKeys must be an object.');
  }
  if (
    (wrappedKeys as Record<string, unknown>).master === undefined ||
    typeof (wrappedKeys as Record<string, unknown>).master !== 'object'
  ) {
    throw new VaultCorruptError('Vault file: wrappedKeys.master is required.');
  }

  const data = obj.data;
  if (
    data === null ||
    typeof data !== 'object' ||
    typeof (data as Record<string, unknown>).nonce !== 'string' ||
    typeof (data as Record<string, unknown>).ciphertext !== 'string'
  ) {
    throw new VaultCorruptError('Vault file: data must have base64 nonce + ciphertext.');
  }

  // WR-05: validate the meta SHAPE, not just "is an object". createdAt + modifiedAt MUST be
  // present and string-typed (the VaultDocumentV1 type guarantees `string`); deviceLabel, if
  // present, MUST be a string. A file with meta:{} or a numeric createdAt would otherwise
  // parse "successfully" and the cast would lie about the string guarantee. Fail closed.
  const meta = obj.meta;
  if (meta === null || typeof meta !== 'object') {
    throw new VaultCorruptError('Vault file: meta must be an object.');
  }
  const m = meta as Record<string, unknown>;
  if (typeof m.createdAt !== 'string' || typeof m.modifiedAt !== 'string') {
    throw new VaultCorruptError(
      'Vault file: meta.createdAt and meta.modifiedAt must both be ISO 8601 strings.',
    );
  }
  if (m.deviceLabel !== undefined && typeof m.deviceLabel !== 'string') {
    throw new VaultCorruptError('Vault file: meta.deviceLabel must be a string when present.');
  }

  // Validated shape — cast through the checked structure.
  return obj as unknown as VaultDocumentV1;
}

/** Serialize a VaultDocumentV1 to UTF-8 JSON bytes (2-space indent, trailing newline). */
export function serializeOuter(doc: VaultDocumentV1): Uint8Array {
  const text = JSON.stringify(doc, null, 2) + '\n';
  return new TextEncoder().encode(text);
}

/**
 * Encrypt the entries JSON into the vault `data` blob: pad to a DC-6 tier bucket
 * (entry-count hiding), then seal under VAULT_AD (binds the file-format version, SEC-06)
 * with a fresh nonce. Returns base64 {nonce, ciphertext} (ORIGINAL variant, decision 27).
 */
export async function encryptInner(
  entriesJsonBytes: Uint8Array,
  vaultKey: Uint8Array,
): Promise<{ nonce: string; ciphertext: string }> {
  const sodium = await getSodium();
  const padded = padToTieredBucket(entriesJsonBytes);
  const { ciphertext, nonce } = await sealData(padded, vaultKey, VAULT_AD);
  return {
    nonce: sodium.to_base64(nonce, sodium.base64_variants.ORIGINAL),
    ciphertext: sodium.to_base64(ciphertext, sodium.base64_variants.ORIGINAL),
  };
}

/**
 * Decrypt the vault `data` blob back to the exact entries JSON: base64-decode, open
 * under VAULT_AD (fail-closed — any auth/tamper/version mismatch throws VaultCorruptError),
 * then strip the DC-6 padding via the uint32 LE prefix.
 */
export async function decryptInner(
  data: { nonce: string; ciphertext: string },
  vaultKey: Uint8Array,
): Promise<Uint8Array> {
  const sodium = await getSodium();
  const nonce = sodium.from_base64(data.nonce, sodium.base64_variants.ORIGINAL);
  const ciphertext = sodium.from_base64(data.ciphertext, sodium.base64_variants.ORIGINAL);
  const padded = await openData(ciphertext, nonce, vaultKey, VAULT_AD);
  return unpad(padded);
}
