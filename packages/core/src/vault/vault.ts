// packages/core/src/vault/vault.ts
//
// DC-8 VERB-FIRST PUBLIC API — the top-level functions Phase 3 (entry CRUD + storage
// adapter) and Phase 4 (UI) call. State lives in the CALLER (apps/desktop's VaultSession
// singleton), never here: UnlockedVault is a PLAIN DATA interface with no methods and does
// NOT hold the vault key. The vault key is returned alongside the UnlockedVault and the
// caller is responsible for mounting + memzeroing it (SEC-09).
//
// THE DATA FLOW (RESEARCH System Architecture Diagram):
//   createVault: calibrateArgon2id → random 32-byte vault_key → deriveKey(masterPassword)
//                → wrapKey(vault_key, masterDK) → wrappedKeys.master. Optional recovery:
//                generateRecoveryKey → wrapKey(vault_key, recovery.wrapKey) →
//                wrappedKeys.recovery. encryptInner(empty entries) → data blob.
//   unlockVault: parseOuter → (masterPassword) deriveKey + tryUnwrap(master) | (recoveryKey)
//                decodeRecoveryKey + toRecoveryWrapKey + tryUnwrap(recovery) → vault_key →
//                decryptInner(data) → entries. Wrong secret → typed error (DC-9), never
//                partial data (SEC-08).
//   saveVault:   encryptInner(current entries, vault_key) with a FRESH nonce → serializeOuter.
//   changeMasterPassword: verify currentPassword unwraps master → re-wrapKey under the NEW
//                derived key → replace wrappedKeys.master. The `data` blob is UNTOUCHED —
//                that is the envelope-encryption benefit (VAULT-02): a password change
//                re-wraps one 32-byte key, never re-encrypts the entries.
//
// DC-5 GENERIC tryUnwrap: there is NO unlockWithMaster()/unlockWithRecovery() split here —
//   both paths derive a 32-byte key and hand it to the single tryUnwrap primitive.
// DC-10 OPEN-UNION SECRET: unlockVault's `secret` is `{ masterPassword } | { recoveryKey }`;
//   v2.5 adds `| { mobileWrapKey }` etc. with no signature break.
// DC-4 OPEN wrappedKeys MAP: addWrappedKey/removeWrappedKey manage labeled wraps for the
//   v2.5 forward-compat path (mobile / biometric); removing `master` is REFUSED (bricking).
//
// AUTH-06: the raw recovery bytes are NEVER persisted — generateRecoveryKey's wrapKey is
//   used to produce wrappedKeys.recovery and the encoded string is returned to the caller
//   (shown once in the UI); nothing recovery-raw is written into the vault document.
//
// Source: CONTEXT DC-4/DC-5/DC-8/DC-9/DC-10, RESEARCH Architecture Patterns, the Phase-1
//   VaultSession contract, and the 02-01/02-02/02-03 primitives this ties together.

import { getSodium } from '../crypto/sodium';
import { calibrateArgon2id, deriveKey } from '../crypto/kdf';
import type { KdfParams } from '../crypto/kdf';
import { wrapKey, tryUnwrap } from '../crypto/wrap';
import { generateRecoveryKey, decodeRecoveryKey, toRecoveryWrapKey } from '../crypto/recovery';
import { parseOuter, serializeOuter, encryptInner, decryptInner } from './serialize';
import type { VaultDocumentV1, WrappedKeyV1 } from './format';
import { CURRENT_FORMAT_VERSION, FORMAT_IDENTIFIER } from './format';
import {
  WrongPasswordError,
  WrongRecoveryKeyError,
  VaultKeyMismatchError,
  ProtectedWrapError,
  VaultCorruptError,
} from '../errors';
import type { InnerDoc } from '../entries/types';
import { DEFAULT_RANDOM_OPTIONS } from '../generator/types';

/**
 * DC-8 plain-data UnlockedVault: the parsed on-disk document plus the DECRYPTED entries.
 * NO methods, and crucially NO vault key — the key is returned separately by createVault /
 * unlockVault and the caller (VaultSession) owns its lifecycle + memzero (SEC-09).
 *
 * `entries` is the decrypted entries object (the entries SCHEMA itself is Phase 3's
 * concern; Phase 2 treats it as an opaque JSON object that round-trips losslessly).
 */
export interface UnlockedVault {
  /** The parsed outer vault document (wrappedKeys, data blob, meta). */
  doc: VaultDocumentV1;
  /** The decrypted entries object. Opaque to Phase 2; shaped by Phase 3. */
  entries: object;
}

/** The DC-2 creation report (data shape only — the Phase-4 UI renders it). */
export interface CreationReport {
  memLimit: number;
  opsLimit: number;
  measuredMs: number;
  /** true when calibration landed > 512 MiB → Phase-4 portability disclosure (DC-2). */
  portabilityWarning: boolean;
}

/**
 * P3-01 versioned inner document written by createVault.
 * `schemaVersion: 1` is SEPARATE from the outer file-format `version` (= 1).
 * `settings.generator` seeds the vault-level defaults (GEN-04).
 */
const EMPTY_ENTRIES: InnerDoc = {
  schemaVersion: 1,
  entries: [],
  settings: {
    generator: DEFAULT_RANDOM_OPTIONS,
  },
};

/**
 * Securely wipe a key buffer (SEC-09). Exposed so the desktop VaultSession can zero its
 * #vaultKey on lock() WITHOUT importing raw libsodium (which the ESLint no-restricted-imports
 * ban forbids outside crypto/sodium.ts). The desktop layer imports this from @cryptiq/core.
 */
export async function secureWipe(buffer: Uint8Array | null | undefined): Promise<void> {
  if (!buffer || buffer.length === 0) return;
  const sodium = await getSodium();
  sodium.memzero(buffer);
}

/**
 * Create a brand-new vault. Calibrates Argon2id for the master wrap (unless `kdfParams` is
 * supplied — a TEST seam to skip the ~1s calibration ladder), generates a random 32-byte
 * vault key, wraps it under the master password and (optionally) a fresh recovery key, and
 * seals an empty entries blob.
 *
 * @returns `{ vault, vaultKey, recoveryKey?, creationReport }`. The caller mounts `vaultKey`
 *   into its session; `recoveryKey` (if requested) is the 54-char string to show ONCE in the
 *   UI — it is NOT persisted anywhere (AUTH-06).
 */
export async function createVault(opts: {
  masterPassword: Uint8Array;
  withRecoveryKey: boolean;
  /** TEST seam: supply fixed kdf params to skip calibration. Production omits this. */
  kdfParams?: KdfParams;
  deviceLabel?: string;
}): Promise<{
  vault: UnlockedVault;
  vaultKey: Uint8Array;
  recoveryKey?: string;
  creationReport: CreationReport;
}> {
  const sodium = await getSodium();

  // 1. Master wrap params: calibrate (production) or use the supplied test params.
  let masterParams: KdfParams;
  let creationReport: CreationReport;
  if (opts.kdfParams) {
    masterParams = opts.kdfParams;
    creationReport = {
      memLimit: masterParams.memLimit,
      opsLimit: masterParams.opsLimit,
      measuredMs: 0,
      portabilityWarning: masterParams.memLimit > 512 * 1024 * 1024,
    };
  } else {
    const calib = await calibrateArgon2id();
    masterParams = calib.params;
    creationReport = {
      memLimit: calib.params.memLimit,
      opsLimit: calib.params.opsLimit,
      measuredMs: calib.measuredMs,
      portabilityWarning: calib.portabilityWarning,
    };
  }

  // 2. Random 32-byte vault key — the only thing that actually decrypts entries.
  const vaultKey = sodium.randombytes_buf(32);

  // 3. Master wrap (always present). WR-02: wipe the transient derived key on every exit
  //    (try/finally) so a throw inside wrapKey (e.g. OOM) never leaves masterDK in memory.
  const masterDK = await deriveKey(opts.masterPassword, masterParams);
  let master: WrappedKeyV1;
  try {
    master = await wrapKey(vaultKey, masterDK, masterParams);
  } finally {
    await secureWipe(masterDK);
  }

  const wrappedKeys: VaultDocumentV1['wrappedKeys'] = { master };

  // 4. Optional recovery wrap. The recovery wrap-key is BLAKE2b-derived (no Argon2id), so
  //    its stored kdf params are the recovery domain marker (opsLimit/memLimit 0): they are
  //    NOT used to re-derive on unlock — decodeRecoveryKey + toRecoveryWrapKey reproduce the
  //    wrap-key from the typed recovery string alone. Storing zeros documents "not Argon2id".
  let recoveryKey: string | undefined;
  if (opts.withRecoveryKey) {
    const rec = await generateRecoveryKey();
    const recoveryParams: KdfParams = {
      algorithm: 2,
      opsLimit: 0,
      memLimit: 0,
      salt: new Uint8Array(0),
    };
    // WR-02: wipe the recovery wrap-key + raw recovery bytes on EVERY exit. If wrapKey throws
    // mid-wrap, the recovery secret material must still be zeroed (SEC-09 / AUTH-06).
    try {
      wrappedKeys.recovery = await wrapKey(vaultKey, rec.wrapKey, recoveryParams);
      recoveryKey = rec.encoded; // shown once; never persisted (AUTH-06)
    } finally {
      await secureWipe(rec.wrapKey);
      await secureWipe(rec.rawBytes);
    }
  }

  // 5. Seal an empty entries blob and assemble the document.
  const data = await encryptInner(
    new TextEncoder().encode(JSON.stringify(EMPTY_ENTRIES)),
    vaultKey,
  );
  const now = new Date().toISOString();
  const doc: VaultDocumentV1 = {
    format: FORMAT_IDENTIFIER,
    version: CURRENT_FORMAT_VERSION,
    wrappedKeys,
    data,
    meta: {
      createdAt: now,
      modifiedAt: now,
      ...(opts.deviceLabel !== undefined ? { deviceLabel: opts.deviceLabel } : {}),
    },
  };

  const result: {
    vault: UnlockedVault;
    vaultKey: Uint8Array;
    recoveryKey?: string;
    creationReport: CreationReport;
  } = {
    // Deep clone: a shallow `{ ...EMPTY_ENTRIES }` would share the inner `entries`
    // array (and `settings`) with the module-level constant, so every vault created
    // in one process would mutate the SAME array via addEntry — leaking entries across
    // vaults. structuredClone gives each vault a fully independent InnerDoc.
    vault: { doc, entries: structuredClone(EMPTY_ENTRIES) },
    vaultKey,
    creationReport,
  };
  if (recoveryKey !== undefined) result.recoveryKey = recoveryKey;
  return result;
}

/** DC-10 open-union unlock secret. */
export type UnlockSecret = { masterPassword: Uint8Array } | { recoveryKey: string };

/**
 * Unlock a vault from its serialized bytes using either a master password or a recovery key
 * (DC-10). Uses the single generic tryUnwrap (DC-5). Returns the UnlockedVault plus the
 * recovered 32-byte vault key (the caller mounts it). FAIL CLOSED:
 *   - wrong master password → WrongPasswordError
 *   - malformed / wrong recovery key → WrongRecoveryKeyError
 *   - tampered data blob → VaultCorruptError (from decryptInner)
 * Never returns partial data (SEC-08).
 */
export async function unlockVault(
  bytes: Uint8Array,
  secret: UnlockSecret,
): Promise<{ vault: UnlockedVault; vaultKey: Uint8Array }> {
  const doc = parseOuter(bytes);

  let vaultKey: Uint8Array | null;
  if ('masterPassword' in secret) {
    const master = doc.wrappedKeys.master;
    const params = await wrappedKdfParams(master);
    // WR-02: wipe the transient derived key on every exit (try/finally).
    const dk = await deriveKey(secret.masterPassword, params);
    try {
      vaultKey = await tryUnwrap(master, dk);
    } finally {
      await secureWipe(dk);
    }
    if (vaultKey === null) {
      throw new WrongPasswordError('Master password did not unlock the vault.');
    }
  } else {
    const recovery = doc.wrappedKeys.recovery;
    if (recovery === undefined) {
      throw new WrongRecoveryKeyError('This vault has no recovery key configured.');
    }
    // decodeRecoveryKey throws WrongRecoveryKeyError on bad check char / version.
    const rawBytes = await decodeRecoveryKey(secret.recoveryKey);
    // WR-02: wipe the derived recovery wrap-key + raw recovery bytes on every exit.
    const wrapKeyBytes = await toRecoveryWrapKey(rawBytes);
    try {
      vaultKey = await tryUnwrap(recovery, wrapKeyBytes);
    } finally {
      await secureWipe(wrapKeyBytes);
      await secureWipe(rawBytes);
    }
    if (vaultKey === null) {
      throw new WrongRecoveryKeyError('Recovery key did not unlock the vault.');
    }
  }

  // Decrypt the entries blob under the recovered vault key (fail-closed in decryptInner).
  const entriesBytes = await decryptInner(doc.data, vaultKey);
  // IN-05: the AEAD tag guarantees authenticity, so malformed inner JSON should be impossible
  // in normal operation — but a buggy/self-signed-corrupt inner must still surface a TYPED
  // VaultCorruptError (fail closed), never a raw SyntaxError.
  let entries: object;
  try {
    entries = JSON.parse(new TextDecoder().decode(entriesBytes)) as object;
  } catch (e) {
    throw new VaultCorruptError(
      `Decrypted vault entries are not valid JSON: ${(e as Error).message}`,
    );
  }

  return { vault: { doc, entries }, vaultKey };
}

/**
 * Re-encrypt the current in-memory entries under the vault key (fresh nonce, SEC-04), update
 * `meta.modifiedAt`, and serialize to bytes. Does NOT touch the wrapped keys.
 */
export async function saveVault(vault: UnlockedVault, vaultKey: Uint8Array): Promise<Uint8Array> {
  const entriesBytes = new TextEncoder().encode(JSON.stringify(vault.entries));
  const data = await encryptInner(entriesBytes, vaultKey);
  vault.doc.data = data;
  vault.doc.meta.modifiedAt = new Date().toISOString();
  return serializeOuter(vault.doc);
}

/**
 * Re-seal a merged InnerDoc under an existing vault key, preserving the partner's
 * wrappedKeys, salt, KDF params, version, and format discriminator (D-03, KAT-1..4
 * wire-format LOCKED boundary). Only `data` and `meta.modifiedAt` change.
 *
 * Used twice by Plan 04 (Phase 11): once for A's re-sealed blob and once for B's.
 * The input `mergedInner` is taken as-is (object spread only — `partnerDoc` is NOT
 * mutated). Returns the serialized `VaultDocumentV1` bytes.
 *
 * SAFE-04: this verb OWNS the lifecycle of the plaintext byte buffer it allocates —
 * it zeroes the encoded `mergedInner` JSON bytes in a `finally` immediately after AEAD
 * sealing, so the encrypted plaintext never lingers in a buffer the caller cannot reach
 * (Pitfall 3). The caller still owns the `mergedInner` OBJECT (and any JSON string it
 * created elsewhere) — those are JS-managed and unwipeable, an accepted residual
 * consistent with the rest of the vault path (saveVault, unlockVault).
 *
 * Propagates typed errors from encryptInner (e.g. VaultCorruptError) to the caller.
 */
export async function resealInnerDoc(
  mergedInner: InnerDoc,
  vaultKey: Uint8Array,
  partnerDoc: VaultDocumentV1,
): Promise<Uint8Array> {
  const entriesBytes = new TextEncoder().encode(JSON.stringify(mergedInner));
  try {
    const data = await encryptInner(entriesBytes, vaultKey);
    const newDoc: VaultDocumentV1 = {
      ...partnerDoc,
      data,
      meta: { ...partnerDoc.meta, modifiedAt: new Date().toISOString() },
    };
    return serializeOuter(newDoc);
  } finally {
    // SAFE-04: zero the plaintext JSON bytes the moment sealing is done — this verb is
    // the only code with a reference to this buffer.
    await secureWipe(entriesBytes);
  }
}

/**
 * Change the master password (VAULT-02 envelope benefit): verify `currentPassword` unwraps
 * the master wrap, then re-wrap the SAME vault key under a key derived from `newPassword`.
 * The `data` blob (entries ciphertext) is NEVER re-encrypted. Mutates `vault.doc` in place
 * and returns it.
 *
 * @throws WrongPasswordError if `currentPassword` does not unwrap the master wrap.
 */
export async function changeMasterPassword(
  vault: UnlockedVault,
  vaultKey: Uint8Array,
  opts: {
    currentPassword: Uint8Array;
    newPassword: Uint8Array;
    /** TEST seam: supply fixed kdf params to skip calibration. Production omits this. */
    kdfParams?: KdfParams;
  },
): Promise<VaultDocumentV1> {
  const sodium = await getSodium();

  // 1. Verify the current password actually unwraps the master wrap (re-derive + tryUnwrap).
  //    WR-02: wipe the transient derived key on EVERY exit (try/finally), not just the happy
  //    path — if tryUnwrap throws (e.g. OOM mid-open) the key must still be zeroed.
  const currentMaster = vault.doc.wrappedKeys.master;
  const currentParams = await wrappedKdfParams(currentMaster);
  const currentDK = await deriveKey(opts.currentPassword, currentParams);
  let unwrapped: Uint8Array | null;
  try {
    unwrapped = await tryUnwrap(currentMaster, currentDK);
  } finally {
    await secureWipe(currentDK);
  }
  if (unwrapped === null) {
    throw new WrongPasswordError('Current master password is incorrect.');
  }

  // CR-02 — SANITY: the unwrapped key MUST equal the live vault key. A session desync (a
  // caller passing a vaultKey that the current master wrap does not actually protect) would
  // otherwise re-wrap the WRONG key under the new password, permanently bricking the
  // (untouched) data blob. Use libsodium's CONSTANT-TIME memcmp on the secret key material —
  // never `===` / a byte-loop with early exit. memcmp throws on a length mismatch, so guard
  // length first; it returns a boolean (true === equal). Wipe `unwrapped` on every exit.
  let matches: boolean;
  try {
    matches = unwrapped.length === vaultKey.length && sodium.memcmp(unwrapped, vaultKey);
  } finally {
    await secureWipe(unwrapped);
  }
  if (!matches) {
    // Fail closed. The doc is NOT mutated — the master wrap + data blob are left intact.
    // No key bytes in the message (SEC-09).
    throw new VaultKeyMismatchError(
      'changeMasterPassword: the supplied vault key does not match the key protected by the current master wrap (session desync) — refusing to re-wrap.',
    );
  }

  // 2. New master wrap params: calibrate (production) or use the supplied test params.
  const newParams = opts.kdfParams ?? (await calibrateArgon2id()).params;

  // 3. Re-wrap the vault key under the NEW derived key. Entries blob untouched (VAULT-02).
  //    WR-02: wrap inside try/finally so newDK is wiped even if wrapKey throws.
  const newDK = await deriveKey(opts.newPassword, newParams);
  try {
    vault.doc.wrappedKeys.master = await wrapKey(vaultKey, newDK, newParams);
  } finally {
    await secureWipe(newDK);
  }

  vault.doc.meta.modifiedAt = new Date().toISOString();
  return vault.doc;
}

/**
 * DC-4 forward-compat: add a labeled wrapped key (e.g. v2.5 `mobile`, v1.5
 * `biometric_<device-id>`) that wraps the SAME vault key under a different derivation key.
 * The caller supplies an already-derived 32-byte key and the params that produced it.
 */
export async function addWrappedKey(
  vault: UnlockedVault,
  vaultKey: Uint8Array,
  opts: { label: string; derivationKey: Uint8Array; kdfParams: KdfParams },
): Promise<void> {
  if (opts.label === 'master') {
    throw new ProtectedWrapError(
      'addWrappedKey: refuse to overwrite the master wrap via addWrappedKey.',
    );
  }
  vault.doc.wrappedKeys[opts.label] = await wrapKey(vaultKey, opts.derivationKey, opts.kdfParams);
  vault.doc.meta.modifiedAt = new Date().toISOString();
}

/**
 * DC-4 forward-compat: remove a labeled wrapped key. REFUSES to remove `master` (that would
 * brick the vault — the master wrap is the always-present unlock path).
 */
export function removeWrappedKey(vault: UnlockedVault, label: string): void {
  if (label === 'master') {
    throw new ProtectedWrapError(
      'removeWrappedKey: the master wrap cannot be removed (would brick the vault).',
    );
  }
  delete vault.doc.wrappedKeys[label];
  vault.doc.meta.modifiedAt = new Date().toISOString();
}

/**
 * Reconstruct the runtime KdfParams from a stored WrappedKeyV1's per-wrap `kdf` (DC-3).
 * Decodes the base64 salt back to bytes via libsodium (decision 27: ORIGINAL variant — the
 * SAME explicit variant wrapKey() used to encode it; never the libsodium default).
 */
async function wrappedKdfParams(wrapped: WrappedKeyV1): Promise<KdfParams> {
  const sodium = await getSodium();
  return {
    algorithm: 2,
    opsLimit: wrapped.kdf.opsLimit,
    memLimit: wrapped.kdf.memLimit,
    salt: sodium.from_base64(wrapped.kdf.salt, sodium.base64_variants.ORIGINAL),
  };
}
