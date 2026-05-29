// scripts/demo/02-2-envelope.mjs
//
// Checkpoint 2 demo (DC-12): exercise envelope encryption end-to-end against
// packages/core's TypeScript source and print real bytes the user can eyeball.
//
//   1. Derive a 32-byte derivation key from a master password with Argon2id at the
//      Cryptiq floor params (256 MiB / 3 ops) — fast enough for a demo, real KDF.
//   2. Generate a random 32-byte vault_key and wrapKey() it under the derivation key.
//   3. tryUnwrap() with the RIGHT key  -> byte-equal vault_key recovered.
//      tryUnwrap() with a WRONG key    -> null (DC-5 normal branch, not a throw).
//   4. sealData() a small plaintext under the vault_key and openData() it back.
//
// Demo scripts live outside packages/core, so console.log is allowed here (no SEC-10 ban).
//
// Run (preferred): pnpm demo:02-2
// Or directly:
//   node --experimental-transform-types --import ./scripts/demo/_loader.mjs scripts/demo/02-2-envelope.mjs

import {
  getSodium,
  deriveKey,
  wrapKey,
  tryUnwrap,
  sealData,
  openData,
} from '@cryptiq/core/internal';

const FLOOR_MEM = 268_435_456; // 256 MiB
const FLOOR_OPS = 3;

const sodium = await getSodium();

console.log('Cryptiq — Envelope encryption (Checkpoint 2)');
console.log('--------------------------------------------');

// 1. Derive a derivation key from a master password (Argon2id, floor params).
const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
const kdfParams = { algorithm: 2, opsLimit: FLOOR_OPS, memLimit: FLOOR_MEM, salt };
const masterPassword = new TextEncoder().encode('correct horse battery staple');
const derivationKey = await deriveKey(masterPassword, kdfParams);
console.log(`  derivation key    : ${derivationKey.length} bytes (Argon2id, 256 MiB / 3 ops)`);

// 2. Random vault key + wrap.
const vaultKey = sodium.randombytes_buf(32);
const wrapped = await wrapKey(vaultKey, derivationKey, kdfParams);
console.log('');
console.log('  WrappedKey JSON shape (DC-3 per-wrap kdf — NO top-level kdf):');
console.log(
  JSON.stringify(
    {
      nonce: wrapped.nonce.slice(0, 16) + '…',
      ciphertext: wrapped.ciphertext.slice(0, 16) + '…',
      kdf: {
        opsLimit: wrapped.kdf.opsLimit,
        memLimit: wrapped.kdf.memLimit,
        salt: wrapped.kdf.salt.slice(0, 12) + '…',
        algorithm: wrapped.kdf.algorithm,
      },
    },
    null,
    2,
  )
    .split('\n')
    .map((l) => '    ' + l)
    .join('\n'),
);

// 3. Unwrap with the right and wrong keys.
const rightUnwrap = await tryUnwrap(wrapped, derivationKey);
const byteEqual =
  rightUnwrap !== null &&
  rightUnwrap.length === vaultKey.length &&
  rightUnwrap.every((b, i) => b === vaultKey[i]);
console.log('');
console.log(`  tryUnwrap(right key) : ${rightUnwrap === null ? 'null' : 'recovered'} — byte-equal to vault_key: ${byteEqual}`);

const wrongKey = sodium.randombytes_buf(32);
const wrongUnwrap = await tryUnwrap(wrapped, wrongKey);
console.log(`  tryUnwrap(wrong key) : ${wrongUnwrap === null ? 'null (DC-5 wrong-key branch)' : 'UNEXPECTED non-null!'}`);

// 4. Seal + open a data blob under the vault key (uses VAULT_AD, version-bound).
const plaintext = new TextEncoder().encode('{"entries":[{"title":"GitHub","secret":"hunter2"}]}');
const { ciphertext, nonce } = await sealData(plaintext, vaultKey);
const recovered = await openData(ciphertext, nonce, vaultKey);
const dataRoundTrip = new TextDecoder().decode(recovered);
console.log('');
console.log(`  data seal/open       : nonce ${nonce.length}B, ciphertext ${ciphertext.length}B (= ${plaintext.length} + 16 tag)`);
console.log(`  data round-trip      : ${dataRoundTrip === new TextDecoder().decode(plaintext) ? 'lossless ✓' : 'MISMATCH!'}`);
console.log(`    -> ${dataRoundTrip}`);
console.log('');
console.log(
  byteEqual && wrongUnwrap === null && dataRoundTrip === new TextDecoder().decode(plaintext)
    ? '  Envelope encryption OK: right-key unwrap byte-equal, wrong-key null, data round-trips.'
    : '  ENVELOPE DEMO FAILED — investigate.',
);
