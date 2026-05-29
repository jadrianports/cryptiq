// scripts/demo/02-3-vault-format.mjs
//
// Checkpoint 3 demo (DC-12): build a REAL serialized Cryptiq vault file and prove the
// vault file format end-to-end against packages/core's TypeScript source.
//
//   1. Derive a derivation key (Argon2id floor params) and wrapKey() a random vault_key
//      into a master WrappedKey (DC-3 per-wrap kdf — NO top-level kdf).
//   2. encryptInner() a small entries JSON -> DC-6 tiered padding + sealData under
//      VAULT_AD (version-bound, SEC-06) -> base64 {nonce, ciphertext}.
//   3. serializeOuter() the VaultDocumentV1 -> print the actual on-disk JSON.
//   4. parseOuter() it back -> print version + wrappedKeys labels (DC-4 open map).
//   5. Encrypt two DIFFERENT entry counts in the same tier -> show IDENTICAL padded
//      ciphertext byte length (entry-count hiding, VAULT-03 / T-02-12).
//   6. Show parseOuter refuses an unknown version (UnknownVaultVersionError, VAULT-07).
//
// Demo scripts live outside packages/core, so console.log is allowed here (no SEC-10 ban).
//
// Run (preferred): pnpm demo:02-3
// Or directly:
//   node --experimental-transform-types --import ./scripts/demo/_loader.mjs scripts/demo/02-3-vault-format.mjs

import {
  getSodium,
  deriveKey,
  wrapKey,
  encryptInner,
  serializeOuter,
  parseOuter,
} from '@cryptiq/core/internal';

const FLOOR_MEM = 268_435_456; // 256 MiB
const FLOOR_OPS = 3;

const sodium = await getSodium();

console.log('Cryptiq — Vault file format (Checkpoint 3)');
console.log('------------------------------------------');

// 1. Master wrap: derive a key, generate a vault_key, wrap it (DC-3 per-wrap kdf).
const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
const kdfParams = { algorithm: 2, opsLimit: FLOOR_OPS, memLimit: FLOOR_MEM, salt };
const masterPassword = new TextEncoder().encode('correct horse battery staple');
const derivationKey = await deriveKey(masterPassword, kdfParams);
const vaultKey = sodium.randombytes_buf(32);
const master = await wrapKey(vaultKey, derivationKey, kdfParams);

// 2. Encrypt a small entries blob (DC-6 padding + VAULT_AD seal).
const entries = '{"entries":[{"title":"GitHub","username":"acme","secret":"hunter2"}]}';
const data = await encryptInner(new TextEncoder().encode(entries), vaultKey);

// 3. Build + serialize the VaultDocumentV1.
const now = new Date('2026-05-29T12:00:00.000Z').toISOString();
const doc = {
  format: 'cryptiq-vault',
  version: 1,
  wrappedKeys: { master },
  data,
  meta: { createdAt: now, modifiedAt: now, deviceLabel: 'demo-machine' },
};
const fileBytes = serializeOuter(doc);

// Pretty-print the on-disk JSON with base64 fields truncated for readability.
const printable = JSON.parse(new TextDecoder().decode(fileBytes));
printable.wrappedKeys.master.nonce = printable.wrappedKeys.master.nonce.slice(0, 16) + '…';
printable.wrappedKeys.master.ciphertext =
  printable.wrappedKeys.master.ciphertext.slice(0, 16) + '…';
printable.wrappedKeys.master.kdf.salt = printable.wrappedKeys.master.kdf.salt.slice(0, 12) + '…';
printable.data.nonce = printable.data.nonce.slice(0, 16) + '…';
printable.data.ciphertext =
  printable.data.ciphertext.slice(0, 24) + `… (${data.ciphertext.length} b64 chars)`;
console.log('');
console.log('  Serialized vault file (base64 fields truncated):');
console.log(
  JSON.stringify(printable, null, 2)
    .split('\n')
    .map((l) => '    ' + l)
    .join('\n'),
);

// 4. Parse it back.
const parsed = parseOuter(fileBytes);
console.log('');
console.log(`  parseOuter -> format=${parsed.format}, version=${parsed.version}`);
console.log(
  `  wrappedKeys labels (DC-4 open map): [${Object.keys(parsed.wrappedKeys).join(', ')}]`,
);
console.log(
  `  per-wrap kdf (DC-3): ops=${parsed.wrappedKeys.master.kdf.opsLimit}, mem=${parsed.wrappedKeys.master.kdf.memLimit}, alg=${parsed.wrappedKeys.master.kdf.algorithm}`,
);
console.log(
  `  top-level kdf present? ${parsed.kdf === undefined ? 'NO (correct — DC-3)' : 'YES (WRONG!)'}`,
);

// 5. Entry-count hiding: two different entry counts in the same tier -> equal padded size.
const few = await encryptInner(new TextEncoder().encode('{"entries":[{"t":"A"}]}'), vaultKey);
const more = await encryptInner(
  new TextEncoder().encode('{"entries":[{"t":"A"},{"t":"B"},{"t":"C"},{"t":"D"},{"t":"E"}]}'),
  vaultKey,
);
const lenFew = sodium.from_base64(few.ciphertext, sodium.base64_variants.ORIGINAL).length;
const lenMore = sodium.from_base64(more.ciphertext, sodium.base64_variants.ORIGINAL).length;
console.log('');
console.log('  Entry-count hiding (VAULT-03 / T-02-12):');
console.log(`    1-entry vault  -> padded ciphertext ${lenFew} bytes`);
console.log(`    5-entry vault  -> padded ciphertext ${lenMore} bytes`);
console.log(`    equal size? ${lenFew === lenMore ? 'YES (count hidden ✓)' : 'NO (LEAK!)'}`);

// 6. Version refusal (VAULT-07).
let refused = false;
try {
  parseOuter(serializeOuter({ ...doc, version: 2 }));
} catch (err) {
  refused = err?.code === 'UNKNOWN_VAULT_VERSION';
  console.log('');
  console.log(`  version: 2 refused -> ${err?.constructor?.name} (code=${err?.code})`);
}

console.log('');
console.log(
  parsed.version === 1 && parsed.kdf === undefined && lenFew === lenMore && refused
    ? '  Vault file format OK: parses, DC-3 per-wrap kdf, entry-count hidden, unknown version refused.'
    : '  VAULT-FORMAT DEMO FAILED — investigate.',
);
