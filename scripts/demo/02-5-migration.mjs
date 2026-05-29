// scripts/demo/02-5-migration.mjs
//
// Checkpoint 5 demo (DC-12): exercise the migration framework scaffold end-to-end against
// packages/core's TypeScript source. Cryptiq's PRODUCTION registry is empty (it starts at
// v1), so this demo passes a SYNTHETIC v0→v1 mock migration into loadAndMigrate to prove
// the back-up → migrate-copy → verify-by-cold-decrypt → swap pipeline:
//
//   1. Build a synthetic version-0 vault (master wrap + sealed entries) + an in-memory mock
//      storage adapter whose savePreMigrationBackup logs the named backup.
//   2. Run loadAndMigrate with an HONEST v0→v1 migration → print:
//        - "backup written" (the never-rotated pre-migration backup, BEFORE transform)
//        - "migrated v0→v1" (a fresh version-1 document)
//        - the cold-decrypt-verified entry (the verify re-derived the key from the NEW file
//          and round-tripped a known entry — not just a JSON parse).
//   3. Run loadAndMigrate again with a BUGGY migration that corrupts data.ciphertext →
//      print that it threw MigrationFailedError (the cold-decrypt verify caught it; the
//      original was NOT swapped).
//
// A FIXED kdf-override (256 MiB / 3 ops floor) keeps the demo snappy — real Argon2id, just
// not auto-tuned. Demo scripts live outside packages/core, so console.log is allowed here.
//
// Run (preferred): pnpm demo:02-5
// Or directly:
//   node --experimental-transform-types --import ./scripts/demo/_loader.mjs scripts/demo/02-5-migration.mjs

import {
  getSodium,
  deriveKey,
  wrapKey,
  sealData,
  VAULT_AD,
  padToTieredBucket,
  loadAndMigrate,
} from '@cryptiq/core/internal';

const FLOOR_MEM = 268_435_456; // 256 MiB
const FLOOR_OPS = 3;
const FORMAT_IDENTIFIER = 'cryptiq-vault';
const pw = (s) => new TextEncoder().encode(s);

const sodium = await getSodium();
const b64 = (u8) => sodium.to_base64(u8, sodium.base64_variants.ORIGINAL);
const floorParams = () => ({
  algorithm: 2,
  opsLimit: FLOOR_OPS,
  memLimit: FLOOR_MEM,
  salt: sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES),
});

const KNOWN_ENTRIES = { entries: [{ title: 'Email', username: 'me', secret: 'hunter2' }] };
const MASTER_PW = 'correct horse battery staple migration';

console.log('Cryptiq — Migration framework scaffold (Checkpoint 5)');
console.log('-----------------------------------------------------');

// --- Build a synthetic version-0 vault + capture its vault key (so the mock migration can
//     re-seal the v1 data blob with the SAME key the orchestrator recovers). -------------
async function makeSyntheticV0() {
  const params = floorParams();
  const vaultKey = sodium.randombytes_buf(32);
  const masterDK = await deriveKey(pw(MASTER_PW), params);
  const master = await wrapKey(vaultKey, masterDK, params);
  sodium.memzero(masterDK);

  const padded = padToTieredBucket(new TextEncoder().encode(JSON.stringify(KNOWN_ENTRIES)));
  const { ciphertext, nonce } = await sealData(padded, vaultKey, VAULT_AD);

  const v0doc = {
    format: FORMAT_IDENTIFIER,
    version: 0,
    wrappedKeys: { master },
    data: { nonce: b64(nonce), ciphertext: b64(ciphertext) },
    meta: { createdAt: '2020-01-01T00:00:00.000Z', modifiedAt: '2020-01-01T00:00:00.000Z' },
  };
  return {
    bytes: new TextEncoder().encode(JSON.stringify(v0doc, null, 2) + '\n'),
    vaultKey,
  };
}

async function sealInner(inner, vaultKey) {
  const padded = padToTieredBucket(new TextEncoder().encode(JSON.stringify(inner)));
  const { ciphertext, nonce } = await sealData(padded, vaultKey, VAULT_AD);
  return { nonce: b64(nonce), ciphertext: b64(ciphertext) };
}

// Honest v0→v1: re-stamp version, carry the master wrap, re-seal the entries correctly.
async function honestMigration(vaultKey) {
  const sealed = await sealInner(KNOWN_ENTRIES, vaultKey);
  return {
    fromVersion: 0,
    toVersion: 1,
    description: 'synthetic v0→v1 (demo)',
    apply(doc, decryptedInner) {
      return {
        ok: true,
        doc: {
          format: FORMAT_IDENTIFIER,
          version: 1,
          wrappedKeys: doc.wrappedKeys,
          data: sealed,
          meta: { createdAt: doc.meta.createdAt, modifiedAt: new Date().toISOString() },
        },
        newInner: decryptedInner,
      };
    },
  };
}

// Buggy v0→v1: corrupts one char of data.ciphertext but still claims the real entries.
async function buggyMigration(vaultKey) {
  const sealed = await sealInner(KNOWN_ENTRIES, vaultKey);
  const ct = sealed.ciphertext;
  const at = 10;
  const flipped = ct[at] === 'A' ? 'B' : 'A';
  const corrupted = {
    nonce: sealed.nonce,
    ciphertext: ct.slice(0, at) + flipped + ct.slice(at + 1),
  };
  return {
    fromVersion: 0,
    toVersion: 1,
    description: 'buggy v0→v1 (corrupts data.ciphertext)',
    apply(doc) {
      return {
        ok: true,
        doc: {
          format: FORMAT_IDENTIFIER,
          version: 1,
          wrappedKeys: doc.wrappedKeys,
          data: corrupted,
          meta: { createdAt: doc.meta.createdAt, modifiedAt: new Date().toISOString() },
        },
        newInner: KNOWN_ENTRIES,
      };
    },
  };
}

// In-memory mock adapter — logs the pre-migration backup write.
function makeMockAdapter() {
  const backups = [];
  return {
    backups,
    vaultLabel: 'demo://migration',
    exists: () => Promise.resolve(true),
    load: () => Promise.reject(new Error('not used')),
    save: () => Promise.resolve(),
    listBackups: () => Promise.resolve([]),
    loadBackup: () => Promise.reject(new Error('not used')),
    savePreMigrationBackup(name, bytes) {
      backups.push({ name, byteLength: bytes.length });
      console.log(`    backup written: "${name}" (${bytes.length} bytes, never rotated)`);
      return Promise.resolve();
    },
  };
}

// --- 1. HONEST migration --------------------------------------------------------------
console.log('');
console.log('  [1] Honest v0→v1 migration:');
const { bytes: v0a, vaultKey: keyA } = await makeSyntheticV0();
const adapterA = makeMockAdapter();
const honest = await loadAndMigrate(v0a, { masterPassword: pw(MASTER_PW) }, adapterA, [
  await honestMigration(keyA),
]);
const newVersion = JSON.parse(new TextDecoder().decode(honest.bytes)).version;
console.log(`    migrated v0→v${newVersion}: ${honest.migrated ? 'YES ✓' : 'NO (BUG!)'}`);
console.log(
  `    cold-decrypt-verified entry: ${JSON.stringify(honest.vault.entries)} ` +
    `(${JSON.stringify(honest.vault.entries) === JSON.stringify(KNOWN_ENTRIES) ? 'round-tripped ✓' : 'MISMATCH (BUG!)'})`,
);
console.log(`    backups taken: ${adapterA.backups.length} (exactly one, before transform)`);

// --- 2. BUGGY migration (corrupt ciphertext) → MigrationFailedError --------------------
console.log('');
console.log('  [2] Buggy v0→v1 migration (corrupts data.ciphertext):');
const { bytes: v0b, vaultKey: keyB } = await makeSyntheticV0();
const adapterB = makeMockAdapter();
let buggyTyped = false;
let buggyMsg = '';
try {
  await loadAndMigrate(v0b, { masterPassword: pw(MASTER_PW) }, adapterB, [
    await buggyMigration(keyB),
  ]);
} catch (err) {
  buggyTyped = err?.code === 'MIGRATION_FAILED';
  buggyMsg = err?.message ?? '';
}
console.log(
  `    -> ${buggyTyped ? 'MigrationFailedError ✓' : 'WRONG error type / silently passed (BUG!)'}`,
);
console.log(`       "${buggyMsg}"`);
console.log(
  `    original preserved (backup still written, NOT swapped): ${adapterB.backups.length === 1 ? 'YES ✓' : 'NO (BUG!)'}`,
);

// --- Summary --------------------------------------------------------------------------
const ok =
  honest.migrated &&
  newVersion === 1 &&
  JSON.stringify(honest.vault.entries) === JSON.stringify(KNOWN_ENTRIES) &&
  adapterA.backups.length === 1 &&
  buggyTyped &&
  adapterB.backups.length === 1;
console.log('');
console.log(
  ok
    ? '  Migration scaffold OK: back-up → migrate → verify-by-cold-decrypt → swap; buggy migration rejected.'
    : '  MIGRATION DEMO FAILED — investigate.',
);
