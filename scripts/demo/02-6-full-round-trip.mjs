// scripts/demo/02-6-full-round-trip.mjs
//
// Checkpoint 6 demo (DC-12) — THE PHASE-2 END-STATE FINALE. Exercises the full verb-first
// vault lifecycle against packages/core's TypeScript source, the exact flow the Phase-4 UI
// and Phase-3 storage adapter will drive:
//
//   create → save → (simulate cold start) → load → unlock → print the entries blob
//
//   1. createVault({ masterPassword, withRecoveryKey: true }) → master + recovery wraps,
//      a random 32-byte vault key, the one-time recovery string, and the DC-2 creation report.
//   2. add a sample entry to the plain-data UnlockedVault.
//   3. saveVault → the serialized .cryptiq bytes (entries sealed under VAULT_AD, fresh nonce).
//   4. SIMULATE A COLD START: discard the in-memory key/vault, keep only the bytes, then
//      unlockVault(bytes, { masterPassword }) — re-derives the key from the password alone.
//   5. ALSO unlock via the recovery key → prove both paths recover the SAME entries + key.
//   6. console.log the recovery key + the decrypted entries blob (the human-eyeball finale).
//
// A FIXED kdf-override (256 MiB / 3 ops floor) keeps the demo snappy — real Argon2id, just
// not auto-tuned. Demo scripts live outside packages/core, so console.log is allowed here.
//
// Run (preferred): pnpm demo:02-6
// Or directly:
//   node --experimental-transform-types --import ./scripts/demo/_loader.mjs scripts/demo/02-6-full-round-trip.mjs

import { getSodium, createVault, saveVault, unlockVault } from '@cryptiq/core/internal';

const FLOOR_MEM = 268_435_456; // 256 MiB
const FLOOR_OPS = 3;
const MASTER_PW = 'correct horse battery staple finale';
const pw = (s) => new TextEncoder().encode(s);

const sodium = await getSodium();
const floorParams = () => ({
  algorithm: 2,
  opsLimit: FLOOR_OPS,
  memLimit: FLOOR_MEM,
  salt: sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES),
});

const SAMPLE_ENTRY = {
  title: 'GitHub',
  username: 'octocat',
  url: 'https://github.com',
  secret: 'hunter2-the-classic',
  notes: 'created in the Checkpoint 6 end-state demo',
};

console.log('Cryptiq — Full vault round-trip (Checkpoint 6, DC-12 end-state)');
console.log('---------------------------------------------------------------');

// --- 1. CREATE -----------------------------------------------------------------------
console.log('');
console.log('  [1] createVault({ withRecoveryKey: true }) ...');
const created = await createVault({
  masterPassword: pw(MASTER_PW),
  withRecoveryKey: true,
  kdfParams: floorParams(),
});
console.log(
  `      master wrap: ${created.vault.doc.wrappedKeys.master ? 'present ✓' : 'MISSING (BUG!)'}`,
);
console.log(
  `      recovery wrap: ${created.vault.doc.wrappedKeys.recovery ? 'present ✓' : 'MISSING (BUG!)'}`,
);
console.log(
  `      creation report: ${JSON.stringify({
    memLimit: created.creationReport.memLimit,
    opsLimit: created.creationReport.opsLimit,
    portabilityWarning: created.creationReport.portabilityWarning,
  })}`,
);
console.log(`      recovery key (shown once, never persisted): ${created.recoveryKey}`);

// --- 2 + 3. ADD ENTRY + SAVE ---------------------------------------------------------
console.log('');
console.log('  [2/3] add a sample entry, then saveVault → serialized .cryptiq bytes ...');
created.vault.entries = { entries: [SAMPLE_ENTRY] };
const bytes = await saveVault(created.vault, created.vaultKey);
console.log(`      serialized vault: ${bytes.length} bytes (entries sealed under VAULT_AD)`);

// Simulate a COLD START: forget the in-memory key + vault; only the bytes survive.
sodium.memzero(created.vaultKey);
const onDisk = bytes;

// --- 4. LOAD + UNLOCK (master password) ----------------------------------------------
console.log('');
console.log('  [4] cold start — unlockVault(bytes, { masterPassword }) ...');
const viaMaster = await unlockVault(onDisk, { masterPassword: pw(MASTER_PW) });
console.log('      decrypted entries blob:');
console.log('      ' + JSON.stringify(viaMaster.vault.entries, null, 2).replace(/\n/g, '\n      '));

// --- 5. UNLOCK via recovery key — proves the second path recovers the SAME vault -----
console.log('');
console.log('  [5] unlockVault(bytes, { recoveryKey }) — the recovery path ...');
const viaRecovery = await unlockVault(onDisk, { recoveryKey: created.recoveryKey });
const sameKey = sodium.to_hex(viaMaster.vaultKey) === sodium.to_hex(viaRecovery.vaultKey);
const sameEntries =
  JSON.stringify(viaMaster.vault.entries) === JSON.stringify(viaRecovery.vault.entries);
console.log(`      recovers the SAME vault key:  ${sameKey ? 'YES ✓' : 'NO (BUG!)'}`);
console.log(`      recovers the SAME entries:    ${sameEntries ? 'YES ✓' : 'NO (BUG!)'}`);

// --- Summary -------------------------------------------------------------------------
const ok =
  JSON.stringify(viaMaster.vault.entries) === JSON.stringify({ entries: [SAMPLE_ENTRY] }) &&
  sameKey &&
  sameEntries;
console.log('');
console.log(
  ok
    ? '  Full round-trip OK: create → save → cold load → unlock (master + recovery) → entries recovered.'
    : '  FULL ROUND-TRIP DEMO FAILED — investigate.',
);
