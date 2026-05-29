// scripts/demo/02-4-recovery.mjs
//
// Checkpoint 4 demo (DC-12): exercise the recovery-key path + master-password change
// end-to-end against packages/core's TypeScript source, printing real bytes/strings the
// user can eyeball at the YOLO checkpoint.
//
//   1. createVault({ withRecoveryKey: true }) -> print the 54-char Crockford recovery key
//      (only chars 0-9 A-Z minus I/L/O/U, plus the check char) + the DC-2 creationReport.
//   2. saveVault -> serialized bytes.
//   3. unlockVault via masterPassword -> print the recovered entries.
//   4. unlockVault via recoveryKey -> print the SAME entries (proves the recovery wrap).
//   5. changeMasterPassword -> show the OLD password now fails, the NEW one works, and the
//      data.ciphertext is BYTE-IDENTICAL before/after (envelope re-wrap, NOT re-encrypt).
//   6. Show a 1-char typo in the recovery key -> typed WrongRecoveryKeyError ("check char").
//
// A FIXED kdf-override (256 MiB / 3 ops floor) is used so the demo doesn't run the full
// adaptive calibration ladder — real Argon2id, just not auto-tuned (keeps the demo snappy).
//
// Demo scripts live outside packages/core, so console.log is allowed here (no SEC-10 ban).
//
// Run (preferred): pnpm demo:02-4
// Or directly:
//   node --experimental-transform-types --import ./scripts/demo/_loader.mjs scripts/demo/02-4-recovery.mjs

import {
  getSodium,
  createVault,
  unlockVault,
  saveVault,
  changeMasterPassword,
  parseOuter,
} from '@cryptiq/core/internal';

const FLOOR_MEM = 268_435_456; // 256 MiB
const FLOOR_OPS = 3;
const pw = (s) => new TextEncoder().encode(s);

const sodium = await getSodium();
const floorParams = () => ({
  algorithm: 2,
  opsLimit: FLOOR_OPS,
  memLimit: FLOOR_MEM,
  salt: sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES),
});

console.log('Cryptiq — Recovery key path + master-password change (Checkpoint 4)');
console.log('-------------------------------------------------------------------');

// 1. Create a vault WITH a recovery key.
const masterPw = pw('correct horse battery staple');
const created = await createVault({
  masterPassword: masterPw,
  withRecoveryKey: true,
  kdfParams: floorParams(),
});
created.vault.entries = { entries: [{ title: 'GitHub', username: 'acme', secret: 'hunter2' }] };

const flat = created.recoveryKey.replace(/[^0-9A-Za-z*~$=]/g, '');
console.log('');
console.log('  Recovery key (display form, dashed):');
console.log(`    ${created.recoveryKey}`);
console.log(`  Flat form: ${flat}  (${flat.length} chars: 53 base32 + 1 check)`);
console.log(
  `  Alphabet check (no I/L/O/U): ${/[ILOU]/.test(flat.slice(0, 53)) ? 'FAIL (has look-alike!)' : 'OK ✓'}`,
);
console.log('');
console.log('  creationReport (Phase-4 DC-2 data shape):');
console.log(`    ${JSON.stringify(created.creationReport)}`);

// 2. Save -> bytes.
const bytes = await saveVault(created.vault, created.vaultKey);
const dataCiphertextBefore = parseOuter(bytes).data.ciphertext;

// 3. Unlock via master password.
const viaMaster = await unlockVault(bytes, { masterPassword: masterPw });
console.log('');
console.log(`  unlock via master   -> entries: ${JSON.stringify(viaMaster.vault.entries)}`);

// 4. Unlock via recovery key.
const viaRecovery = await unlockVault(bytes, { recoveryKey: created.recoveryKey });
console.log(`  unlock via recovery -> entries: ${JSON.stringify(viaRecovery.vault.entries)}`);
const sameVaultKey =
  viaMaster.vaultKey.length === viaRecovery.vaultKey.length &&
  viaMaster.vaultKey.every((b, i) => b === viaRecovery.vaultKey[i]);
console.log(`  both paths recovered the SAME vault_key: ${sameVaultKey ? 'YES ✓' : 'NO (BUG!)'}`);

// 5. Change master password (envelope re-wrap — data NOT re-encrypted).
const newPw = pw('a far longer brand new passphrase that I will actually remember');
const unlocked = await unlockVault(bytes, { masterPassword: masterPw });
const newDoc = await changeMasterPassword(unlocked.vault, unlocked.vaultKey, {
  currentPassword: masterPw,
  newPassword: newPw,
  kdfParams: floorParams(),
});
const dataCiphertextAfter = newDoc.data.ciphertext;
const rewrapped = await saveVault(unlocked.vault, unlocked.vaultKey);

let oldFails = false;
try {
  await unlockVault(rewrapped, { masterPassword: masterPw });
} catch (err) {
  oldFails = err?.code === 'WRONG_PASSWORD';
}
const reopened = await unlockVault(rewrapped, { masterPassword: newPw });
console.log('');
console.log('  changeMasterPassword:');
console.log(
  `    old password now fails:        ${oldFails ? 'YES ✓ (WrongPasswordError)' : 'NO (BUG!)'}`,
);
console.log(
  `    new password unlocks:          ${JSON.stringify(reopened.vault.entries) === JSON.stringify(created.vault.entries) ? 'YES ✓' : 'NO (BUG!)'}`,
);
console.log(
  `    data.ciphertext UNCHANGED:     ${dataCiphertextBefore === dataCiphertextAfter ? 'YES ✓ (re-wrap, not re-encrypt)' : 'NO (entries were re-encrypted — wrong!)'}`,
);

// 6. A 1-char typo in the recovery key -> typed WrongRecoveryKeyError mentioning the check char.
let typoTyped = false;
let typoMsg = '';
const corrupted = flat.slice(0, 53) + (flat[53] === '0' ? '1' : '0'); // flip the check char
try {
  await unlockVault(bytes, { recoveryKey: corrupted });
} catch (err) {
  typoTyped = err?.code === 'WRONG_RECOVERY_KEY';
  typoMsg = err?.message ?? '';
}
console.log('');
console.log('  Corrupted recovery key (check-char typo):');
console.log(
  `    -> ${typoTyped ? 'WrongRecoveryKeyError ✓' : 'WRONG error type (BUG!)'}: "${typoMsg}"`,
);

console.log('');
console.log(
  sameVaultKey &&
    oldFails &&
    dataCiphertextBefore === dataCiphertextAfter &&
    typoTyped &&
    !/[ILOU]/.test(flat.slice(0, 53))
    ? '  Recovery + master-change OK: dual unlock, re-wrap (not re-encrypt), typed typo error.'
    : '  RECOVERY DEMO FAILED — investigate.',
);
