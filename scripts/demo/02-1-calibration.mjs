// scripts/demo/02-1-calibration.mjs
//
// Checkpoint 1 demo (DC-12): run the DC-1 adaptive Argon2id calibration on THIS
// machine and print the chosen params + timing so the user can eyeball them. Demo
// scripts live outside packages/core, so console.log is allowed here (no SEC-10 ban).
//
// Run (preferred — wraps the flags below):
//   pnpm demo:02-1
// Or directly:
//   node --experimental-transform-types --import ./scripts/demo/_loader.mjs scripts/demo/02-1-calibration.mjs
//
// The _loader.mjs preload (Node stdlib only, zero new deps) makes the demo run against
// packages/core's TypeScript source: it retries extensionless relative imports with a
// `.ts` suffix and redirects the broken libsodium-wrappers-sumo ESM build to its CJS
// entry. --experimental-transform-types is required because errors.ts uses a TS
// parameter property (MigrationFailedError's `cause`), which Node's default strip-only
// mode cannot handle.
//
// Imports the crypto primitives through the @cryptiq/core/internal subpath (DC-12),
// which keeps demo access to internals without enlarging the main `.` public API.

import { calibrateArgon2id } from '@cryptiq/core/internal';

const MiB = 1024 * 1024;

const { params, measuredMs, portabilityWarning } = await calibrateArgon2id();

console.log('Cryptiq — Argon2id calibration (Checkpoint 1)');
console.log('---------------------------------------------');
console.log(`  memLimit          : ${(params.memLimit / MiB).toFixed(0)} MiB (${params.memLimit} bytes)`);
console.log(`  opsLimit          : ${params.opsLimit}`);
console.log(`  algorithm         : ${params.algorithm} (Argon2id v1.3)`);
console.log(`  salt length       : ${params.salt.length} bytes`);
console.log(`  measured unlock   : ${measuredMs.toFixed(0)} ms`);
console.log(`  portabilityWarning: ${portabilityWarning} (set when memLimit > 512 MiB)`);
console.log('');
console.log(
  portabilityWarning
    ? '  NOTE: calibration landed above 512 MiB — Phase 4 creation report will surface the portability disclosure + an "older machines" opt-down (DC-2).'
    : '  Calibration within the portable band (<= 512 MiB).',
);
