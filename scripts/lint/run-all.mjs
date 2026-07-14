#!/usr/bin/env node
// scripts/lint/run-all.mjs
//
// HARD-06 / D-11
//
// Auto-discovery custom-lint runner. Replaces the naive `&&`-chained lint list
// in root package.json with a sorted `readdirSync` glob over this directory —
// AUTO-DISCOVERY, not a hardcoded array, is the whole point: a hardcoded list
// can silently drift when a new `lint-*.mjs` script is added and forgotten in
// the chain (exactly the "new lint file silently not wired" failure class this
// phase exists to structurally prevent — a direct cousin of the silent-skip
// pathology Phase 33 killed for CI jobs). Every discovered lint gets a legible
// `▶ <name>` banner BEFORE it runs, so the TOTP wire-minimization tripwire (and
// every other gate) stays individually named in the CI run log even after the
// 11 separate ci.yml steps collapse into one `pnpm lint:custom` call.
//
// Zero-dependency (node:fs/node:path/node:url/node:child_process only), same
// self-location + accumulate-then-report idiom as every lint-*.mjs script in
// this directory (see lint-version-consistency.mjs).

import { readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const LINT_DIR = dirname(fileURLToPath(import.meta.url));

// Glob: startsWith('lint-') && endsWith('.mjs'), sorted for deterministic order.
// This naturally excludes run-all.mjs (doesn't start with "lint-"), README.md
// and __fixtures__/ (don't end with ".mjs").
const lints = readdirSync(LINT_DIR)
  .filter((f) => f.startsWith('lint-') && f.endsWith('.mjs'))
  .sort();

if (lints.length === 0) {
  console.error('No lint-*.mjs scripts discovered in scripts/lint/ — refusing to report a false pass.');
  process.exit(1);
}

const failed = [];

for (const lint of lints) {
  console.log(`\n▶ ${lint}`);
  const result = spawnSync(process.execPath, [join(LINT_DIR, lint)], { stdio: 'inherit' });
  if (result.status !== 0) {
    failed.push(lint);
  }
}

if (failed.length > 0) {
  console.error(`\n✖ ${failed.length}/${lints.length} custom lint(s) failed: ${failed.join(', ')}`);
  process.exit(1);
}

console.log(`\n✓ all ${lints.length} custom lints passed`);
