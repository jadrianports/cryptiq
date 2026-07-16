#!/usr/bin/env node
// scripts/lint/lint-supply-chain.mjs
//
// Asserts the supply-chain hardening invariants from Plan 01-01:
//   - package.json#packageManager matches pnpm@11.x (SEC-15)
//   - package.json#engines.node is >=20 (SEC-15)
//   - package.json has NO `pnpm` field (pnpm 11 SILENTLY IGNORES it — see below)
//   - pnpm-workspace.yaml has `minimumReleaseAge: 1440` (SEC-15)
//   - pnpm-workspace.yaml includes '@tauri-apps/*' under minimumReleaseAgeExclude
//   - pnpm-workspace.yaml declares `allowBuilds:` (the build-script allow-list)
//   - .gitignore contains `package-lock.json` (Pitfall 6 defense)
//
// pnpm 11 note (migrated 2026-07-15): build-script permissions moved from
// `package.json#pnpm.onlyBuiltDependencies` to `pnpm-workspace.yaml#allowBuilds`.
// pnpm 11 does not read `package.json#pnpm` AND DOES NOT ERROR — it just warns
// and ignores it. So a well-meaning re-add of `pnpm.onlyBuiltDependencies` there
// would silently grant nothing while LOOKING like it granted something. That is a
// silent-failure footgun, so it is a hard lint violation here.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = fileURLToPath(new URL('../../', import.meta.url));
const PKG_JSON = join(REPO_ROOT, 'package.json');
const WORKSPACE_YAML = join(REPO_ROOT, 'pnpm-workspace.yaml');
const GITIGNORE = join(REPO_ROOT, '.gitignore');

let violations = 0;

function readOrExit(path, label) {
  try {
    return readFileSync(path, 'utf8');
  } catch (e) {
    if (e.code === 'ENOENT') {
      console.error(`${label} not found: ${path}`);
      process.exit(1);
    }
    throw e;
  }
}

const pkgText = readOrExit(PKG_JSON, 'package.json');
const wsText = readOrExit(WORKSPACE_YAML, 'pnpm-workspace.yaml');
const giText = readOrExit(GITIGNORE, '.gitignore');

let pkg;
try {
  pkg = JSON.parse(pkgText);
} catch (e) {
  console.error(`package.json: invalid JSON — ${e.message}`);
  process.exit(1);
}

// 1. packageManager pin to pnpm 11.x
// pnpm 10.x is NOT acceptable: npm retired the legacy audit endpoint (2026-07-15)
// and `pnpm audit` is permanently broken on the entire 10.x line (HTTP 410), which
// would silently reduce the CI audit gate to a guaranteed-red no-op. pnpm 11 uses
// the bulk advisory endpoint.
if (typeof pkg.packageManager !== 'string' || !/^pnpm@11\./.test(pkg.packageManager)) {
  console.error(
    `package.json: packageManager must match pnpm@11.x (got ${JSON.stringify(pkg.packageManager)}) — SEC-15.`,
  );
  violations++;
}

// 1b. package.json must NOT carry a `pnpm` field — pnpm 11 ignores it SILENTLY.
if (pkg.pnpm !== undefined) {
  console.error(
    'package.json: `pnpm` field present, but pnpm 11 does not read it (silently ignored). ' +
      'Move these settings to pnpm-workspace.yaml — build permissions belong in `allowBuilds:`. SEC-15.',
  );
  violations++;
}

// 2. engines.node >= 20
const nodeEngine = pkg?.engines?.node;
if (typeof nodeEngine !== 'string') {
  console.error('package.json: missing engines.node — SEC-15 requires Node 20+.');
  violations++;
} else {
  // Accept ">=20", ">=20.0.0", ">=21", "^20", etc. Reject "<20" etc.
  const minMatch = nodeEngine.match(/(\d+)/);
  if (!minMatch || Number(minMatch[1]) < 20) {
    console.error(
      `package.json: engines.node "${nodeEngine}" must allow Node >=20 (SEC-15 / pnpm 10 requirement).`,
    );
    violations++;
  }
}

// 3. pnpm-workspace.yaml has minimumReleaseAge: 1440
if (!/^\s*minimumReleaseAge:\s*1440\b/m.test(wsText)) {
  console.error(
    'pnpm-workspace.yaml: missing `minimumReleaseAge: 1440` — SEC-15 (24h embargo on fresh npm releases).',
  );
  violations++;
}

// 4. minimumReleaseAgeExclude contains '@tauri-apps/*'
// Find the block and scan its list items via simple line-by-line walk.
const wsLines = wsText.split('\n');
let inExcludeBlock = false;
let hasTauriExclude = false;
for (const line of wsLines) {
  if (/^\s*minimumReleaseAgeExclude:/.test(line)) {
    inExcludeBlock = true;
    continue;
  }
  if (inExcludeBlock) {
    if (/^[A-Za-z]/.test(line) && line.trim().length > 0) {
      // New top-level key — block ended.
      inExcludeBlock = false;
      continue;
    }
    if (/^\s*-\s+['"]@tauri-apps\/\*['"]/.test(line)) {
      hasTauriExclude = true;
    }
  }
}
if (!hasTauriExclude) {
  console.error(
    "pnpm-workspace.yaml: minimumReleaseAgeExclude does not include '@tauri-apps/*' — required by SEC-15 + Snippet 1 discretion (coordinated Tauri releases).",
  );
  violations++;
}

// 4b. pnpm-workspace.yaml must declare `allowBuilds:` — the build-script allow-list.
// Without it, the SEC-15 posture depends on pnpm's default alone and a future
// `strictDepBuilds`/default change would pass unnoticed. Presence is asserted here;
// the true/false values are a human supply-chain decision (see the file's comment).
if (!/^allowBuilds:/m.test(wsText)) {
  console.error(
    'pnpm-workspace.yaml: missing `allowBuilds:` map — SEC-15 requires an explicit ' +
      'build-script allow-list (replaced package.json#pnpm.onlyBuiltDependencies in pnpm 11).',
  );
  violations++;
}

// 5. .gitignore must contain `package-lock.json` (Pitfall 6 defense)
// Match a literal line (no leading wildcard), allowing trailing whitespace.
const giLines = giText.split('\n').map((s) => s.trim());
if (!giLines.includes('package-lock.json')) {
  console.error(
    '.gitignore: missing `package-lock.json` line — defends Pitfall 6 (Tauri CLI mis-detection visibility).',
  );
  violations++;
}

if (violations > 0) {
  console.error(`\n${violations} supply-chain violation(s).`);
  process.exit(1);
}

console.log(
  'OK: pnpm 11 pinned, no stale package.json#pnpm field, allowBuilds declared, ' +
    'minimumReleaseAge 1440 active, @tauri-apps/* exempt, package-lock.json gitignored.',
);
