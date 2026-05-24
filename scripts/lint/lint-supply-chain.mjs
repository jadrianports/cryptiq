#!/usr/bin/env node
// scripts/lint/lint-supply-chain.mjs
//
// Asserts the supply-chain hardening invariants from Plan 01-01:
//   - package.json#packageManager matches pnpm@10.x (SEC-15)
//   - package.json#engines.node is >=20 (SEC-15)
//   - pnpm-workspace.yaml has `minimumReleaseAge: 1440` (SEC-15)
//   - pnpm-workspace.yaml includes '@tauri-apps/*' under minimumReleaseAgeExclude
//   - .gitignore contains `package-lock.json` (Pitfall 6 defense)

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

// 1. packageManager pin to pnpm 10.x
if (typeof pkg.packageManager !== 'string' || !/^pnpm@10\./.test(pkg.packageManager)) {
  console.error(
    `package.json: packageManager must match pnpm@10.x (got ${JSON.stringify(pkg.packageManager)}) — SEC-15.`,
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
  'OK: pnpm 10 pinned, minimumReleaseAge 1440 active, @tauri-apps/* exempt, package-lock.json gitignored.',
);
