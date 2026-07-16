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

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = fileURLToPath(new URL('../../', import.meta.url));
const PKG_JSON = join(REPO_ROOT, 'package.json');
const WORKSPACE_YAML = join(REPO_ROOT, 'pnpm-workspace.yaml');
const GITIGNORE = join(REPO_ROOT, '.gitignore');
const WORKFLOWS_DIR = join(REPO_ROOT, '.github', 'workflows');

// pnpm 11 imports `node:sqlite`, a Node 22+ builtin. Raising the pnpm pin
// without raising this (and every CI node-version) is a guaranteed red run.
// The minor matters too: node:sqlite landed in 22.13, so ">=22.0.0" is below
// the real floor even though its major is correct.
const MIN_NODE_MAJOR = 22;
const MIN_NODE_MINOR = 13;

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
  // Require an EXPLICIT lower bound (">=22.13") and validate major AND minor.
  // pnpm 11 requires Node >=22.13 (it imports the `node:sqlite` builtin); on
  // Node 20 it dies with ERR_UNKNOWN_BUILTIN_MODULE.
  //
  // The previous `nodeEngine.match(/(\d+)/)` grabbed the first digit run and
  // DISCARDED the comparison operator, so it asserted almost nothing: "<22"
  // extracted 22, compared 22 < 22 => false => PASSED, while declaring the exact
  // opposite of the requirement. "<=22" passed identically, and "22.0.0" passed
  // despite being below the 22.13 node:sqlite floor. A version-skew lint
  // defeatable by a one-character edit, in the phase whose point is catching skew.
  const m = /^>=\s*(\d+)(?:\.(\d+))?/.exec(nodeEngine.trim());
  if (!m) {
    console.error(
      `package.json: engines.node "${nodeEngine}" must be an explicit lower bound ` +
        `(">=${MIN_NODE_MAJOR}.${MIN_NODE_MINOR}") — any other form leaves the floor unasserted.`,
    );
    violations++;
  } else if (
    Number(m[1]) < MIN_NODE_MAJOR ||
    (Number(m[1]) === MIN_NODE_MAJOR && Number(m[2] ?? 0) < MIN_NODE_MINOR)
  ) {
    console.error(
      `package.json: engines.node "${nodeEngine}" must allow Node >=${MIN_NODE_MAJOR}.${MIN_NODE_MINOR} ` +
        '(pnpm 11 requires the node:sqlite builtin).',
    );
    violations++;
  }
}

// 2b. Every workflow `node-version:` must satisfy the same floor.
// THIS GUARD EXISTS BECAUSE OF A REAL FAILURE (2026-07-16): the pnpm 11 bump was
// verified locally on Node 24 and pushed, but CI pinned node-version: '20', so
// every job died on `node:sqlite`. Local dev Node != CI Node, and nothing caught
// the skew until a red run. Now it fails locally, before the push.
//
// The loop only ever RAISED on lines it matched, and never asserted it matched
// anything — so zero matches across every workflow was indistinguishable from a
// fully-correct pin. Silent-bypass forms that all reported OK: `node-version-file:
// .nvmrc` (never matches `node-version:`), `node-version: ${{ matrix.node }}` (the
// `(\d+)` cannot match `${{`), and a workflow with no pin at all riding the
// runner's preinstalled Node. All three are now explicit violations, and a
// zero-site run refuses to report a false pass — the same idiom run-all.mjs
// already uses.
let nodeVersionSites = 0;
for (const wf of readdirSync(WORKFLOWS_DIR).filter((f) => /\.ya?ml$/.test(f))) {
  const wfPath = join(WORKFLOWS_DIR, wf);
  const wfText = readFileSync(wfPath, 'utf8');

  if (/^\s*node-version-file:/m.test(wfText)) {
    console.error(
      `.github/workflows/${wf}: node-version-file: bypasses the Node ${MIN_NODE_MAJOR} skew guard — ` +
        'pin node-version: literally so this lint can evaluate it.',
    );
    violations++;
  }

  for (const m of wfText.matchAll(/^\s*node-version:\s*(.+)$/gm)) {
    nodeVersionSites++;
    const raw = m[1].trim().replace(/^['"]|['"]$/g, '');
    const major = /^(\d+)/.exec(raw);
    if (!major) {
      console.error(
        `.github/workflows/${wf}: node-version '${raw}' is not a literal version — ` +
          'the skew guard cannot evaluate it (no expressions/indirection here).',
      );
      violations++;
    } else if (Number(major[1]) < MIN_NODE_MAJOR) {
      console.error(
        `.github/workflows/${wf}: node-version '${raw}' is below Node ${MIN_NODE_MAJOR} — ` +
          `pnpm ${pkg.packageManager} cannot run on it (node:sqlite is a Node ${MIN_NODE_MAJOR}+ builtin).`,
      );
      violations++;
    }
  }
}
if (nodeVersionSites === 0) {
  console.error(
    'No node-version: pins found in .github/workflows/ — refusing to report a false pass ' +
      `(the Node ${MIN_NODE_MAJOR} skew guard would be silently inert).`,
  );
  violations++;
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
