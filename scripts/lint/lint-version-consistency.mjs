#!/usr/bin/env node
// scripts/lint/lint-version-consistency.mjs
//
// CI-05 / CI-11
//
// Asserts byte-equality of the app's `version` field across the four sources that
// each independently claim a version number:
//   - apps/desktop/package.json           (canonical per D-04)
//   - apps/desktop/src-tauri/tauri.conf.json
//   - apps/desktop/src-tauri/Cargo.toml    ([package] version = "...")
//   - apps/native-host/Cargo.toml          ([package] version = "...")
//
// D-04: single-sourcing via Tauri's native `"version": "../package.json"` path
// reference was considered and REJECTED for auditability — every file must show the
// real literal number, so this lint is the only thing standing between that and
// silent drift. `tagName: 'v__VERSION__'` publishes whatever apps/desktop/package.json
// claims at release time, so a drifted value here can mislabel a public release.
//
// ALSO folds in CI-11: asserts tauri.conf.json's bundle.targets does NOT contain
// "msi" — installerHooks are NSIS-only (the DIST-02 `-196608` bug class); an update
// shipped via an MSI target would silently skip native-host registration.
//
// Zero-dependency (node:fs/node:path/node:url only), mirrors the existing 7-lint
// idiom (see lint-supply-chain.mjs): readOrExit helper, JSON.parse-with-context,
// accumulate violations, single OK/exit-1 report.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = fileURLToPath(new URL('../../', import.meta.url));

const DESKTOP_PKG_JSON = join(REPO_ROOT, 'apps', 'desktop', 'package.json');
const TAURI_CONF_JSON = join(REPO_ROOT, 'apps', 'desktop', 'src-tauri', 'tauri.conf.json');
const DESKTOP_CARGO_TOML = join(REPO_ROOT, 'apps', 'desktop', 'src-tauri', 'Cargo.toml');
const NATIVE_HOST_CARGO_TOML = join(REPO_ROOT, 'apps', 'native-host', 'Cargo.toml');

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

function parseJsonOrExit(text, path, label) {
  try {
    return JSON.parse(text);
  } catch (e) {
    console.error(`${label}: invalid JSON (${path}) — ${e.message}`);
    process.exit(1);
  }
}

// [package]-block version regex — no TOML parser dependency (a single scalar field
// does not justify the project's first TOML-parser dep).
const CARGO_PACKAGE_VERSION_RE = /^\[package\]\s*[\s\S]*?^version\s*=\s*"([^"]+)"/m;

function extractCargoVersion(text, path, label) {
  const match = CARGO_PACKAGE_VERSION_RE.exec(text);
  if (!match) {
    console.error(`${label}: could not find [package] version = "..." in ${path}`);
    process.exit(1);
  }
  return match[1];
}

// --- Read all four sources ---

const desktopPkgText = readOrExit(DESKTOP_PKG_JSON, 'apps/desktop/package.json');
const tauriConfText = readOrExit(TAURI_CONF_JSON, 'apps/desktop/src-tauri/tauri.conf.json');
const desktopCargoText = readOrExit(DESKTOP_CARGO_TOML, 'apps/desktop/src-tauri/Cargo.toml');
const nativeHostCargoText = readOrExit(NATIVE_HOST_CARGO_TOML, 'apps/native-host/Cargo.toml');

const desktopPkg = parseJsonOrExit(desktopPkgText, DESKTOP_PKG_JSON, 'apps/desktop/package.json');
const tauriConf = parseJsonOrExit(tauriConfText, TAURI_CONF_JSON, 'apps/desktop/src-tauri/tauri.conf.json');

// --- Canonical value (D-04) ---

const canonical = desktopPkg.version;
const CANONICAL_LABEL = 'apps/desktop/package.json';

if (typeof canonical !== 'string' || canonical.length === 0) {
  console.error(`${CANONICAL_LABEL}: missing or empty "version" field — cannot establish canonical version.`);
  process.exit(1);
}

// --- Compare the other three against canonical, reporting EVERY mismatch ---

const others = [
  {
    label: 'apps/desktop/src-tauri/tauri.conf.json',
    value: tauriConf.version,
  },
  {
    label: 'apps/desktop/src-tauri/Cargo.toml',
    value: extractCargoVersion(desktopCargoText, DESKTOP_CARGO_TOML, 'apps/desktop/src-tauri/Cargo.toml'),
  },
  {
    label: 'apps/native-host/Cargo.toml',
    value: extractCargoVersion(nativeHostCargoText, NATIVE_HOST_CARGO_TOML, 'apps/native-host/Cargo.toml'),
  },
];

for (const { label, value } of others) {
  if (value !== canonical) {
    console.error(
      `${label} version ${JSON.stringify(value)} != canonical ${CANONICAL_LABEL} version ${JSON.stringify(canonical)}`,
    );
    violations++;
  }
}

// --- CI-11: folded msi-absence assertion over tauri.conf.json bundle.targets ---

const bundleTargets = tauriConf?.bundle?.targets;
if (!Array.isArray(bundleTargets)) {
  console.error(
    'apps/desktop/src-tauri/tauri.conf.json: bundle.targets is missing or not an array — cannot verify CI-11 msi-absence.',
  );
  violations++;
} else if (bundleTargets.includes('msi')) {
  console.error(
    'apps/desktop/src-tauri/tauri.conf.json bundle.targets contains "msi" — installerHooks are NSIS-only (CI-11).',
  );
  violations++;
}

if (violations > 0) {
  console.error(`\n${violations} version-consistency/bundle-target violation(s).`);
  process.exit(1);
}

console.log(`OK: all 4 version sources report ${JSON.stringify(canonical)}; bundle.targets has no "msi".`);
