#!/usr/bin/env node
// scripts/lint/lint-sync-capabilities.mjs
//
// Asserts sync-specific invariants in capability JSON:
//   peers.json + peers.json.tmp appear as EXACT LITERAL scope objects in the
//   fs:allow-read-file, fs:allow-write-file, fs:allow-exists, and fs:allow-rename
//   allow lists in default.json — never wildcarded.
//
// Defends HARDEN-01 — peer file paths stay literal (no single-* anywhere near
// peer paths). Uses exact-object matching (not substring) per Pitfall 6.
//
// Scans apps/desktop/src-tauri/capabilities/*.json.

import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const CAP_DIR = join(
  fileURLToPath(new URL('../../', import.meta.url)),
  'apps',
  'desktop',
  'src-tauri',
  'capabilities',
);

// Map of fs permission identifier → required literal path strings that MUST
// appear as exact { "path": "..." } objects in the allow list.
// Do NOT use String.includes() — that would accept "$APPCONFIG/cryptiq/peers.json.malicious".
const REQUIRED_PEERS_SCOPES = {
  'fs:allow-read-file': ['$APPCONFIG/cryptiq/peers.json'],
  'fs:allow-write-file': ['$APPCONFIG/cryptiq/peers.json', '$APPCONFIG/cryptiq/peers.json.tmp'],
  'fs:allow-exists': ['$APPCONFIG/cryptiq/peers.json'],
  'fs:allow-rename': ['$APPCONFIG/cryptiq/peers.json', '$APPCONFIG/cryptiq/peers.json.tmp'],
};

let violations = 0;

function checkCapability(filename) {
  const text = readFileSync(join(CAP_DIR, filename), 'utf8');
  let json;
  try {
    json = JSON.parse(text);
  } catch (e) {
    console.error(`${filename}: invalid JSON — ${e.message}`);
    violations++;
    return;
  }
  if (!Array.isArray(json.permissions)) return;

  // Build a lookup map: identifier → Set of literal path strings from the allow list.
  const allowedPaths = new Map();
  for (const perm of json.permissions) {
    if (typeof perm === 'string') continue;
    if (!perm.allow) continue;
    const isFsPermission = typeof perm.identifier === 'string' && perm.identifier.startsWith('fs:');
    if (!isFsPermission) continue;

    const paths = new Set();
    for (const scope of perm.allow) {
      // Only count exact { "path": "..." } objects — not substrings, not globs.
      if (typeof scope === 'object' && scope !== null && typeof scope.path === 'string') {
        paths.add(scope.path);
      }
    }
    allowedPaths.set(perm.identifier, paths);
  }

  // Assert each required literal appears as an exact object in the allow list.
  for (const [identifier, requiredPaths] of Object.entries(REQUIRED_PEERS_SCOPES)) {
    const actualPaths = allowedPaths.get(identifier);
    if (!actualPaths) {
      // Only report if the capability file is default.json (bootstrap.json has no sync scopes).
      if (filename === 'default.json') {
        console.error(
          `${filename}: permission "${identifier}" not found — ` +
            `required literal scope(s) [${requiredPaths.map((p) => `"${p}"`).join(', ')}] are missing. ` +
            'HARDEN-01: peer file paths must stay literal.',
        );
        violations++;
      }
      continue;
    }
    for (const required of requiredPaths) {
      if (!actualPaths.has(required)) {
        console.error(
          `${filename}: permission "${identifier}" is missing exact literal scope ` +
            `{ "path": "${required}" }. ` +
            'HARDEN-01: peer file paths must stay literal (exact-object check, not substring).',
        );
        violations++;
      }
    }
  }
}

try {
  for (const f of readdirSync(CAP_DIR)) {
    if (f.endsWith('.json')) checkCapability(f);
  }
} catch (e) {
  if (e.code === 'ENOENT') {
    console.error(`Capability directory not found: ${CAP_DIR}`);
    process.exit(1);
  }
  throw e;
}

if (violations > 0) {
  console.error(`\n${violations} capability-sync violation(s).`);
  process.exit(1);
}

console.log('OK: peers.json literal scopes are present and exact in capability allow lists.');
