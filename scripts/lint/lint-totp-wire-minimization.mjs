#!/usr/bin/env node
// scripts/lint/lint-totp-wire-minimization.mjs
//
// TOTP-08 GATE (D-15): the stored TOTP seed must NEVER reach the browser
// extension or the native-messaging host — a lower-trust surface than the
// desktop app. This is a build-time grep tripwire mirroring the v3.1 RPC-02
// CVV/PAN wire-minimization precedent: discipline alone is insufficient
// because apps/extension REDECLARES its thin-client EntryMatchMetadata/
// FillRequest types by hand, so a future dev could widen them unnoticed.
//
// Scans ONLY these three source roots (never target/, node_modules/, .wxt/ —
// broadening the walk to parent dirs would self-defeat the tripwire):
//   - apps/extension/src
//   - apps/extension/entrypoints
//   - apps/native-host/src
//
// Any `.ts`/`.svelte`/`.rs` file containing a `totp` token (case-insensitive,
// word-boundary) fails the build.

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = fileURLToPath(new URL('../../', import.meta.url));

const SCAN_ROOTS = [
  join(REPO_ROOT, 'apps/extension/src'),
  join(REPO_ROOT, 'apps/extension/entrypoints'),
  join(REPO_ROOT, 'apps/native-host/src'),
];

const SCANNED_EXTENSIONS = new Set(['.ts', '.svelte', '.rs']);
const TOTP_PATTERN = /\btotp\b/i;

let violations = 0;

function walk(dir) {
  let entries;
  try {
    entries = readdirSync(dir);
  } catch (e) {
    if (e.code === 'ENOENT') {
      // A scan root may legitimately not exist yet — not a lint failure.
      return;
    }
    throw e;
  }

  for (const entry of entries) {
    const fullPath = join(dir, entry);
    const stat = statSync(fullPath);
    if (stat.isDirectory()) {
      walk(fullPath);
      continue;
    }

    const dotIndex = entry.lastIndexOf('.');
    const ext = dotIndex === -1 ? '' : entry.slice(dotIndex);
    if (!SCANNED_EXTENSIONS.has(ext)) {
      continue;
    }

    const contents = readFileSync(fullPath, 'utf8');
    const lines = contents.split('\n');
    lines.forEach((line, idx) => {
      if (TOTP_PATTERN.test(line)) {
        console.error(
          `${fullPath}:${String(idx + 1)}: TOTP-08 violation — 'totp' reference found in a lower-trust surface (extension/native-host). The TOTP seed must never reach this boundary (D-15).`,
        );
        violations++;
      }
    });
  }
}

for (const root of SCAN_ROOTS) {
  walk(root);
}

if (violations > 0) {
  console.error(`\n${violations} TOTP-08 wire-minimization violation(s).`);
  process.exit(1);
}

console.log(
  'OK: zero "totp" references in apps/extension/{src,entrypoints} and apps/native-host/src (TOTP-08 / D-15).',
);
