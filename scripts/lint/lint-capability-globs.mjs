#!/usr/bin/env node
// scripts/lint/lint-capability-globs.mjs
//
// Asserts capability JSON contains zero single-`*` segments in fs allow lists.
// `**` (recursive) is allowed; single `*` (path-segment wildcard) is a hard error
// — defends GHSA-6mv3-wm7j-h4w5 / Pitfall 1.
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

  for (const perm of json.permissions) {
    if (typeof perm === 'string') continue;
    if (!perm.allow) continue;
    const isFsPermission = typeof perm.identifier === 'string' && perm.identifier.startsWith('fs:');
    if (!isFsPermission) continue;

    for (const scope of perm.allow) {
      const path = scope.path ?? scope;
      if (typeof path !== 'string') continue;

      // Tokenize on `/` and look for any segment that is exactly `*`.
      // `**` is allowed (recursive); a segment like `vault.cryptiq.bak.*` is allowed
      // (file-internal wildcard, not a path-traversing wildcard).
      const segments = path.split('/');
      for (const seg of segments) {
        if (seg === '*') {
          console.error(
            `${filename}: permission "${perm.identifier}" has a single-* segment in path "${path}" — ` +
              'defends Pitfall 1 / GHSA-6mv3-wm7j-h4w5. Use a literal filename or ** for recursive scopes.',
          );
          violations++;
        }
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
  console.error(`\n${violations} capability-glob violation(s).`);
  process.exit(1);
}

console.log('OK: no single-* globs in fs capability allow lists.');
