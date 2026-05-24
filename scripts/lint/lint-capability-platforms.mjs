#!/usr/bin/env node
// scripts/lint/lint-capability-platforms.mjs
//
// Asserts every capability JSON has a `platforms` field with values from the
// Tauri v2 allowed set: macOS, windows, linux, android, iOS.
// Per Pitfall 17 / Tauri v2 docs, omitting `platforms` defaults to ALL platforms.
// Cryptiq v1 is windows + macOS only — accidentally enabling android/iOS would
// silently break (no Mobile target builds yet).

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
const ALLOWED_PLATFORMS = new Set(['macOS', 'windows', 'linux', 'android', 'iOS']);
const CRYPTIQ_V1_PLATFORMS = ['windows', 'macOS']; // per D-15 (Linux dropped)

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

  if (!Array.isArray(json.platforms) || json.platforms.length === 0) {
    console.error(
      `${filename}: missing or empty "platforms" field — defends Pitfall 17. ` +
        `Must be ${JSON.stringify(CRYPTIQ_V1_PLATFORMS)}.`,
    );
    violations++;
    return;
  }
  for (const p of json.platforms) {
    if (!ALLOWED_PLATFORMS.has(p)) {
      console.error(
        `${filename}: platform "${p}" not in Tauri v2 allowed set {macOS, windows, linux, android, iOS}.`,
      );
      violations++;
    }
    if (!CRYPTIQ_V1_PLATFORMS.includes(p)) {
      console.error(
        `${filename}: platform "${p}" is not part of Cryptiq v1 target (windows + macOS only per D-15). Remove it.`,
      );
      violations++;
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
  console.error(`\n${violations} capability-platforms violation(s).`);
  process.exit(1);
}

console.log('OK: every capability has a valid platforms field for Cryptiq v1.');
