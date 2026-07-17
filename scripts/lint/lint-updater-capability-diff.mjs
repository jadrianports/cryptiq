#!/usr/bin/env node
// scripts/lint/lint-updater-capability-diff.mjs
//
// UPD-04 (Phase 36) — asserts the capability surface + production CSP block are
// byte-identical to the pre-updater (Phase 35-era) golden snapshot committed at
// __fixtures__/capability-snapshot.json.
//
// MECHANISM DECISION (36-01-PLAN.md, resolving CONTEXT's "planner discretion" item): a
// committed golden byte-snapshot + hash comparison, NOT a CI-step `git diff`. A `git diff`
// assertion depends on ci.yml wiring and a commit range, which breaks the auto-discovery
// no-wiring-needed property this file otherwise gets for free (see run-all.mjs) and silently
// stops asserting anything once the range goes stale. A committed snapshot asserts the
// property in isolation, on every `pnpm lint:custom` run, forever — including on a
// developer's machine before any push.
//
// Reuses lint-csp.mjs's skeleton: self-location via fileURLToPath, JSON.parse(readFileSync)
// with explicit ENOENT/invalid-JSON handling, accumulate-then-report `violations`, exit 1 on
// any violation, `console.log('OK: ...')` on pass.
//
// Three assertion targets:
//   - capabilities/default.json  — full file bytes
//   - capabilities/bootstrap.json — full file bytes
//   - tauri.conf.json#app.security.csp — UTF-8 bytes of the CSP STRING VALUE ONLY, not the
//     whole file (tauri.conf.json legitimately gains a `plugins.updater` block in Plan 08;
//     snapshotting the whole file would make that legitimate addition a false violation).
//
// Fails CLOSED: a missing fixture or a missing target file is a violation, never a pass.

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const FIXTURE_PATH = join(ROOT, 'scripts', 'lint', '__fixtures__', 'capability-snapshot.json');
const DEFAULT_CAPABILITY = join(ROOT, 'apps', 'desktop', 'src-tauri', 'capabilities', 'default.json');
const BOOTSTRAP_CAPABILITY = join(ROOT, 'apps', 'desktop', 'src-tauri', 'capabilities', 'bootstrap.json');
const TAURI_CONF = join(ROOT, 'apps', 'desktop', 'src-tauri', 'tauri.conf.json');

const DRIFT_SENTENCE =
  'UPD-04: the updater must not perturb the capability surface or the production CSP. If this ' +
  'change is intentional, it needs an explicit cross-phase decision — do NOT regenerate the ' +
  'snapshot to make this pass.';

let violations = 0;

function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

// ── Load the golden snapshot. Missing/corrupt fixture is a fail-closed violation. ────────────
let snapshot;
try {
  snapshot = JSON.parse(readFileSync(FIXTURE_PATH, 'utf8'));
} catch (e) {
  if (e.code === 'ENOENT') {
    console.error(`capability-snapshot.json not found: ${FIXTURE_PATH}`);
  } else {
    console.error(`capability-snapshot.json: invalid JSON — ${e.message}`);
  }
  console.error(DRIFT_SENTENCE);
  process.exit(1);
}

// ── Target 1: capabilities/default.json — full file bytes. ───────────────────────────────────
checkFileDigest('capabilities/default.json', DEFAULT_CAPABILITY);

// ── Target 2: capabilities/bootstrap.json — full file bytes. ─────────────────────────────────
checkFileDigest('capabilities/bootstrap.json', BOOTSTRAP_CAPABILITY);

// ── Target 3: tauri.conf.json#app.security.csp — UTF-8 bytes of the CSP string VALUE only. ───
{
  const key = 'tauri.conf.json#app.security.csp';
  let conf;
  try {
    conf = JSON.parse(readFileSync(TAURI_CONF, 'utf8'));
  } catch (e) {
    if (e.code === 'ENOENT') {
      console.error(`tauri.conf.json not found: ${TAURI_CONF}`);
    } else {
      console.error(`tauri.conf.json: invalid JSON — ${e.message}`);
    }
    console.error(DRIFT_SENTENCE);
    violations++;
    conf = null;
  }

  const csp = conf?.app?.security?.csp;
  if (typeof csp !== 'string' || csp.length === 0) {
    console.error('tauri.conf.json: app.security.csp is missing or empty.');
    console.error(DRIFT_SENTENCE);
    violations++;
  } else {
    const expected = snapshot[key];
    const actual = sha256Hex(Buffer.from(csp, 'utf8'));
    if (typeof expected !== 'string') {
      console.error(`capability-snapshot.json: missing expected digest for "${key}".`);
      console.error(DRIFT_SENTENCE);
      violations++;
    } else if (actual !== expected) {
      console.error(`DRIFT DETECTED: ${key}`);
      console.error(`  expected: ${expected}`);
      console.error(`  actual:   ${actual}`);
      console.error(DRIFT_SENTENCE);
      violations++;
    }
  }
}

function checkFileDigest(key, filePath) {
  let bytes;
  try {
    bytes = readFileSync(filePath);
  } catch (e) {
    if (e.code === 'ENOENT') {
      console.error(`${key}: file not found at ${filePath}`);
    } else {
      console.error(`${key}: read error — ${e.message}`);
    }
    console.error(DRIFT_SENTENCE);
    violations++;
    return;
  }

  const expected = snapshot[key];
  const actual = sha256Hex(bytes);
  if (typeof expected !== 'string') {
    console.error(`capability-snapshot.json: missing expected digest for "${key}".`);
    console.error(DRIFT_SENTENCE);
    violations++;
    return;
  }
  if (actual !== expected) {
    console.error(`DRIFT DETECTED: ${key}`);
    console.error(`  expected: ${expected}`);
    console.error(`  actual:   ${actual}`);
    console.error(DRIFT_SENTENCE);
    violations++;
  }
}

if (violations > 0) {
  console.error(`\n${violations} capability/CSP drift violation(s).`);
  process.exit(1);
}

console.log('OK: capability surface + production CSP byte-identical to the pre-updater snapshot.');
