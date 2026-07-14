#!/usr/bin/env node
// scripts/lint/lint-vite-key-leak.mjs
//
// CI-10 — GHSA-2rcp-jvr4-r259 (Tauri updater-signing-key leak via Vite envPrefix)
//
// Tauri's own docs once recommended `envPrefix: ['VITE_', 'TAURI_']` in vite.config.ts.
// Vite's envPrefix match is a literal `startsWith` prefix check (no glob/wildcard
// support) — a bare `TAURI_` prefix bundles TAURI_SIGNING_PRIVATE_KEY (and its
// _PASSWORD sibling) into shipped frontend JS via import.meta.env, readable by anyone
// who downloads the app. This MUST land before the Phase-36 signing key exists —
// gitleaks is structurally blind to this leak (the key lands in gitignored dist/,
// never committed).
//
// Stage A (config-time, ALWAYS runs): extracts the `envPrefix` array literal from
// apps/desktop/vite.config.ts via regex (no TS/AST parser — a single array literal
// does not justify the project's first TS-parser dependency) and fails if any prefix
// is the bare literal `TAURI_`/`''`, or a startsWith-ancestor of
// TAURI_SIGNING_PRIVATE_KEY / TAURI_SIGNING_PRIVATE_KEY_PASSWORD.
//
// Stage B (post-build, runs ONLY if apps/desktop/dist/ exists): recursively greps
// built .js files for the literal TAURI_SIGNING_PRIVATE_KEY(_PASSWORD) or the
// minisign secret-key preamble `untrusted comment:`, as defense-in-depth for any
// OTHER leak mechanism (a `define:` block, a hardcoded fallback) even with a clean
// envPrefix. Skips gracefully (prints a notice, does NOT fail) when dist/ is absent —
// safe to run in a job where the frontend hasn't been built yet.
//
// Zero-dependency (node:fs/node:path/node:url only), mirrors the existing lint idiom
// (see lint-supply-chain.mjs / lint-csp.mjs): readOrExit-style guards, violation
// accumulation, single OK/exit-1 report.

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = fileURLToPath(new URL('../../', import.meta.url));
const DEFAULT_VITE_CONFIG = join(REPO_ROOT, 'apps', 'desktop', 'vite.config.ts');
// Override hook for the should-fail fixture self-test (VITE_KEY_LEAK_CONFIG is a
// path relative to the repo root).
const VITE_CONFIG_PATH = process.env.VITE_KEY_LEAK_CONFIG
  ? join(REPO_ROOT, process.env.VITE_KEY_LEAK_CONFIG)
  : DEFAULT_VITE_CONFIG;
const DIST_DIR = join(REPO_ROOT, 'apps', 'desktop', 'dist');

const SENSITIVE_VARS = ['TAURI_SIGNING_PRIVATE_KEY', 'TAURI_SIGNING_PRIVATE_KEY_PASSWORD'];
const DIST_FORBIDDEN_STRINGS = [...SENSITIVE_VARS, 'untrusted comment:'];

let violations = 0;

// --- Stage A: envPrefix config-time guard ---

let configText;
try {
  configText = readFileSync(VITE_CONFIG_PATH, 'utf8');
} catch (e) {
  if (e.code === 'ENOENT') {
    console.error(`vite config not found: ${VITE_CONFIG_PATH}`);
    process.exit(1);
  }
  throw e;
}

const envPrefixMatch = /envPrefix:\s*\[([^\]]*)\]/.exec(configText);
if (!envPrefixMatch) {
  console.error(
    `${VITE_CONFIG_PATH}: could not find an \`envPrefix: [...]\` array literal — cannot verify CI-10.`,
  );
  process.exit(1);
}

const prefixes = envPrefixMatch[1]
  .split(',')
  .map((entry) => entry.trim())
  .filter((entry) => entry.length > 0)
  .map((entry) => {
    const m = /^['"](.*)['"]$/.exec(entry);
    return m ? m[1] : entry;
  });

// Vite's envPrefix match is a literal startsWith check — a prefix "forbids" a
// sensitive var if that var would match (i.e. start with) the prefix.
function isForbiddenAncestor(prefix, sensitiveVar) {
  return sensitiveVar.startsWith(prefix);
}

for (const prefix of prefixes) {
  if (prefix === 'TAURI_' || prefix === '') {
    console.error(
      `${VITE_CONFIG_PATH}: envPrefix contains ${JSON.stringify(prefix)} — a bare "TAURI_"/"" prefix ` +
        `would bundle TAURI_SIGNING_PRIVATE_KEY (and TAURI_SIGNING_PRIVATE_KEY_PASSWORD) into shipped ` +
        `frontend JS via import.meta.env (GHSA-2rcp-jvr4-r259).`,
    );
    violations++;
    continue;
  }
  for (const sensitiveVar of SENSITIVE_VARS) {
    if (isForbiddenAncestor(prefix, sensitiveVar)) {
      console.error(
        `${VITE_CONFIG_PATH}: envPrefix entry ${JSON.stringify(prefix)} is a startsWith-ancestor of ` +
          `${sensitiveVar} — would expose it to import.meta.env in built frontend JS (GHSA-2rcp-jvr4-r259).`,
      );
      violations++;
    }
  }
}

// --- Stage B: post-build dist/**/*.js grep (skips gracefully if dist/ absent) ---

if (!existsSync(DIST_DIR)) {
  console.log(
    `NOTICE: ${DIST_DIR} does not exist — Stage B (built-output secret grep) skipped. ` +
      'Run again after `vite build` / `tauri build` to exercise Stage B.',
  );
} else {
  function walkDist(dir) {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      const stat = statSync(full);
      if (stat.isDirectory()) {
        walkDist(full);
      } else if (entry.endsWith('.js')) {
        const text = readFileSync(full, 'utf8');
        for (const needle of DIST_FORBIDDEN_STRINGS) {
          if (text.includes(needle)) {
            console.error(
              `${full}: built output contains forbidden string ${JSON.stringify(needle)} — signing-key leak (GHSA-2rcp-jvr4-r259).`,
            );
            violations++;
          }
        }
      }
    }
  }
  walkDist(DIST_DIR);
}

if (violations > 0) {
  console.error(`\n${violations} vite-key-leak violation(s).`);
  process.exit(1);
}

console.log('OK: envPrefix has no TAURI_ signing-key exposure; dist/**/*.js (if built) is clean.');
