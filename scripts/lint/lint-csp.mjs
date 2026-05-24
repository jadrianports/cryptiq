#!/usr/bin/env node
// scripts/lint/lint-csp.mjs
//
// Asserts the production CSP in apps/desktop/src-tauri/tauri.conf.json is strict:
//   - script-src has no 'unsafe-inline' / 'unsafe-eval' (but 'wasm-unsafe-eval' is OK)
//   - no localhost:PORT, ws://, or 127.0.0.1 anywhere in the production csp
//   - default-src 'self' is present
//   - http://... is forbidden EXCEPT Tauri's internal protocol origins
//     http://asset.localhost and http://ipc.localhost (used by WebView2 / WKWebView
//     asset loader and IPC scheme — NOT real network endpoints)
//   - devCsp exists as a separate field and differs from csp
//
// Defends SEC-13 (no dev-relaxation leakage into prod).

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const TAURI_CONF = join(
  fileURLToPath(new URL('../../', import.meta.url)),
  'apps',
  'desktop',
  'src-tauri',
  'tauri.conf.json',
);

// Note: 'wasm-unsafe-eval' is REQUIRED in production for libsodium WASM.
// Only the bare 'unsafe-eval' and 'unsafe-inline' are forbidden in script-src.
const PROD_CSP_FORBIDDEN_SCRIPT_SRC_TOKENS = ["'unsafe-inline'", "'unsafe-eval'"];

// These substrings indicate a dev-server leak anywhere in the production csp.
const PROD_CSP_FORBIDDEN_GLOBAL_SUBSTRINGS = ['ws://', '127.0.0.1'];

// Tauri internal protocol origins (NOT dev-server leaks).
const TAURI_INTERNAL_ORIGINS = ['http://asset.localhost', 'http://ipc.localhost'];

let violations = 0;

let conf;
try {
  conf = JSON.parse(readFileSync(TAURI_CONF, 'utf8'));
} catch (e) {
  if (e.code === 'ENOENT') {
    console.error(`tauri.conf.json not found: ${TAURI_CONF}`);
  } else {
    console.error(`tauri.conf.json: invalid JSON — ${e.message}`);
  }
  process.exit(1);
}

const csp = conf?.app?.security?.csp;
const devCsp = conf?.app?.security?.devCsp;

if (typeof csp !== 'string' || csp.length === 0) {
  console.error('tauri.conf.json: app.security.csp is missing or empty (production CSP required).');
  process.exit(1);
}
if (typeof devCsp !== 'string' || devCsp.length === 0) {
  console.error(
    'tauri.conf.json: app.security.devCsp is missing — must be a separate field for dev relaxations (SEC-13).',
  );
  violations++;
}
if (devCsp === csp) {
  console.error(
    'tauri.conf.json: app.security.devCsp must differ from production csp (SEC-13 — dev-relaxation must be confined to the dev field).',
  );
  violations++;
}

// 1. default-src 'self' presence
if (!csp.includes("default-src 'self'")) {
  console.error("production csp: missing `default-src 'self'` directive.");
  violations++;
}

// 2. Extract script-src directive and scan tokens
const directives = csp.split(';').map((d) => d.trim());
const scriptSrcDirective = directives.find((d) => d.startsWith('script-src'));
if (!scriptSrcDirective) {
  console.error('production csp: missing `script-src` directive.');
  violations++;
} else {
  // 'wasm-unsafe-eval' is allowed; strip it before checking for 'unsafe-eval' (substring overlap).
  const scriptSrcWithoutWasm = scriptSrcDirective.replace("'wasm-unsafe-eval'", '');
  for (const tok of PROD_CSP_FORBIDDEN_SCRIPT_SRC_TOKENS) {
    if (scriptSrcWithoutWasm.includes(tok)) {
      console.error(
        `production csp script-src contains forbidden token ${tok} — defends SEC-13 (no dev relaxations in prod).`,
      );
      violations++;
    }
  }
}

// 3. Global substring scan for ws:// and 127.0.0.1
for (const tok of PROD_CSP_FORBIDDEN_GLOBAL_SUBSTRINGS) {
  if (csp.includes(tok)) {
    console.error(
      `production csp contains forbidden substring "${tok}" — defends SEC-13 (no dev-server origin leaks).`,
    );
    violations++;
  }
}

// 4. http:// scan, excluding Tauri's internal protocol origins.
let cspMinusInternal = csp;
for (const origin of TAURI_INTERNAL_ORIGINS) {
  cspMinusInternal = cspMinusInternal.split(origin).join('');
}
if (cspMinusInternal.includes('http://')) {
  console.error(
    'production csp contains an http://... origin other than Tauri internal (http://asset.localhost / http://ipc.localhost) — defends SEC-13.',
  );
  violations++;
}

// 5. localhost:PORT scan (Tauri internal hosts have no port; dev server is :1420)
if (/localhost:\d+/.test(csp)) {
  console.error(
    'production csp contains a localhost:PORT origin — dev-server leak (defends SEC-13). Move to devCsp only.',
  );
  violations++;
}

if (violations > 0) {
  console.error(`\n${violations} csp violation(s).`);
  process.exit(1);
}

console.log('OK: production CSP is strict; dev relaxations confined to devCsp block.');
