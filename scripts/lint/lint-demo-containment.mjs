#!/usr/bin/env node
// scripts/lint/lint-demo-containment.mjs
//
// DEMO-02 / D-07 (Phase 38, 38-CONTEXT.md) — "nothing persists — structurally,
// not by promise". This lint scans the BUILT apps/site/dist bundle (not source)
// and hard-fails on any of two independent assertion groups:
//
// (a) FORBIDDEN-API grep — a recursive text scan of every .js/.html file under
//     dist for the literal strings: localStorage, sessionStorage, indexedDB,
//     document.cookie, fetch(, XMLHttpRequest, sendBeacon, WebSocket,
//     EventSource. Any occurrence means the shipped bundle could touch
//     persistence or the network — a forbidden-by-design property for the
//     public demo page (D-07). Substring match is intentionally conservative:
//     a false positive fails safe; it is a surface-it-and-decide moment, not a
//     silent allowlist.
//
// (b) CSP-SURVIVAL + structural belt-and-suspenders — every .html file under
//     dist must contain the meta-CSP with `connect-src 'none'` (DEMO-02b), and
//     must contain zero `type="password"`, zero `<form`, and zero
//     `type="submit"` (DEMO-01 structural lock, mirroring D-04).
//
// Skips gracefully (NOTICE + exit 0) when apps/site/dist does not exist yet —
// safe in the pre-build lint:custom auto-discovery chain (scripts/lint/run-all.mjs),
// mirroring lint-vite-key-leak.mjs's Stage B pre-build skip.
//
// Zero-dependency (node:fs/node:path/node:url only), same accumulate-then-report
// idiom as every lint-*.mjs script in this directory.

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = fileURLToPath(new URL('../../', import.meta.url));
const DIST_DIR = join(REPO_ROOT, 'apps', 'site', 'dist');

// (a) Forbidden network/storage APIs — D-07's exact list.
const FORBIDDEN_API_STRINGS = [
  'localStorage',
  'sessionStorage',
  'indexedDB',
  'document.cookie',
  'fetch(',
  'XMLHttpRequest',
  'sendBeacon',
  'WebSocket',
  'EventSource',
];

// (b) DEMO-01 structural belt-and-suspenders — zero password input, zero form,
// zero submit control, over the BUILT html (mirrors D-04's source-level lock).
const FORBIDDEN_STRUCTURAL_STRINGS = ['type="password"', '<form', 'type="submit"'];

const REQUIRED_CSP_SUBSTRING = "connect-src 'none'";

if (!existsSync(DIST_DIR)) {
  console.log(
    `NOTICE: ${DIST_DIR} does not exist — skipped; run again after \`pnpm --filter @cryptiq/site build\`.`,
  );
  process.exit(0);
}

let violations = 0;
const htmlFiles = [];

function walkDist(dir) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      walkDist(full);
    } else if (entry.endsWith('.js') || entry.endsWith('.html')) {
      const text = readFileSync(full, 'utf8');

      for (const needle of FORBIDDEN_API_STRINGS) {
        if (text.includes(needle)) {
          console.error(
            `${full}: built output contains forbidden network/storage API ${JSON.stringify(needle)} — DEMO-02 (D-07) zero-persistence/zero-network violation.`,
          );
          violations++;
        }
      }

      if (entry.endsWith('.html')) {
        htmlFiles.push(full);
      }
    }
  }
}

walkDist(DIST_DIR);

if (htmlFiles.length === 0) {
  console.error(`${DIST_DIR}: no .html files found under dist — cannot verify meta-CSP survival.`);
  process.exit(1);
}

for (const htmlFile of htmlFiles) {
  const text = readFileSync(htmlFile, 'utf8');

  if (!text.includes(REQUIRED_CSP_SUBSTRING)) {
    console.error(
      `${htmlFile}: missing required meta-CSP directive ${JSON.stringify(REQUIRED_CSP_SUBSTRING)} — DEMO-02b zero-network browser-level enforcement did not survive the build.`,
    );
    violations++;
  }

  for (const needle of FORBIDDEN_STRUCTURAL_STRINGS) {
    if (text.includes(needle)) {
      console.error(
        `${htmlFile}: built output contains forbidden structural string ${JSON.stringify(needle)} — DEMO-01 anti-phishing shape violation (reintroduced password input/form/submit control).`,
      );
      violations++;
    }
  }
}

if (violations > 0) {
  console.error(`\n${violations} demo-containment violation(s).`);
  process.exit(1);
}

console.log(
  `OK: apps/site/dist is clean — no forbidden network/storage APIs, meta-CSP (${REQUIRED_CSP_SUBSTRING}) survived the build, and no password input/form/submit control.`,
);
