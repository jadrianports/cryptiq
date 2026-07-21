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
//     dist must contain the meta-CSP with `connect-src 'none'` (DEMO-02b) AND
//     `worker-src 'self'` (39-01, DEMO-03/04, T-39-01-T — see below), and
//     must contain zero `type="password"`, zero `<form`, and zero
//     `type="submit"` (DEMO-01 structural lock, mirroring D-04).
//
// AMENDMENT (39-01, T-39-01-T): `Worker(`/`importScripts` were REMOVED from
// FORBIDDEN_API_STRINGS below. Phase 38 banned them outright ("off-thread
// code that can itself egress") for a page with no legitimate Worker use
// case at the time; DEMO-03/04 now requires a real Web Worker for the
// off-main-thread Argon2id demo, which ALWAYS emits the literal `Worker(`
// substring in the built JS (Vite's documented bundling pattern). A
// same-origin, build-time-bundled module Worker cannot egress any
// differently than the main bundle — both are governed by the SAME
// inherited page CSP (a Worker created from a document with no separate CSP
// response header inherits the creating document's policy). Rather than
// weaken containment, this amendment TIGHTENS it: the inherited guarantee
// is now an EXPLICIT, browser-enforced `worker-src 'self'` directive
// (index.html), and REQUIRED_WORKER_CSP_SUBSTRING below asserts it survives
// the build — mirroring REQUIRED_CSP_SUBSTRING exactly. This is a MINIMAL,
// reviewable two-part diff (delete 2 array entries, add 1 assertion) —
// never a wholesale rewrite that could silently drop another check.
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

// (a) Forbidden network/storage APIs (D-07). This is a build-time backstop, NOT
// the primary control — the meta-CSP `connect-src 'none'` (browser-enforced) is
// what structurally guarantees zero egress. A substring denylist cannot be
// exhaustive (WR-04), so it errs toward the vectors most likely to slip past a
// reviewer; the CSP catches anything this list misses. Substring match is
// intentionally conservative: a false positive fails safe (surface-and-decide),
// never a silent allowlist.
// NOTE: bare `import(` is deliberately NOT listed — dynamic import is legitimate
// ESM the Vite bundle may emit; denylisting it would false-fire on valid output.
// Code-loading egress is instead covered by `importScripts` (worker context) and
// the CSP's `script-src 'self'`.
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
  'RTCPeerConnection', // WebRTC data/media egress
  'ping="', // <a ping="…"> beacon on navigation
];

// (b) DEMO-01 structural belt-and-suspenders — zero password input, zero form,
// zero submit control over the BUILT html. LIMITATION (WR-01): apps/site is a
// client-rendered Svelte SPA, so the shell markup lives in the JS bundle, not in
// the static dist/index.html — this HTML scan therefore only catches a
// reintroduced SSR/prerendered/hand-authored form or password input, not one
// added to App.svelte. The authoritative DEMO-01 control is the browser-mode
// `containment.spec.ts` test that runs the real extension detector against the
// rendered DOM; this string check is a cheap, additional static guard only.
const FORBIDDEN_STRUCTURAL_STRINGS = ['type="password"', '<form', 'type="submit"'];

const REQUIRED_CSP_SUBSTRING = "connect-src 'none'";
// 39-01, DEMO-03/04, T-39-01-T — the explicit worker-src tightening that
// accompanies the Worker(/importScripts removal above (see header comment).
const REQUIRED_WORKER_CSP_SUBSTRING = "worker-src 'self'";

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

  if (!text.includes(REQUIRED_WORKER_CSP_SUBSTRING)) {
    console.error(
      `${htmlFile}: missing required meta-CSP directive ${JSON.stringify(REQUIRED_WORKER_CSP_SUBSTRING)} — DEMO-03 Worker containment did not survive the build.`,
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
  `OK: apps/site/dist is clean — no forbidden network/storage APIs, meta-CSP (${REQUIRED_CSP_SUBSTRING}, ${REQUIRED_WORKER_CSP_SUBSTRING}) survived the build, and no password input/form/submit control.`,
);
