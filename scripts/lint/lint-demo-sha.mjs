#!/usr/bin/env node
// scripts/lint/lint-demo-sha.mjs
//
// DEMO-07 evidentiary integrity (39-01, T-39-01-R). The printed "audit it
// yourself" core commit SHA is the page's central provenance claim, so it
// must be PROVABLY the real build's commit — not just a 40-hex-shaped
// string. This lint greps the BUILT apps/site/dist for the exact literal
// `git rev-parse HEAD` (the same command apps/site/vite.config.ts's `define`
// block uses to bake __CORE_COMMIT_SHA__) and hard-fails if that exact SHA
// is absent from every built file.
//
// NOTE (do not "fix"): `define` only substitutes __CORE_COMMIT_SHA__ where
// source REFERENCES it. At 39-01 nothing in apps/site's source reads that
// global yet (the SHA link is rendered in 39-02's App.svelte), so the SHA is
// NOT yet present in dist and this lint's hard dist-grep assertion will not
// go green until 39-02 lands. It is authored + CI-wired here regardless, so
// the gate is live the moment the SHA is referenced — never a follow-up.
//
// Mirrors lint-demo-containment.mjs's exact structure: zero-dependency
// (node:fs/node:path/node:url/node:child_process only), skip-with-NOTICE +
// exit-0 when apps/site/dist does not exist (safe in the pre-build
// lint:custom auto-discovery chain — scripts/lint/run-all.mjs), recursive
// walkDist over .js/.html, accumulate-then-report violations.
//
// Named `lint-*.mjs` so run-all.mjs auto-discovers it — no hardcoded list to
// drift (HARD-06/D-11).

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = fileURLToPath(new URL('../../', import.meta.url));
const DIST_DIR = join(REPO_ROOT, 'apps', 'site', 'dist');

if (!existsSync(DIST_DIR)) {
  console.log(
    `NOTICE: ${DIST_DIR} does not exist — skipped; run again after \`pnpm --filter @cryptiq/site build\`.`,
  );
  process.exit(0);
}

const headSha = execSync('git rev-parse HEAD', { cwd: REPO_ROOT }).toString().trim();

if (!/^[0-9a-f]{40}$/.test(headSha)) {
  console.error(`\`git rev-parse HEAD\` did not return a 40-hex SHA (got ${JSON.stringify(headSha)}).`);
  process.exit(1);
}

let found = false;

function walkDist(dir) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      walkDist(full);
    } else if (entry.endsWith('.js') || entry.endsWith('.html')) {
      const text = readFileSync(full, 'utf8');
      if (text.includes(headSha)) {
        found = true;
      }
    }
  }
}

walkDist(DIST_DIR);

if (!found) {
  console.error(
    `DEMO-07: the built apps/site/dist does not contain the exact literal \`git rev-parse HEAD\` ` +
      `(${headSha}) in any .js/.html file — the displayed "audit it yourself" SHA (once rendered) ` +
      `must byte-equal the real build commit, never a plausible-looking placeholder.`,
  );
  process.exit(1);
}

console.log(`OK: apps/site/dist contains the exact HEAD SHA (${headSha}) — DEMO-07 evidentiary integrity holds.`);
