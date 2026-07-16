#!/usr/bin/env node
// scripts/lint/lint-workflow-sha-pins.mjs
//
// Asserts every `uses:` reference in .github/workflows/*.yml is a
// 40-character commit SHA, not a version tag.
//
// Defends against CVE-2025-30066 (tj-actions/changed-files retag attack) and
// Pitfall 14. Exit 0 = clean. Exit 1 = violations found (CI fails the job).
//
// FAILS CLOSED on a missing/unreadable .github/workflows/. Plan 01-05 originally
// overrode Snippet 5's ENOENT behavior to exit 0 with a notice while Wave 3 had
// not yet landed the workflow files (Plan 01-06). That scaffold long outlived its
// purpose and became a permanent fail-open: a typo'd path, a directory rename, or
// a checkout that didn't fetch .github/ would print "skipping", exit 0, and
// `pnpm lint:custom` would go green having verified NOTHING. Its catch was also
// broader than intended — wrapping walk() meant an ENOENT from readFileSync inside
// checkFile (a file removed mid-walk) short-circuited the whole lint to a green
// skip too. lint-supply-chain.mjs calls readdirSync bare and correctly explodes;
// the two lints must not disagree about whether a missing workflow dir is a pass.

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const WORKFLOW_DIR = join(
  fileURLToPath(new URL('../../', import.meta.url)),
  '.github',
  'workflows',
);
const SHA_REGEX = /^[a-f0-9]{40}$/;
// YAML step lines have two forms: `uses: foo@bar` and `- uses: foo@bar`.
// trim() strips leading whitespace; the optional `-\s+` covers the list-item prefix.
// Snippet 5's `^uses:` was a latent bug — it silently passed on every real workflow
// file (which always uses the list-item form). Caught here in Plan 01-05 self-test.
const USES_REGEX = /^(?:-\s+)?uses:\s+(\S+)/;

let violations = 0;

function checkFile(path) {
  const text = readFileSync(path, 'utf8');
  const lines = text.split('\n');
  lines.forEach((line, idx) => {
    const trimmed = line.trim();
    // Skip commented-out lines (grep-gate-hygiene rule from CLAUDE.md).
    if (trimmed.startsWith('#')) return;
    const m = trimmed.match(USES_REGEX);
    if (!m) return;
    const ref = m[1];
    // D-01d (Phase 35): narrow the local-ref allowlist to reusable WORKFLOWS specifically —
    // ./.github/workflows/<name>.yml or .yaml — rather than any ./ or ../ prefixed uses:.
    // Defense-in-depth tightening; the broader `./`/`../` allowlist previously here already
    // passed `uses: ./.github/workflows/ci.yml` before this patch (verified, RESEARCH.md item 2).
    if (/^\.\/\.github\/workflows\/.*\.ya?ml$/.test(ref)) return;
    // Docker actions are out of scope for SHA pinning.
    if (ref.startsWith('docker://')) return;

    const atIdx = ref.lastIndexOf('@');
    if (atIdx === -1) {
      console.error(`${path}:${idx + 1}: uses without @ref: ${ref}`);
      violations++;
      return;
    }
    const refValue = ref.slice(atIdx + 1);
    if (!SHA_REGEX.test(refValue)) {
      console.error(
        `${path}:${idx + 1}: ${ref} is not pinned to a 40-char SHA (got "${refValue}"). ` +
          'Resolve via `gh api repos/<org>/<action>/git/refs/tags/<tag>` and replace with @<40-char-sha>  # <tag>.',
      );
      violations++;
    }
  });
}

function walk(dir) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      walk(full);
    } else if (entry.endsWith('.yml') || entry.endsWith('.yaml')) {
      checkFile(full);
    }
  }
}

// D-01d (Phase 35): fixtureArg CLI branch, mirroring lint-sidecar-staging.mjs — lints a single
// fixture path directly (used by the sha-pins-good.yml / sha-pins-bad.yml proof pair) instead of
// walking .github/workflows/. No-arg invocation (the run-all.mjs auto-discovery / CI path, D-11)
// is unchanged below.
const fixtureArg = process.argv[2];

if (fixtureArg) {
  checkFile(resolve(fixtureArg));
} else {
  // No ENOENT catch: .github/workflows MUST exist. A missing/unreadable directory is a
  // violation of the CVE-2025-30066 gate, not a reason to report a pass (see header).
  walk(WORKFLOW_DIR);
}

if (violations > 0) {
  console.error(
    `\n${violations} workflow SHA-pin violation(s). Every uses: must be @<40-char-SHA>. See CVE-2025-30066 / Pitfall 14.`,
  );
  process.exit(1);
}

console.log('OK: all workflow uses: are SHA-pinned.');
