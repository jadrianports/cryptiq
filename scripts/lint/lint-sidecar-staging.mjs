#!/usr/bin/env node
// scripts/lint/lint-sidecar-staging.mjs
//
// Asserts (CI-04): for every job in .github/workflows/*.yml that runs a
// cargo/tauri-build step, a sidecar-staging step (`stage:nmhost` or
// `copy-nmhost-binary.mjs`) appears EARLIER in the SAME job. `tauri-build`'s
// build script resolves `externalBin` entries during `cargo check` itself —
// not only at bundle time — so staging must precede the first cargo step,
// not just the `tauri build`/bundle step (this is the exact class that
// killed CI at `cargo check` for four milestones, per CI-01/CI-02).
//
// Check shape: line-by-line scan, no YAML parser (mirrors
// lint-workflow-sha-pins.mjs). Job boundaries are detected via the
// top-level 2-space `<jobname>:` keys nested directly under `jobs:`.
// Within each job, this records the line index of the FIRST staging match
// and the FIRST cargo/tauri-build match, then fails if the build match
// exists with no earlier staging match in that same job (staging line
// absent, OR staging line index greater than the build line index).
//
// GRACE PERIOD (deliberate, mirrors the ENOENT-tolerance idiom already used
// by lint-workflow-sha-pins.mjs for not-yet-landed dependent work): this is
// an ORDERING check, not a PRESENCE check — it needs a staging step to
// already exist somewhere in the file before it can meaningfully assert
// order. If a workflow file contains ZERO occurrences of the staging
// pattern anywhere, this lint skips that file with a notice instead of
// failing. This is why `node scripts/lint/lint-sidecar-staging.mjs` exits 0
// against today's `.github/workflows/` tree: neither `ci.yml` (single
// un-tiered `ci` job) nor `release.yml` (stages via tauri-action's own
// build, no raw `stage:nmhost` call yet) has been restructured yet — that
// restructuring is Plan 04's scope. Once Plan 04 wires staging into either
// file, the per-job ordering check activates automatically for that file.
//
// Exit 0 = clean (or grace-period skip). Exit 1 = an ordering violation
// found in a file that already has at least one staging step.
//
// Usage: `node scripts/lint/lint-sidecar-staging.mjs` scans the real
// .github/workflows/ tree. `node scripts/lint/lint-sidecar-staging.mjs
// <fixture-path>` checks a single file instead (used by the should-fail
// fixture at scripts/lint/__fixtures__/sidecar-staging-bad.yml).

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = fileURLToPath(new URL('../../', import.meta.url));
const WORKFLOW_DIR = join(REPO_ROOT, '.github', 'workflows');

const STAGE_REGEX = /stage:nmhost|copy-nmhost-binary\.mjs/;
const BUILD_REGEX = /cargo\s|tauri build|tauri-apps\/tauri-action/;
const JOB_NAME_REGEX = /^ {2}([A-Za-z0-9_.-]+):\s*$/;
// Only step `run:`/`uses:` VALUES are checked for staging/build patterns — never a step's
// `name:` label. A `name:` describing "the cargo build" or "stage the sidecar" in prose
// must not itself count as the actual invocation (a real false-positive found and fixed
// during this lint's own self-test against its should-fail fixture).
const RUN_OR_USES_REGEX = /^\s*(?:-\s+)?(?:run|uses):\s*(.*)$/;

let violations = 0;

function checkFile(fullPath, relPath) {
  const text = readFileSync(fullPath, 'utf8');
  const lines = text.split('\n');

  const fileHasStaging = lines.some((line) => {
    if (line.trim().startsWith('#')) return false;
    const m = line.match(RUN_OR_USES_REGEX);
    return m ? STAGE_REGEX.test(m[1]) : false;
  });
  if (!fileHasStaging) {
    console.log(
      `${relPath}: no sidecar-staging step present yet — skipping ordering check ` +
        '(Plan 04 will wire staging into this workflow; see CI-01).',
    );
    return;
  }

  const jobs = new Map(); // jobName -> { stageLine: number|null, buildLine: number|null }
  let inJobsBlock = false;
  let currentJob = null;

  lines.forEach((line, idx) => {
    if (/^jobs:\s*$/.test(line)) {
      inJobsBlock = true;
      currentJob = null;
      return;
    }
    if (!inJobsBlock) return;

    // A non-blank, non-indented line other than `jobs:` itself ends the jobs block
    // (e.g. a trailing top-level key — none exist today, but stay defensive).
    if (/^\S/.test(line) && !/^jobs:\s*$/.test(line)) {
      inJobsBlock = false;
      currentJob = null;
      return;
    }

    const jobMatch = line.match(JOB_NAME_REGEX);
    if (jobMatch) {
      currentJob = jobMatch[1];
      jobs.set(currentJob, { stageLine: null, buildLine: null });
      return;
    }

    if (!currentJob) return;
    if (line.trim().startsWith('#')) return; // commented-out lines don't count

    const m = line.match(RUN_OR_USES_REGEX);
    if (!m) return; // only a step's run:/uses: VALUE counts — never its name: label
    const value = m[1];

    const info = jobs.get(currentJob);
    if (info.stageLine === null && STAGE_REGEX.test(value)) {
      info.stageLine = idx + 1;
    }
    if (info.buildLine === null && BUILD_REGEX.test(value)) {
      info.buildLine = idx + 1;
    }
  });

  for (const [jobName, info] of jobs) {
    if (info.buildLine === null) continue; // job has no cargo/tauri-build step — nothing to check
    const staged = info.stageLine !== null && info.stageLine < info.buildLine;
    if (!staged) {
      console.error(
        `${relPath}:${info.buildLine}: job '${jobName}' runs a cargo/tauri-build step with ` +
          'no preceding sidecar-staging step in the same job (CI-01/CI-04). A staging step ' +
          'in a different job does not count — externalBin must be staged before this job\'s ' +
          'own cargo/build step.',
      );
      violations++;
    }
  }
}

function walk(dir) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      walk(full);
    } else if (entry.endsWith('.yml') || entry.endsWith('.yaml')) {
      checkFile(full, relative(REPO_ROOT, full));
    }
  }
}

const fixtureArg = process.argv[2];

if (fixtureArg) {
  const fullPath = resolve(fixtureArg);
  checkFile(fullPath, fixtureArg);
} else {
  try {
    walk(WORKFLOW_DIR);
  } catch (e) {
    if (e.code === 'ENOENT') {
      console.log(
        'lint-sidecar-staging: no .github/workflows directory found — skipping.',
      );
      process.exit(0);
    }
    throw e;
  }
}

if (violations > 0) {
  console.error(`\n${violations} sidecar-staging ordering violation(s). See CI-01/CI-04.`);
  process.exit(1);
}

console.log('OK: every job with a cargo/tauri-build step stages the sidecar first (or the file is not yet wired for staging).');
