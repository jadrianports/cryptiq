#!/usr/bin/env node
// scripts/lint/lint-workspace-scripts.mjs
//
// CI-09 — pnpm's `-r run typecheck` silently SKIPS a workspace package that lacks a
// `typecheck` script (pnpm's own documented behavior: "If a package doesn't have the
// command, it is skipped. If none of the packages have the command, the command
// fails.") There is no `--fail-on-missing` counterpart to `--if-present`. This already
// bit this project for real: @cryptiq/extension's typecheck script was originally
// named `compile`, so `pnpm -r run typecheck` silently ran zero type-checks against
// the extension for the duration it carried the wrong name.
//
// Fix: enumerate the ACTUAL pnpm-workspace.yaml `packages:` globs (no hardcoded
// package-name allowlist — an allowlist silently misses the Nth app the same way
// pnpm's skip silently missed the 4th) and assert every resolved package.json
// declares a non-empty `scripts.typecheck`. Directories with no package.json (e.g.
// apps/native-host, a Rust-only workspace member) are correctly not pnpm workspace
// members and are skipped, not flagged.
//
// Zero-dependency (node:fs/node:path/node:url only), mirrors the existing lint idiom
// (hand-walked YAML line scan, no YAML/glob parser — see lint-supply-chain.mjs).

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = fileURLToPath(new URL('../../', import.meta.url));
const WORKSPACE_YAML = join(REPO_ROOT, 'pnpm-workspace.yaml');
// Root-override hook for the should-fail fixture self-test: when set, the override
// path itself is treated as a single package directory to check directly (bypassing
// pnpm-workspace.yaml glob enumeration) — mirrors how the fixture root IS a package
// dir with its own package.json.
const OVERRIDE_ROOT = process.env.WORKSPACE_SCRIPTS_ROOT;

function readOrExit(path, label) {
  try {
    return readFileSync(path, 'utf8');
  } catch (e) {
    if (e.code === 'ENOENT') {
      console.error(`${label} not found: ${path}`);
      process.exit(1);
    }
    throw e;
  }
}

// Hand-walked YAML line scan for the `packages:` list block — no YAML parser
// dependency, matching the project's established idiom (lint-supply-chain.mjs).
function extractPackageGlobs(text) {
  const lines = text.split('\n');
  let inBlock = false;
  const globs = [];
  for (const line of lines) {
    if (/^packages:\s*$/.test(line)) {
      inBlock = true;
      continue;
    }
    if (inBlock) {
      const itemMatch = /^\s*-\s+['"]([^'"]+)['"]/.exec(line);
      if (itemMatch) {
        globs.push(itemMatch[1]);
        continue;
      }
      if (/^[A-Za-z]/.test(line) && line.trim().length > 0) {
        // New top-level key — block ended.
        break;
      }
      // Blank/whitespace-only lines inside the block: keep scanning.
    }
  }
  return globs;
}

let packageDirs;

if (OVERRIDE_ROOT) {
  packageDirs = [join(REPO_ROOT, OVERRIDE_ROOT)];
} else {
  const wsText = readOrExit(WORKSPACE_YAML, 'pnpm-workspace.yaml');
  const globs = extractPackageGlobs(wsText);
  if (globs.length === 0) {
    console.error('pnpm-workspace.yaml: no `packages:` glob entries found — cannot enumerate workspace members.');
    process.exit(1);
  }

  packageDirs = [];
  for (const glob of globs) {
    // Only the project's actual glob shape (`<dir>/*`) is supported — enumerating an
    // arbitrary glob library is unneeded complexity for two fixed entries.
    const globMatch = /^(.*)\/\*$/.exec(glob);
    if (!globMatch) {
      console.error(
        `pnpm-workspace.yaml: unsupported packages glob shape ${JSON.stringify(glob)} — expected "<dir>/*".`,
      );
      process.exit(1);
    }
    const parentDir = join(REPO_ROOT, globMatch[1]);
    for (const entry of readdirSync(parentDir)) {
      const full = join(parentDir, entry);
      if (statSync(full).isDirectory()) {
        packageDirs.push(full);
      }
    }
  }
}

let violations = 0;
let checked = 0;

for (const dir of packageDirs) {
  const pkgJsonPath = join(dir, 'package.json');
  if (!existsSync(pkgJsonPath)) {
    // Rust-only workspace dirs (e.g. apps/native-host) are correctly not pnpm
    // workspace members — skip, don't flag.
    continue;
  }
  checked++;

  let pkg;
  try {
    pkg = JSON.parse(readFileSync(pkgJsonPath, 'utf8'));
  } catch (e) {
    console.error(`${pkgJsonPath}: invalid JSON — ${e.message}`);
    violations++;
    continue;
  }

  const typecheckScript = pkg?.scripts?.typecheck;
  if (typeof typecheckScript !== 'string' || typecheckScript.length === 0) {
    console.error(
      `${pkgJsonPath}: missing a non-empty scripts.typecheck — pnpm -r run typecheck would silently SKIP this package (CI-09).`,
    );
    violations++;
  }
}

if (checked === 0) {
  console.error('lint-workspace-scripts: no package.json found under any resolved workspace directory — nothing to check.');
  process.exit(1);
}

if (violations > 0) {
  console.error(`\n${violations} workspace-scripts violation(s).`);
  process.exit(1);
}

console.log(`OK: all ${checked} workspace package(s) declare scripts.typecheck.`);
