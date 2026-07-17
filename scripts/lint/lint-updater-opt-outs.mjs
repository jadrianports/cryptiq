#!/usr/bin/env node
// scripts/lint/lint-updater-opt-outs.mjs
//
// UPD-02 (Phase 36) — "Tauri's default comparator is correct; the work is never opting out."
// There are exactly three ways to silently lose the updater's anti-rollback property, and all
// three are silent (no runtime error, no test failure — just a channel that quietly accepts a
// downgrade or an unencrypted transport): `allowDowngrades`, `dangerousInsecureTransportProtocol`,
// and relying on the plugin's IMPLICIT default comparator instead of writing it down explicitly
// in Cryptiq's own source (see commands/update.rs's `is_strictly_newer`/`with_explicit_comparator`).
// This lint makes all three mechanically unreachable.
//
// Reuses lint-csp.mjs's skeleton: self-location via fileURLToPath, JSON.parse(readFileSync) with
// explicit ENOENT/invalid-JSON handling, accumulate-then-report `violations`, exit 1 on any
// violation, `console.log('OK: ...')` on pass.
//
// Three checks:
//   1. CONFIG BAN — tauri.conf.json's `plugins.updater` block (if present) must not contain
//      `allowDowngrades` or `dangerousInsecureTransportProtocol` at any depth. A `plugins.updater`
//      absent entirely (true as of this plan — Plan 08 adds it) is NOT itself a violation. The raw
//      file TEXT is also scanned for both literal strings regardless of JSON structure, so a key
//      nested somewhere the structural check doesn't walk (or a config that fails to parse) still
//      trips the lint. Each banned key is reported as exactly ONE violation (structural-match OR
//      raw-text-match, never both) — see `--fixture` below for why this counting matters.
//   2. SOURCE COMPARATOR PRESENCE — `commands/update.rs`'s source text, with Rust `//`/`///` line
//      comments STRIPPED FIRST, must contain at least one literal `.version_comparator(` call.
//      Comment-stripping matters here specifically: this file's own header prose mentions
//      `.version_comparator(...)` in a doc comment (documenting the single call-site rule) — an
//      unstripped scan would find that comment and stay green even if the real call were deleted.
//      Its ABSENCE (after stripping) is itself a violation — UPD-02 forbids relying on the
//      library's implicit default.
//   3. SOURCE OPT-OUT BAN — in the same comment-stripped text, `dangerous_insecure_transport_protocol`
//      must not be set to `true` in the PRODUCTION portion of the file — i.e. before the first
//      `#[cfg(test)] mod tests` marker. Plan 02's UPD-03 experiment fixtures/tests legitimately
//      reference this identifier inside the test module; production code must never set it.
//
// --fixture <path>: points check 1 (CONFIG BAN) at an arbitrary JSON file instead of the real
// tauri.conf.json — this is how updater-opt-outs-bad.json proves the lint can actually fail.
// Checks 2 and 3 (source-side) always run against the real update.rs regardless of --fixture,
// since the fixture is a config-shaped file, not a source file.

import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const DEFAULT_TAURI_CONF = join(ROOT, 'apps', 'desktop', 'src-tauri', 'tauri.conf.json');
const UPDATE_RS = join(ROOT, 'apps', 'desktop', 'src-tauri', 'src', 'commands', 'update.rs');

const BANNED_CONFIG_KEYS = ['allowDowngrades', 'dangerousInsecureTransportProtocol'];

let violations = 0;

// ── argv: --fixture <path> ─────────────────────────────────────────────────────────────────────
function parseFixtureArg(argv) {
  const idx = argv.indexOf('--fixture');
  if (idx === -1) return null;
  const value = argv[idx + 1];
  if (!value) {
    console.error('lint-updater-opt-outs: --fixture requires a path argument.');
    process.exit(1);
  }
  return resolve(value);
}

const fixturePath = parseFixtureArg(process.argv.slice(2));
const configPath = fixturePath ?? DEFAULT_TAURI_CONF;
const configLabel = fixturePath ? `--fixture ${fixturePath}` : 'tauri.conf.json';

// ── Check 1: CONFIG BAN (structural + raw-text) ────────────────────────────────────────────────

function containsKeyDeep(node, key) {
  if (node === null || typeof node !== 'object') return false;
  if (Object.prototype.hasOwnProperty.call(node, key)) return true;
  for (const value of Object.values(node)) {
    if (containsKeyDeep(value, key)) return true;
  }
  return false;
}

let configRawText;
try {
  configRawText = readFileSync(configPath, 'utf8');
} catch (e) {
  if (e.code === 'ENOENT') {
    console.error(`${configLabel}: file not found at ${configPath}.`);
  } else {
    console.error(`${configLabel}: read error — ${e.message}`);
  }
  console.error('UPD-02: cannot verify the config-side opt-out ban without this file.');
  process.exit(1);
}

let config = null;
let configParseOk = true;
try {
  config = JSON.parse(configRawText);
} catch (e) {
  configParseOk = false;
  console.error(`${configLabel}: invalid JSON — ${e.message}. Falling back to raw-text scan only.`);
}

const updaterBlock = configParseOk ? config?.plugins?.updater : undefined;

for (const key of BANNED_CONFIG_KEYS) {
  const foundStructurally = updaterBlock !== undefined && containsKeyDeep(updaterBlock, key);
  const foundInRawText = configRawText.includes(key);
  if (foundStructurally || foundInRawText) {
    console.error(
      `${configLabel}: forbidden updater opt-out "${key}" present — UPD-02 bans this key ` +
        'unconditionally (it silently disables anti-rollback protection). Remove it.',
    );
    violations++;
  }
}

// ── Checks 2 + 3: source-side (always the real update.rs) ─────────────────────────────────────

let sourceText;
try {
  sourceText = readFileSync(UPDATE_RS, 'utf8');
} catch (e) {
  if (e.code === 'ENOENT') {
    console.error(`update.rs not found: ${UPDATE_RS}`);
  } else {
    console.error(`update.rs: read error — ${e.message}`);
  }
  console.error('UPD-02: cannot verify the source-side comparator/opt-out checks without this file.');
  process.exit(1);
}

// Strip Rust line comments (`//` and `///` both start with `//`) so header/doc prose that merely
// MENTIONS an identifier can never satisfy a presence check, and can never trip an absence-in-
// production check either. Line-based; does not handle `//` inside a string literal — verified
// (2026-07-17) that no string literal in update.rs currently contains the substring `//`.
function stripLineComments(text) {
  return text
    .split('\n')
    .map((line) => {
      const idx = line.indexOf('//');
      return idx === -1 ? line : line.slice(0, idx);
    })
    .join('\n');
}

const strippedSource = stripLineComments(sourceText);

// Check 2: SOURCE COMPARATOR PRESENCE — absence is the violation.
if (!strippedSource.includes('.version_comparator(')) {
  console.error(
    `${UPDATE_RS}: no \`.version_comparator(\` call found outside comments — UPD-02 forbids ` +
      'relying on the plugin\'s implicit default comparator. Route every UpdaterBuilder ' +
      'construction through an explicit `.version_comparator(...)` call (see is_strictly_newer/' +
      'with_explicit_comparator).',
  );
  violations++;
}

// Check 3: SOURCE OPT-OUT BAN — dangerous_insecure_transport_protocol=true must not appear before
// the first `#[cfg(test)] mod tests` marker (the test-module carve-out is deliberate and bounded).
const testModuleMarker = /#\[cfg\(test\)\]\s*\n\s*mod\s+tests/;
const markerMatch = testModuleMarker.exec(strippedSource);
const productionSlice = markerMatch ? strippedSource.slice(0, markerMatch.index) : strippedSource;

const dangerousTrueRe = /dangerous_insecure_transport_protocol\s*[:(]\s*true/;
if (dangerousTrueRe.test(productionSlice)) {
  console.error(
    `${UPDATE_RS}: \`dangerous_insecure_transport_protocol\` is set to true OUTSIDE the ` +
      '`#[cfg(test)] mod tests` module — UPD-02 bans this opt-out in production code. It is ' +
      'only permitted inside the test module (Plan 02\'s UPD-03 experiment fixtures).',
  );
  violations++;
}

if (violations > 0) {
  console.error(`\n${violations} updater opt-out violation(s).`);
  process.exit(1);
}

console.log('OK: updater opt-outs absent; version_comparator is explicit.');
