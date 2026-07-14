#!/usr/bin/env node
// apps/desktop/scripts/copy-nmhost-binary.mjs
//
// D-06: builds apps/native-host (release) and stages the resulting
// cryptiq-nmhost.exe into apps/desktop/src-tauri/binaries/ with the Tauri
// externalBin target-triple suffix (e.g. cryptiq-nmhost-x86_64-pc-windows-msvc.exe).
// This is genuinely new build-pipeline surface (no existing precedent) — run
// before `tauri build` so the sidecar ships alongside the app.
//
// NOTE: this only STAGES the binary for bundling; Chrome invokes
// cryptiq-nmhost.exe directly via the registry-pointed manifest path, never
// through Tauri's Command.sidecar at runtime (see RESEARCH.md "Native Host
// Bundling via externalBin").

import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// apps/desktop/scripts -> apps/desktop -> apps -> <repo root>
const repoRoot = path.resolve(__dirname, '..', '..', '..');
const nativeHostDir = path.join(repoRoot, 'apps', 'native-host');
const binariesDir = path.join(__dirname, '..', 'src-tauri', 'binaries');

function run(cmd, args, cwd) {
  console.log(`> ${cmd} ${args.join(' ')} (cwd: ${cwd})`);
  execFileSync(cmd, args, { cwd, stdio: 'inherit' });
}

// --target <triple> is OPTIONAL — omitting it preserves today's local-dev, host-triple
// behavior (matches `rustc --print host-tuple`, no output-path change). Passing --target
// (even a triple equal to the host's own) makes Cargo write output under
// target/<triple>/release/ instead of target/release/ — see the releaseDir branch below
// (CI-02: this is the load-bearing Cargo nuance that breaks a naive cross-compile fix).
const targetIdx = process.argv.indexOf('--target');
const explicitTarget = targetIdx !== -1 ? process.argv[targetIdx + 1] : undefined;

// 1. Build the sidecar in release mode (cross-compiled when --target is passed).
const cargoArgs = ['build', '-p', 'cryptiq-nmhost', '--release'];
if (explicitTarget) cargoArgs.push('--target', explicitTarget);
run('cargo', cargoArgs, nativeHostDir);

// 2. Determine the naming triple. Once --target is explicit, reuse THAT value — never
// re-derive via `rustc --print host-tuple`, which always reports the HOST triple regardless
// of --target (the literal CI-02 bug: it broke both macOS cross-build legs identically).
const triple =
  explicitTarget ?? execFileSync('rustc', ['--print', 'host-tuple']).toString().trim();

// .exe only on Windows triples — Tauri's externalBin naming convention cares about exactly
// this one bit; do not build a full triple->extension lookup table.
const ext = triple.includes('-windows-') ? '.exe' : '';

// 3. Copy the compiled binary to src-tauri/binaries/ with the target-triple suffix Tauri's
// externalBin naming convention requires. Cargo's OUTPUT PATH changes the moment --target is
// passed — even when the triple matches the host — so the source dir must branch:
//   no --target  -> target/release/
//   --target X   -> target/X/release/
const releaseDir = explicitTarget
  ? path.join(nativeHostDir, 'target', explicitTarget, 'release')
  : path.join(nativeHostDir, 'target', 'release');

const srcBinary = path.join(releaseDir, `cryptiq-nmhost${ext}`);
if (!existsSync(srcBinary)) {
  throw new Error(`Expected sidecar binary not found at ${srcBinary} — did the cargo build fail silently?`);
}

if (!existsSync(binariesDir)) {
  mkdirSync(binariesDir, { recursive: true });
}

const destBinary = path.join(binariesDir, `cryptiq-nmhost-${triple}${ext}`);
copyFileSync(srcBinary, destBinary);

console.log(`Staged sidecar binary: ${destBinary}`);
