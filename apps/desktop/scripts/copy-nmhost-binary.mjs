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

// 1. Build the sidecar in release mode.
run('cargo', ['build', '-p', 'cryptiq-nmhost', '--release'], nativeHostDir);

// 2. Determine the host target triple (Windows-first per CLAUDE.md).
const triple = execFileSync('rustc', ['--print', 'host-tuple']).toString().trim();

// 3. Copy the compiled binary to src-tauri/binaries/ with the target-triple
// suffix Tauri's externalBin naming convention requires.
const srcBinary = path.join(nativeHostDir, 'target', 'release', 'cryptiq-nmhost.exe');
if (!existsSync(srcBinary)) {
  throw new Error(`Expected sidecar binary not found at ${srcBinary} — did the cargo build fail silently?`);
}

if (!existsSync(binariesDir)) {
  mkdirSync(binariesDir, { recursive: true });
}

const destBinary = path.join(binariesDir, `cryptiq-nmhost-${triple}.exe`);
copyFileSync(srcBinary, destBinary);

console.log(`Staged sidecar binary: ${destBinary}`);
