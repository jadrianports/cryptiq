// apps/site/vitest.config.ts
//
// Single, always-on browser-mode Vitest config (38-RESEARCH.md Open Question 2,
// RESOLVED: every test this phase's D-05/D-08/D-09 decisions need — the
// field-detector assertion, the storage-throw setup, and the real-core round
// trip — benefits from / requires a real DOM + WASM realm, so there is no
// node-only test in this phase's scope that would justify a desktop-style
// vitest.config.ts/vitest.browser.config.ts split).
//
// libsodium-wrappers-sumo ESM workaround (CLAUDE.md decision 26): mirrors
// apps/desktop/vitest.browser.config.ts's alias verbatim.

import { defineConfig } from 'vitest/config';
import { createRequire } from 'node:module';
import { execSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import tailwindcss from '@tailwindcss/vite';
import wasm from 'vite-plugin-wasm';
import topLevelAwait from 'vite-plugin-top-level-await';

const require = createRequire(import.meta.url);
const libsodiumCjs = require.resolve('libsodium-wrappers-sumo');

// Local escape hatch for Playwright's browser binary — mirrors
// apps/desktop/vitest.browser.config.ts (this dev machine has flaky access to
// the Playwright CDN; CI has good network and leaves this unset).
const browserBin = process.env.CRYPTIQ_TEST_BROWSER_BIN;

// 39-02 Task 3: App.svelte now references __CORE_COMMIT_SHA__ (DEMO-07) for
// the first time in source — this test config runs Svelte components through
// its OWN separate Vite pipeline (not apps/site/vite.config.ts), so it needs
// the SAME `define` block or every browser-mode spec that renders App.svelte
// throws `ReferenceError: __CORE_COMMIT_SHA__ is not defined`. Mirrors
// vite.config.ts's block verbatim (single source of truth for the values,
// duplicated here only because Vitest and Vite each resolve their own config).
const REPO_ROOT = fileURLToPath(new URL('../../', import.meta.url));
const coreCommitSha = execSync('git rev-parse HEAD', { cwd: REPO_ROOT }).toString().trim();
const tauriConf = JSON.parse(
  readFileSync(join(REPO_ROOT, 'apps', 'desktop', 'src-tauri', 'tauri.conf.json'), 'utf8'),
) as { version: string };
const appVersion = tauriConf.version;
const releaseTag = `v${appVersion}`;
const installerAsset = `Cryptiq_${appVersion}_x64-setup.exe`;

export default defineConfig({
  plugins: [svelte({ hot: false }), tailwindcss(), wasm(), topLevelAwait()],
  resolve: {
    alias: {
      // Force the working CJS libsodium build (decision 26).
      'libsodium-wrappers-sumo': libsodiumCjs,
    },
  },
  define: {
    __CORE_COMMIT_SHA__: JSON.stringify(coreCommitSha),
    __RELEASE_TAG__: JSON.stringify(releaseTag),
    __INSTALLER_ASSET__: JSON.stringify(installerAsset),
  },
  test: {
    // vitest-browser-svelte's setup wires the render() cleanup + locator API.
    setupFiles: ['vitest-browser-svelte'],
    include: ['src/tests/**/*.spec.ts'],
    // The round-trip test runs real Argon2id at floor params (~1s/run) — give
    // headroom over the default 10s timeout, matching apps/desktop's pattern.
    testTimeout: 20_000,
    browser: {
      enabled: true,
      provider: 'playwright',
      headless: true,
      instances: [
        {
          browser: 'chromium',
          ...(browserBin ? { launch: { executablePath: browserBin } } : {}),
        },
      ],
    },
  },
});
