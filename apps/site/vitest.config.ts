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

export default defineConfig({
  plugins: [svelte({ hot: false }), tailwindcss(), wasm(), topLevelAwait()],
  resolve: {
    alias: {
      // Force the working CJS libsodium build (decision 26).
      'libsodium-wrappers-sumo': libsodiumCjs,
    },
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
