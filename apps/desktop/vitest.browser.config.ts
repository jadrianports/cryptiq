// apps/desktop/vitest.browser.config.ts
//
// Layer-2 component-test harness (TEST-09 / 04-07). Vitest browser mode with the
// Playwright provider + vitest-browser-svelte, run via:
//   pnpm --filter @cryptiq/desktop run test:components
//
// WHY THIS RUNNER (supersedes plan 04-02's @playwright/experimental-ct-svelte choice):
//   The 04-07 specs assert on SHARED in-process singletons — the FakeVaultStorageAdapter
//   spy (saveCount), the `ui` toast queue, and the `vaultSession`/`view` rune state.
//   Playwright component-testing runs the spec in Node and the mounted component in a
//   SEPARATE browser process, so those singletons are different instances and the
//   assertions cannot work (and `.svelte.ts` rune modules don't compile in Playwright's
//   Node transform → `$state is not defined`). Vitest browser mode runs the spec AND
//   the component in ONE browser realm through Vite, so the singletons are shared and
//   runes compile via @sveltejs/vite-plugin-svelte. The browser is still driven by
//   Playwright (the `provider: 'playwright'`), honoring the locked "Playwright
//   (components)" stack choice. User-approved harness switch, 2026-05-30.
//
// The node-environment unit/adapter tests keep running under the default vitest.config.ts
// (`pnpm test`, *.test.ts). This config owns *.spec.ts only — no overlap.
//
// libsodium-wrappers-sumo ESM workaround (CLAUDE.md decision 26): the published .mjs
// imports a non-shipped sibling './libsodium-sumo.mjs' and breaks under any ESM loader.
// Alias the bare specifier to the working CJS build (the package's `require` condition)
// so Vite bundles the functioning build for the browser. Same fix as the other configs.

import { defineConfig } from 'vitest/config';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import tailwindcss from '@tailwindcss/vite';
import wasm from 'vite-plugin-wasm';
import topLevelAwait from 'vite-plugin-top-level-await';

const __dirname = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const libsodiumCjs = require.resolve('libsodium-wrappers-sumo');

// Local escape hatch for Playwright's browser binary. When CRYPTIQ_TEST_BROWSER_BIN
// points at an already-installed Chromium / chrome-headless-shell executable, launch
// it directly instead of relying on `playwright install`. This dev machine has flaky
// access to the Playwright CDN (ECONNRESET) and already has a usable headless-shell
// build on disk. Unset in CI (good network) → the provider manages the browser normally.
const browserBin = process.env.CRYPTIQ_TEST_BROWSER_BIN;

export default defineConfig({
  plugins: [svelte({ hot: false }), tailwindcss(), wasm(), topLevelAwait()],
  resolve: {
    alias: {
      // Mock @tauri-apps/api/core's invoke() so the advisory-lock IPC the
      // VaultSession performs resolves without a live Tauri backend.
      '@tauri-apps/api/core': resolve(
        __dirname,
        'src/tests/support/mockTauriInvoke.ts',
      ),
      // Force the working CJS libsodium build (decision 26).
      'libsodium-wrappers-sumo': libsodiumCjs,
    },
  },
  optimizeDeps: {
    // The @tauri-apps/api/core alias above redirects to a local mock module. If Vite
    // pre-bundles the tauri packages, esbuild inlines a SEPARATE copy of that mock into
    // the optimized dep, so state a spec sets via its (source) mock import is invisible
    // to plugin-fs's (pre-bundled) mock import — e.g. setMockVaultBytes() never reaches
    // the readFile() path, which then returns config bytes and unlockVault reports
    // "damaged". Excluding the tauri packages keeps a SINGLE mock instance.
    exclude: [
      '@tauri-apps/api',
      '@tauri-apps/plugin-fs',
      '@tauri-apps/plugin-dialog',
      '@tauri-apps/plugin-clipboard-manager',
      '@tauri-apps/plugin-opener',
    ],
  },
  test: {
    // vitest-browser-svelte's setup wires the render() cleanup + locator API.
    setupFiles: ['vitest-browser-svelte'],
    include: ['src/tests/**/*.spec.ts'],
    // Each spec creates a real floor-param vault in beforeEach (~1s Argon2id) and
    // drives DOM interactions; give headroom over the node-test 10s default.
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
