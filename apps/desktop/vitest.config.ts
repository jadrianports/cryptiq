// apps/desktop/vitest.config.ts
//
// Vitest configuration for the desktop adapter tests (Plan 03-05, Task 2).
//
// These tests mock @tauri-apps/api/core and @tauri-apps/plugin-fs — they do NOT
// require a live Tauri runtime or WASM. The node environment is correct; browser
// mode is reserved for Svelte component tests (Phase 4+, Playwright provider).
//
// The TauriVaultStorageAdapter test (saveMutex.test.ts) is a pure TS unit test
// that exercises: save-mutex ordering, isSaving flag, content-hash dedup, and
// the three backup methods (listBackups/loadBackup/savePreMigrationBackup).
//
// libsodium-wrappers-sumo ESM workaround (same fix as packages/core/vitest.config.ts):
//   The published .mjs entry imports a non-existent sibling './libsodium-sumo.mjs'.
//   We alias the bare specifier to the working CJS build via createRequire().resolve.
//   The adapter test doesn't directly use WASM, but @cryptiq/core is in the
//   dependency graph (for the error types) and libsodium is a transitive import.

import { defineConfig } from 'vitest/config';
import { createRequire } from 'node:module';
import { svelte } from '@sveltejs/vite-plugin-svelte';

const require = createRequire(import.meta.url);
const libsodiumCjs = require.resolve('libsodium-wrappers-sumo');

export default defineConfig({
  plugins: [
    // Include the Svelte plugin so .svelte.ts files are resolved correctly
    // (vault.svelte.ts is a .svelte.ts module in the test dependency graph).
    svelte({ hot: false }),
  ],
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts', 'src/**/__tests__/**/*.test.ts'],
    // No Argon2id in these tests — no need for singleFork or long timeout.
    testTimeout: 10_000,
    // Setup file: polyfills window = globalThis in node env so the idle
    // controller's window.addEventListener / test's window.dispatchEvent
    // both target the same globalThis EventTarget (Plan 05-03, LOCK-01).
    setupFiles: ['src/test-setup.ts'],
    alias: {
      'libsodium-wrappers-sumo': libsodiumCjs,
    },
  },
});
