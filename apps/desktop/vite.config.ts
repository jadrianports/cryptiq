import { defineConfig } from 'vite';
import { createRequire } from 'node:module';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import tailwindcss from '@tailwindcss/vite';
import wasm from 'vite-plugin-wasm';
import topLevelAwait from 'vite-plugin-top-level-await';

// libsodium-wrappers-sumo@0.7.16 ESM-build workaround (CLAUDE.md decision 26).
//   The published ESM entry (dist/modules-sumo-esm/libsodium-wrappers.mjs) does
//   `import e from "./libsodium-sumo.mjs"` — a sibling file the package does NOT ship —
//   so Vite cannot resolve it and the webview renderer fails to load. The CommonJS entry
//   (dist/modules-sumo/libsodium-wrappers.js, the `require` export condition) works in the
//   Chromium-based Tauri WebView (proven by the 29 vitest-browser component tests, which
//   run real Argon2id via this build). Alias the bare specifier to that working CJS build —
//   the same fix packages/core/vitest.config.ts and vitest.browser.config.ts apply. This
//   was missing here because Phase-3 deferred the live `pnpm tauri dev` smoke (UAT T1).
const libsodiumCjs = createRequire(import.meta.url).resolve(
  'libsodium-wrappers-sumo',
);

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    svelte(),
    tailwindcss(),
    // Defends Pitfall 5 — Vite WASM MIME stripping.
    // libsodium ships WASM-in-JS so technically isn't needed for it,
    // but ships in Phase 1 so Phase 2 has the right tooling on day one.
    wasm(),
    topLevelAwait(),
  ],

  resolve: {
    // Force the working CJS libsodium build (decision 26 — see note above).
    alias: {
      'libsodium-wrappers-sumo': libsodiumCjs,
    },
  },

  // Prevent Vite from obscuring rust errors
  clearScreen: false,
  // Tauri expects a fixed port; fail if not available
  server: {
    port: 1420,
    strictPort: true,
    host: false,
    // No HMR overlay obscuring Tauri webview when full-screen
    hmr: { protocol: 'ws', host: 'localhost', port: 1421 },
    // Vite must NOT watch the Tauri Rust build tree. On Windows, chokidar will
    // EBUSY-error on every cargo recompile because the running cryptiq_lib.dll
    // is locked. Excluding src-tauri/** also avoids spurious HMR reloads when
    // Cargo writes incremental artifacts. Recommended pattern from Tauri v2 docs.
    watch: {
      ignored: ['**/src-tauri/**'],
    },
  },

  // libsodium is aliased to its CommonJS build (see decision 26 note above). Vite must
  // PRE-BUNDLE it so esbuild converts that CJS module to ESM for the webview — the prior
  // `exclude` did the opposite (served raw CJS the browser can't run), which is why the
  // app failed to boot (UAT T1). `include` forces the dev-server pre-bundle; the alias is
  // resolved to the absolute CJS path before optimization. (Vite v6 dep-pre-bundling docs.)
  optimizeDeps: {
    include: ['libsodium-wrappers-sumo'],
  },

  // Env variables starting with `VITE_` are exposed to the renderer.
  envPrefix: ['VITE_', 'TAURI_ENV_*'],

  build: {
    target: 'chrome111', // Tauri webview floor on Windows (WebView2 evergreen, but pin a floor)
    minify: !process.env.TAURI_DEBUG ? 'esbuild' : false,
    sourcemap: !!process.env.TAURI_DEBUG,
    // Production `vite build` (Rollup) must also convert the CJS libsodium build to ESM.
    // node_modules is matched by default, but the alias resolves into the pnpm store, so
    // name the package explicitly alongside the default node_modules matcher.
    commonjsOptions: {
      include: [/libsodium-wrappers-sumo/, /node_modules/],
    },
  },
});
