import { defineConfig } from 'vite';
import { createRequire } from 'node:module';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import tailwindcss from '@tailwindcss/vite';
import wasm from 'vite-plugin-wasm';
import topLevelAwait from 'vite-plugin-top-level-await';

// libsodium-wrappers-sumo@0.7.16 ESM-build workaround — mirrored VERBATIM from
// apps/desktop/vite.config.ts (CLAUDE.md decision 26). The published ESM entry
// (dist/modules-sumo-esm/libsodium-wrappers.mjs) does
// `import e from "./libsodium-sumo.mjs"` — a sibling file the package does NOT
// ship — so Vite cannot resolve it. The CommonJS entry (dist/modules-sumo/
// libsodium-wrappers.js, the `require` export condition) works and is what
// apps/desktop's 29 vitest-browser component tests already exercise. Alias the
// bare specifier to that working CJS build (38-RESEARCH.md Pattern 1).
const libsodiumCjs = createRequire(import.meta.url).resolve(
  'libsodium-wrappers-sumo',
);

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [svelte(), tailwindcss(), wasm(), topLevelAwait()],

  resolve: {
    // Force the working CJS libsodium build (decision 26 — see note above).
    alias: {
      'libsodium-wrappers-sumo': libsodiumCjs,
    },
  },

  // apps/site is a plain static site (no Tauri) — only VITE_-prefixed env vars
  // are exposed to the client, never a bare TAURI_ prefix.
  envPrefix: ['VITE_'],

  // libsodium is aliased to its CommonJS build (see note above). Vite must
  // PRE-BUNDLE it so esbuild converts that CJS module to ESM for the browser.
  optimizeDeps: {
    include: ['libsodium-wrappers-sumo'],
  },

  build: {
    // Production `vite build` (Rollup) must also convert the CJS libsodium
    // build to ESM. node_modules is matched by default, but the alias
    // resolves into the pnpm store, so name the package explicitly alongside
    // the default node_modules matcher.
    commonjsOptions: {
      include: [/libsodium-wrappers-sumo/, /node_modules/],
    },
  },
});
