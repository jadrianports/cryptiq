import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import tailwindcss from '@tailwindcss/vite';
import wasm from 'vite-plugin-wasm';
import topLevelAwait from 'vite-plugin-top-level-await';

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

  // Defends Pitfall 5 — exclude libsodium from dep pre-bundling (added in Phase 2;
  // harmless to land in Phase 1 so Phase 2 has no retrofit step).
  optimizeDeps: {
    exclude: ['libsodium-wrappers-sumo'],
  },

  // Env variables starting with `VITE_` are exposed to the renderer.
  envPrefix: ['VITE_', 'TAURI_ENV_*'],

  build: {
    target: 'chrome111', // Tauri webview floor on Windows (WebView2 evergreen, but pin a floor)
    minify: !process.env.TAURI_DEBUG ? 'esbuild' : false,
    sourcemap: !!process.env.TAURI_DEBUG,
  },
});
