import { defineConfig } from 'vite';
import { createRequire } from 'node:module';
import { execSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
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

// REPO_ROOT — apps/site/vite.config.ts is two directories below the repo root
// (mirrors the scripts/lint/*.mjs `fileURLToPath(new URL('../../', ...))` idiom).
const REPO_ROOT = fileURLToPath(new URL('../../', import.meta.url));

// DEMO-07/D-18 — the printed "audit it yourself" commit SHA. Resolved ONCE at
// Node config-load time via `git rev-parse HEAD` (the commit that produced
// THIS exact build, including packages/core's tree state) — deliberately NOT
// `git log -1 -- packages/core` (39-RESEARCH.md Pattern 2): HEAD is simpler,
// always resolvable under a shallow (`fetch-depth: 1`) CI checkout, and the
// linked tree at HEAD is byte-identical to any earlier "last-touched" SHA for
// the packages/core subpath (history is monotonic). `define` is a compile-time
// text substitution — it never touches `envPrefix: ['VITE_']` (D-18) and adds
// zero CI wiring.
const coreCommitSha = execSync('git rev-parse HEAD', { cwd: REPO_ROOT }).toString().trim();

// DEMO-09/D-12 — release-asset URL construction, single source of truth
// (39-RESEARCH.md Pattern 4 / Assumptions Log A4). `version`/`productName` are
// read from apps/desktop/src-tauri/tauri.conf.json, the SAME file the release
// pipeline (release.yml) already treats as authoritative (CI-03/CI-05) — this
// can never drift independently of the app itself. Asset filename pattern
// (`Cryptiq_<version>_x64-setup.exe`) is empirically confirmed against the
// Phase-35 dry run (35-08-SUMMARY.md).
const tauriConf = JSON.parse(
  readFileSync(join(REPO_ROOT, 'apps', 'desktop', 'src-tauri', 'tauri.conf.json'), 'utf8'),
) as { version: string };
const appVersion = tauriConf.version;
const releaseTag = `v${appVersion}`;
const installerAsset = `Cryptiq_${appVersion}_x64-setup.exe`;

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

  // DEMO-07/DEMO-09/D-18/D-12 — compile-time constant baking. `define` is a
  // literal text substitution (NOT process.env passthrough), so it stays
  // within the envPrefix:['VITE_'] constraint with zero CI wiring — the
  // browser only ever displays a static string, no runtime lookup, no network
  // call (39-RESEARCH.md Pattern 2/Pattern 4).
  define: {
    __CORE_COMMIT_SHA__: JSON.stringify(coreCommitSha),
    __RELEASE_TAG__: JSON.stringify(releaseTag),
    __INSTALLER_ASSET__: JSON.stringify(installerAsset),
  },

  // Pitfall 6 (39-RESEARCH.md) — this repo has no CNAME, so the deployed URL
  // is the project-scoped `https://jadrianports.github.io/cryptiq/`. Vite
  // defaults `base: '/'`, which would 404 every asset (incl. the Worker's
  // `new URL(..., import.meta.url)` resolution) once served from `/cryptiq/`.
  // A fixed base works identically for `dev`/`build`/`preview`.
  base: '/cryptiq/',

  // DEMO-03/04 — Web Worker bundling for the off-main-thread crypto engine
  // (Task 2). Vite's top-level `plugins` array only applies to workers in DEV
  // — production worker builds are a SEPARATE Rollup build and need their own
  // plugin list declared here (39-RESEARCH.md Pitfall 2, verified against the
  // installed vite@6's `ResolvedWorkerOptions` type, not a newer-major doc
  // snapshot).
  worker: {
    format: 'es',
    plugins: () => [wasm(), topLevelAwait()],
    // Assumptions Log A2 (39-RESEARCH.md): whether the top-level
    // `build.commonjsOptions` below (needed for the libsodium CJS alias) is
    // ALSO inherited by the worker's separate Rollup build is unconfirmed by
    // Vite's docs. Left empty here; Task 2 (which introduces the first real
    // worker consumer of libsodium) verifies this empirically via
    // `pnpm --filter @cryptiq/site build` — if the worker chunk retains a raw
    // CJS `require` reference, restate
    // `commonjsOptions: { include: [/libsodium-wrappers-sumo/, /node_modules/] }`
    // here at that point.
    rollupOptions: {},
  },

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

    // D-07 (38-03): Vite's default modulePreload polyfill unconditionally
    // embeds a literal `fetch(i.href, s)` call in the shipped bundle (dead
    // code on this single-chunk build with no <link rel=modulepreload> to
    // trigger it, but the byte string is still there) — which trips
    // lint-demo-containment.mjs's forbidden-API scan and, more importantly,
    // violates "structurally, not by promise": a network call must not exist
    // in the shipped bytes at all, reachable or not. apps/site has no code
    // splitting to preload, so disabling this outright costs nothing.
    modulePreload: false,
  },
});
