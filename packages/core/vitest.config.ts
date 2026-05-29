import { defineConfig } from 'vitest/config';
import { createRequire } from 'node:module';

// Vitest 3 — pin justified in STACK.md §Q5 (v4 changed browser-provider package shape;
// revisit upgrade after Phase 2 ships green).
//
// Settings here are oriented for the Phase 2 crypto suite:
//   - pool: 'forks' (default in v3) — safer for WASM + Argon2id memory across tests
//   - singleFork: true — serializes 256+ MiB Argon2id allocations to avoid OOM
//   - testTimeout: 30000 — calibration tests walk the memlimit ladder
//
// Phase 1's only test is the trivial sanity stub; the config is sized for Phase 2
// so the harness has no retrofit step.
//
// libsodium-wrappers-sumo@0.7.16 ESM-build workaround:
//   The package's ESM entry (dist/modules-sumo-esm/libsodium-wrappers.mjs) does
//   `import e from "./libsodium-sumo.mjs"` — a sibling file that is NOT shipped in
//   that package (the actual sumo WASM payload lives in the separate `libsodium-sumo`
//   package as CommonJS). The result: the published `.mjs` is broken under any ESM
//   loader (plain `node --input-type=module` AND Vite/Vitest both fail to resolve it).
//   The CommonJS entry (dist/modules-sumo/libsodium-wrappers.js, selected by the
//   package's `require` export condition) works correctly. We alias the bare specifier
//   to that working CJS file via createRequire().resolve so the whole crypto suite
//   loads the functioning build. STACK.md §Q5 flagged libsodium WASM init as the known
//   Vitest friction point; this is the concrete fix. Pin stays ^0.7.15 (CLAUDE.md
//   decision 4/8 — do NOT chase 0.8.x to dodge this packaging bug).
const require = createRequire(import.meta.url);
const libsodiumCjs = require.resolve('libsodium-wrappers-sumo');

export default defineConfig({
  test: {
    environment: 'node',
    testTimeout: 30_000,
    pool: 'forks',
    poolOptions: {
      forks: { singleFork: true },
    },
    include: ['src/**/*.test.ts', 'src/**/__tests__/**/*.test.ts'],
    alias: {
      'libsodium-wrappers-sumo': libsodiumCjs,
    },
  },
});
