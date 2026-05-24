import { defineConfig } from 'vitest/config';

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

export default defineConfig({
  test: {
    environment: 'node',
    testTimeout: 30_000,
    pool: 'forks',
    poolOptions: {
      forks: { singleFork: true },
    },
    include: ['src/**/*.test.ts', 'src/**/__tests__/**/*.test.ts'],
  },
});
