// vitest.config.ts (repository root)
//
// Vitest 3.2 `test.projects` aggregator — the native replacement for the
// deprecated `vitest.workspace.ts` (workspace was deprecated in 3.2 and replaced
// by a `projects` array inside `test`). It exists so the bare root invocation
// `vitest run` honors EACH package's own config instead of falling back to Vitest
// defaults. Two surfaces depend on this:
//   - the root `test` script in package.json (`vitest run`)
//   - CI's `pnpm exec vitest run` (.github/workflows/ci.yml:76-77)
//
// Without this file, root `vitest run` discovers every package's *.test.ts WITHOUT
// applying their configs:
//   - apps/desktop loses `setupFiles: ['src/test-setup.ts']` → `window is not defined`
//     in dialogGuard.svelte.ts / idle.svelte.ts
//   - packages/core loses its `libsodium-wrappers-sumo` → CJS alias and singleFork
//     pool → libsodium ESM resolution failure / Argon2id OOM
//
// Each entry is a directory string; Vitest auto-discovers that directory's
// default-named `vitest.config.ts` and applies it verbatim — so each package's own
// config stays the single source of truth (core keeps singleFork + 30s timeout +
// libsodium alias; desktop keeps the window polyfill + Svelte plugin). This file
// only binds them under one root run. Explicit directory strings (not a glob) keep
// resolution deterministic and intentionally resolve the node-env
// apps/desktop/vitest.config.ts, NOT apps/desktop/vitest.browser.config.ts — the
// Playwright component suite (`test:components`) stays out of the root aggregate.
//
// apps/site (Phase 38, 38-03, Pitfall 2) has a SINGLE always-on browser-mode
// vitest.config.ts (no node/desktop-style split) — apps/site has no node-only test
// in this phase's scope that would justify a split, so its one config IS the
// browser-mode suite and resolves directly here, intentionally.
//
// Vitest stays pinned at ^3.2.4 (STACK.md §Q5 / CLAUDE.md) — `test.projects` is the
// native 3.2 mechanism; no version bump, no new dependencies.

import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    projects: ['packages/core', 'apps/desktop', 'apps/site'],
  },
});
