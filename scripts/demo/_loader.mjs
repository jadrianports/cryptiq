// scripts/demo/_loader.mjs
//
// Zero-dependency Node module-resolution preload for the Phase 2 demo scripts. Node 24
// strips TypeScript natively, but two resolution quirks block running the demos
// directly against packages/core's .ts source. This preload registers _hooks.mjs to
// fix both with Node stdlib only (no tsx / ts-node / esbuild-register install — keeps
// the SEC-15 dependency-minimization rule intact):
//
//   1. EXTENSIONLESS RELATIVE TS IMPORTS. packages/core uses the project convention
//      `export * from './errors'` (no extension). Vite/Vitest and tsc tolerate this;
//      native Node ESM requires './errors.ts'. The hook retries with a `.ts` suffix.
//
//   2. BROKEN libsodium-wrappers-sumo@0.7.x ESM BUILD. Its published .mjs imports an
//      unshipped sibling `./libsodium-sumo.mjs` and throws under any ESM loader. The
//      hook redirects the bare specifier to the package's working CommonJS entry,
//      mirroring the alias in packages/core/vitest.config.ts.
//
// Usage:  node --import ./scripts/demo/_loader.mjs scripts/demo/02-<N>-<name>.mjs

import { register } from 'node:module';

register(new URL('./_hooks.mjs', import.meta.url));
