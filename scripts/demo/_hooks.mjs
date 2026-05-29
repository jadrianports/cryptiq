// scripts/demo/_hooks.mjs
//
// Module-customization hooks (Node stdlib only) used by _loader.mjs. See _loader.mjs
// for the rationale. Two resolve fixes:
//   1. Retry extensionless relative TS specifiers with a `.ts` suffix.
//   2. Redirect the broken libsodium-wrappers-sumo ESM build to its working CJS entry.

import { existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';

// Anchor the require to the @cryptiq/core package (the package that declares
// libsodium-wrappers-sumo as a dependency) so resolution succeeds regardless of where
// the hook worker is anchored. The `require` export-condition selects the working CJS
// build (dist/modules-sumo/libsodium-wrappers.js), not the broken ESM .mjs.
let libsodiumCjsUrl = null;
for (const anchor of ['../../packages/core/package.json', '../../package.json']) {
  try {
    const require = createRequire(new URL(anchor, import.meta.url));
    libsodiumCjsUrl = pathToFileURL(require.resolve('libsodium-wrappers-sumo')).href;
    break;
  } catch {
    // try next anchor
  }
}

export async function resolve(specifier, context, next) {
  // 2. libsodium broken-ESM → CJS redirect.
  if (
    libsodiumCjsUrl &&
    (specifier === 'libsodium-wrappers-sumo' || specifier.startsWith('libsodium-wrappers-sumo/'))
  ) {
    return { url: libsodiumCjsUrl, format: 'commonjs', shortCircuit: true };
  }

  try {
    return await next(specifier, context);
  } catch (err) {
    // 1. Extensionless relative TS retry.
    const isRelative = specifier.startsWith('./') || specifier.startsWith('../');
    const hasExt = /\.[cm]?[jt]s$/.test(specifier);
    if (isRelative && !hasExt && context.parentURL) {
      const candidate = new URL(specifier + '.ts', context.parentURL);
      if (existsSync(fileURLToPath(candidate))) {
        return await next(specifier + '.ts', context);
      }
    }
    throw err;
  }
}
