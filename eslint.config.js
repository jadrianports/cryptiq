// eslint.config.js — flat config (ESLint 9+)
// Single source of truth for project lint rules. No legacy .eslintrc.cjs.
//
// Three layers:
//   1. Project-wide baseline (Math.random ban, etc.)
//   2. typescript-eslint recommended for all TS
//   3. Stricter overrides for packages/core (forbidden imports + no-console)
//   4. Svelte parser block + svelte/no-at-html-tags
//   5. Test + dev relaxations
//   6. Generated-output ignores

import tseslint from 'typescript-eslint';
import svelteParser from 'svelte-eslint-parser';
import sveltePlugin from 'eslint-plugin-svelte';

const FORBIDDEN_CORE_IMPORTS = [
  // Pure-TS core may not see platform code.
  { name: 'svelte', message: 'packages/core is platform-free — Svelte belongs in apps/desktop.' },
  { name: 'svelte/store', message: 'packages/core is platform-free.' },
  { name: 'svelte/internal', message: 'packages/core is platform-free.' },
  { name: 'fs', message: 'packages/core never touches a disk — use VaultStorageAdapter.' },
  { name: 'node:fs', message: 'packages/core never touches a disk — use VaultStorageAdapter.' },
  { name: 'fs/promises', message: 'packages/core never touches a disk.' },
  { name: 'node:fs/promises', message: 'packages/core never touches a disk.' },
  { name: 'path', message: 'packages/core knows nothing about file paths.' },
  { name: 'node:path', message: 'packages/core knows nothing about file paths.' },
];

const FORBIDDEN_CORE_IMPORT_PATTERNS = [
  '@tauri-apps/*', // core is Tauri-free
  'svelte/*',
];

export default [
  // === Project-wide baseline ===
  {
    files: ['**/*.{ts,tsx,js,mjs,cjs,svelte}'],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: 'module',
    },
    rules: {
      // SEC-14 / project crypto rule: ban Math.random project-wide.
      // The custom message points the developer at the right replacement so
      // there's no "what should I use instead?" friction.
      'no-restricted-properties': [
        'error',
        {
          object: 'Math',
          property: 'random',
          message:
            'Math.random is banned project-wide. Use sodium.randombytes_buf(...) — even for non-security UI randomness, so we never have to audit which call sites are security-relevant.',
        },
      ],

      // Defense in depth — also block any future global window.Math.random pattern
      // and any indirect `const r = Math.random; r();` reassignment.
      'no-restricted-syntax': [
        'error',
        {
          selector: "MemberExpression[object.name='Math'][property.name='random']",
          message: 'Math.random is banned project-wide. Use sodium.randombytes_buf(...).',
        },
      ],
    },
  },

  // === TypeScript-aware rules for all TS files ===
  ...tseslint.configs.recommended,

  // Honor the underscore-prefix convention for intentionally-unused params/locals
  // so it matches tsconfig.base.json's noUnusedParameters / noUnusedLocals handling.
  {
    files: ['**/*.{ts,tsx,svelte}'],
    rules: {
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
        },
      ],
    },
  },

  // === packages/core stricter rules (SEC-14, SEC-10) ===
  {
    files: ['packages/core/**/*.ts'],
    rules: {
      // SEC-14: forbidden imports.
      'no-restricted-imports': [
        'error',
        {
          paths: FORBIDDEN_CORE_IMPORTS,
          patterns: FORBIDDEN_CORE_IMPORT_PATTERNS,
        },
      ],

      // SEC-10 / no plaintext-secrets-to-logs: ban console.* entirely inside core.
      // Tests in __tests__ may need console for debug — overridden below.
      'no-console': 'error',
    },
  },

  // === packages/core tests can use console (relaxation) ===
  {
    files: ['packages/core/**/__tests__/**/*.ts', 'packages/core/**/*.test.ts'],
    rules: {
      'no-console': 'off',
    },
  },

  // === Svelte file parsing ===
  {
    files: ['apps/desktop/**/*.svelte'],
    languageOptions: {
      parser: svelteParser,
      parserOptions: {
        parser: tseslint.parser,
      },
    },
    plugins: { svelte: sveltePlugin },
    rules: {
      ...sveltePlugin.configs.recommended.rules,
      // Phase 1 has no entry data to leak yet, but ban {@html ...} now so
      // Phase 4 can never accidentally render vault entry data as HTML
      // (defends Pitfall 7 / ARCHITECTURE.md §4.2).
      'svelte/no-at-html-tags': 'error',
    },
  },

  // === Boot self-test allowed to use console (it's a dev-only diagnostic) ===
  {
    files: ['apps/desktop/src/lib/dev/**/*.ts'],
    rules: {
      'no-console': 'off',
    },
  },

  // === Ignore generated output + non-source dirs ===
  {
    ignores: [
      '**/node_modules/**',
      '**/dist/**',
      '**/target/**',
      '**/.svelte-kit/**',
      'apps/desktop/src-tauri/gen/**',
      'pnpm-lock.yaml',
      // GSD planning + tool harness — not Cryptiq source.
      '.planning/**',
      '.claude/**',
      'cryptiq-plans/**',
      // Custom lint scripts are intentionally CommonJS-free + Node-stdlib;
      // they don't need typescript-eslint rules. Their own correctness is
      // proven by self-tests (see scripts/lint/README.md).
      'scripts/lint/**',
    ],
  },
];
