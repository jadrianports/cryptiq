/// <reference types="vite/client" />

// DEMO-07/DEMO-09/D-18/D-12 — ambient types for the three `define`-injected
// build-time globals (apps/site/vite.config.ts). `define` performs a literal
// text substitution at build time; these `declare const`s let downstream
// .svelte/.ts consumers (39-02's App.svelte SHA link + download section)
// typecheck against them.

/** The exact 40-hex `git rev-parse HEAD` that produced this build (DEMO-07). */
declare const __CORE_COMMIT_SHA__: string;

/** `v<version>` from apps/desktop/src-tauri/tauri.conf.json (DEMO-09/D-12). */
declare const __RELEASE_TAG__: string;

/** `Cryptiq_<version>_x64-setup.exe` — the real NSIS installer asset filename (DEMO-09/D-12). */
declare const __INSTALLER_ASSET__: string;
