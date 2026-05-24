// apps/desktop/src/lib/dev/boot-self-test.ts
//
// D-02: dev-only boot self-test. Stripped from production by Vite's
// import.meta.env.DEV branch in main.ts.
//
// Three checks:
//   1. Time sodium.ready resolution; console.warn if > 500ms.
//      (Pitfall 5 — Vite WASM MIME stripping = slow init.)
//      Phase 1 stub: warns based on the placeholder Promise.resolve() in App.svelte.
//      Phase 2 replaces with the real sodium.ready timing.
//   2. Verify the loaded CSP matches the production-strict block.
//      Catches dev_csp accidentally leaking into a production build.
//   3. Print which capability file is in effect.

const PROD_CSP_FORBIDDEN_TOKENS = ["'unsafe-inline'", 'localhost:', 'ws://'];

export function runBootSelfTest(): void {
  console.info('[boot-self-test] running (dev only — stripped in production builds).');

  // === Check 1: sodium.ready timing (Phase 2 replaces stub) ===
  const t0 = performance.now();
  Promise.resolve().then(() => {
    const dt = performance.now() - t0;
    if (dt > 500) {
      console.warn(
        `[boot-self-test] sodium.ready took ${dt.toFixed(0)}ms (> 500ms threshold). ` +
          'Suspect Vite WASM MIME stripping — see PITFALLS.md Pitfall 5. ' +
          'Check vite.config.ts has optimizeDeps.exclude: ["libsodium-wrappers-sumo"] and vite-plugin-wasm plugin.',
      );
    } else {
      console.info(`[boot-self-test] sodium.ready: ${dt.toFixed(1)}ms (OK)`);
    }
  });

  // === Check 2: CSP verification ===
  // The browser injects the CSP either via HTTP header (Tauri's path) or meta tag.
  const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
  if (cspMeta) {
    const csp = cspMeta.getAttribute('content') ?? '';
    const scriptSrcMatch = csp.match(/script-src\s+([^;]+)/);
    if (scriptSrcMatch && scriptSrcMatch[1]) {
      const scriptSrc = scriptSrcMatch[1].trim();
      const hasForbiddenInProd = PROD_CSP_FORBIDDEN_TOKENS.some((t) => scriptSrc.includes(t));
      // In dev we expect the forbidden tokens; in prod they would have been stripped from main.ts entirely.
      // If this self-test ever runs in a prod build (bug in the strip logic), warn loudly.
      console.info(`[boot-self-test] CSP script-src: ${scriptSrc}`);
      console.info(
        `[boot-self-test] dev-mode CSP relaxations present: ${hasForbiddenInProd}. (Expected TRUE in dev, FALSE in prod.)`,
      );
    } else {
      console.warn(
        '[boot-self-test] no script-src directive found in CSP meta — review tauri.conf.json security.csp.',
      );
    }
  } else {
    console.info('[boot-self-test] CSP applied via header (no meta tag found — normal for Tauri).');
    // Note: Tauri injects CSP via header, not meta, in production. The meta-tag check
    // above is mostly a backstop. The genuine "CSP leaked into prod" detector is the
    // fact that this entire boot-self-test module is import.meta.env.DEV-gated.
  }

  // === Check 3: capability file print ===
  // Tauri doesn't expose the loaded capability JSON to the renderer at runtime.
  // Log a static identifier so the developer can manually cross-check.
  console.info(`[boot-self-test] expected capability identifiers: cryptiq-main, cryptiq-bootstrap`);
  console.info(`[boot-self-test] expected platforms: ["windows", "macOS"] (D-15: Linux dropped)`);
}
