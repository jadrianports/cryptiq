import { defineConfig } from 'vitest/config';
import { WxtVitest } from 'wxt/testing/vitest-plugin';

// apps/extension/vitest.config.ts
//
// Wave 0 gap closure (15-VALIDATION.md): wires WxtVitest() so tests get
// WXT's `import.meta.env`, the `@/` alias, and fake-browser chrome.*/
// browser.* stubs (wxt/testing/fake-browser) without any manual mocking.
// Non-watch by default — the "test" script below passes `run` explicitly;
// no watch-mode flag lives here or in package.json.
export default defineConfig({
  plugins: [WxtVitest()],
});
