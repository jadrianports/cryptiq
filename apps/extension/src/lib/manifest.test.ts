// apps/extension/src/lib/manifest.test.ts
//
// XSEC-04: locks the manifest permission invariant Task 3 introduces --
// exactly the narrow `scripting` permission was added (for the popup's
// on-demand chrome.scripting.executeScript injection of fill.content.ts,
// Plan 17-04), with NO host_permissions and NO declarative content_scripts
// entry.
//
// Asserts against the raw wxt.config.ts manifest object rather than a built
// .output/chrome-mv3/manifest.json: `defineConfig()` is an identity
// function (node_modules/wxt/dist/core/define-config.mjs — `function
// defineConfig(config) { return config; }`), so the exported config IS the
// manifest's `permissions`/`host_permissions`/`content_scripts` source of
// truth -- WXT's build step does not add/remove permissions, it only
// synthesizes a content_scripts array for `registration:'manifest'`
// entrypoints. fill.content.ts is explicitly `registration:'runtime'`
// (asserted separately, by grep-style test, in fill.content.test.ts's
// sibling suite intent / the plan's own verification step), so it is never
// added to content_scripts regardless. Running a full `wxt build` inside
// this unit-test loop was evaluated (17-RESEARCH.md Open Question #2) and
// judged unnecessary for this invariant.

import { describe, expect, it } from 'vitest';
import config from '../../wxt.config';

// wxt.config.ts's manifest field is authored as a plain object literal (not
// a Promise/function form) -- narrow the broader UserManifest union type
// `defineConfig` exposes down to that literal shape for these assertions.
interface StaticManifestShape {
  permissions?: string[];
  host_permissions?: string[];
  content_scripts?: unknown[];
}
const manifest = config.manifest as StaticManifestShape;

describe('manifest permissions (XSEC-04)', () => {
  it('permissions array contains scripting and activeTab', () => {
    const permissions = manifest.permissions ?? [];
    expect(permissions).toContain('scripting');
    expect(permissions).toContain('activeTab');
  });

  it('permissions are EXACTLY the four narrow permissions this milestone has added so far -- no unexpected broadening', () => {
    const permissions = [...(manifest.permissions ?? [])].sort();
    expect(permissions).toEqual(['activeTab', 'nativeMessaging', 'scripting', 'storage'].sort());
  });

  it('has NO host_permissions key', () => {
    expect(manifest).not.toHaveProperty('host_permissions');
  });

  it('has NO content_scripts array', () => {
    expect(manifest).not.toHaveProperty('content_scripts');
  });

  it('has NO tabs permission (activeTab already covers the popup current-tab read)', () => {
    const permissions = manifest.permissions ?? [];
    expect(permissions).not.toContain('tabs');
  });
});
