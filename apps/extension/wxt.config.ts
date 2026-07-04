import { defineConfig } from 'wxt';

// apps/extension/wxt.config.ts
//
// D-15: `manifest.key` pins a stable, deterministic extension ID across
// reloads/machines so the native-host manifest's `allowed_origins` stays
// valid. The private key (`extension-key.pem`, gitignored) is never used at
// build time — only the derived base64 DER public key below is committed.
// Regenerate via (one-time, already done for this repo):
//   openssl genrsa -out extension-key.pem 2048
//   openssl rsa -in extension-key.pem -pubout -outform DER | openssl base64 -A
//
// D-17: permissions = nativeMessaging (Phase 14) + storage (Phase 15). No
// host_permissions, no content_scripts entry — Phase 14's extension surface
// is background SW + popup only; field detection/injection is Phase 17.
// `storage` is REQUIRED by Phase 15 (BRIDGE-05): associationStore.ts persists
// the permanent identity keypair + association record in chrome.storage.local
// so a reconnect after an MV3 SW restart is silently trusted. Without it
// chrome.storage is undefined in a real browser and ensureAssociation() throws
// on first use — a gap the WxtVitest fake-browser masks (it injects
// chrome.storage regardless of the manifest); found via the live Phase-15 UAT.
//
// Plan 16-04 [Rule 2 — missing critical functionality]: `activeTab` added so
// Popup.svelte can read the current tab's URL to build the `match-origin`
// RPC's `origin` param. `activeTab` is the narrowly-scoped permission
// 16-CONTEXT.md already anticipates for XSEC-04 (Phase 17) — it grants
// temporary access to the tab that triggered the popup's own open (a user
// gesture), never a standing `host_permissions`/`tabs` grant. No
// content_scripts entry added; field-detection injection stays Phase 17.
//
// Plan 17-03 (XSEC-04): `scripting` added -- required for the popup's
// on-demand `chrome.scripting.executeScript({ target: { tabId } })`
// injection of `fill.content.ts` (a `registration:'runtime'` content
// script, so it is NEVER declared below and never auto-runs on page load).
// `scripting` + `activeTab` together is Chrome's documented minimum for
// "inject on click" extensions (17-RESEARCH.md Permission Model,
// Context7-verified). Deliberately did NOT add: `host_permissions` (no
// standing per-origin grant -- injection rides the activeTab gesture only),
// a `content_scripts` entry (the content script is runtime-registered, not
// declarative), or `tabs` (unneeded -- `activeTab` already covers the
// popup's current-tab read).
//
// Plan 18-02 (UX-03): `contextMenus` added -- required for
// `chrome.contextMenus.create`/`onClicked` (right-click "Fill from Cryptiq" /
// "Generate password" on editable fields). No new standing grant: the menu
// only appears on a user's own right-click gesture, and the click handler
// still rides the SAME activeTab-gated `ensureContentScript` +
// `sendAuthenticatedRpc` path the popup already uses -- never a fresh
// host_permissions/tabs grant.
//
// Plan 18-02 (UX-04, D-03/D-04, Pitfall 4): `commands._execute_action` is
// Chrome's RESERVED zero-code popup-open shortcut -- present ONLY because a
// `default_popup` already exists (WXT's `entrypoints/popup/` convention). No
// `onCommand` listener is added or needed; Chrome opens the popup itself.
// `suggested_key` is suggested-or-unbound (user-rebindable via
// chrome://extensions/shortcuts, never silently overrides another
// extension's binding).
export default defineConfig({
  modules: ['@wxt-dev/module-svelte'],
  manifest: {
    name: 'Cryptiq',
    key: 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA19vhX8XkzAUXKFy9ULbh3THq+EUESqEnurUFmD/qlyZNerlM0gxQeuXk61QW/MG9aTBTXnlUQ86+KPbBlORunAs6ST0Nn+AU1sX/UnfCZBlrPQVMY1Y57MRaRviLLwpwpa5W0LKafR0iZHkK4o/WwQzRexsbBlqnR4zu/1b+92d6vYnfEiXIqxYLuB3TF5fy4iGBbuE8CtG7gUD209c+jvJUwcJCBOtGNXAZ65Q8iv25gXBB2BE7Q68BQN7IBsVzt0shzid+PcjNx0zIpMzkyEjwCB29UrucOdJqGazhAfZaFp2AvKpIYHmb+FP1jJ/1duIPifxXyrAhfnQZj2gbdwIDAQAB',
    permissions: ['nativeMessaging', 'storage', 'activeTab', 'scripting', 'contextMenus'],
    commands: {
      _execute_action: {
        suggested_key: { default: 'Ctrl+Shift+Y' },
        description: 'Open Cryptiq popup',
      },
    },
  },
});
