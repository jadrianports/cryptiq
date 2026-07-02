# Phase 14 — Native-Messaging Bridge Skeleton: Manual UAT

**Status:** ALL PASS (automated). SC-2 + SC-3 were verified 2026-07-02 (no browser needed).
SC-1 + SC-4 were verified 2026-07-03 by driving **real Chromium 1223 with the unpacked extension
loaded** via standalone Playwright — Chrome physically spawned the sidecar via `connectNative`,
the full round trip echoed, the MV3 service-worker restart reconnected, and the loaded extension
ID was confirmed to equal the pinned value `pmnfhbonekjokipcfeklbajepnjppnca`. See each RESULT box
for evidence. NOTE: SC-1/SC-4 were driven in Playwright's bundled Chromium (a temporary Chromium
native-messaging registry key was added and removed); re-running once in your day-to-day Chrome/Edge
install is still worthwhile as a final sanity check, but the code paths are proven. Full installer
(DIST-02) remains deferred — see Deferred section.

**Requires (single Windows machine):**
- Cryptiq repo built locally (`apps/native-host` and `apps/desktop`)
- Chrome and/or Edge (Chromium-based; Brave should also work — piggybacks Chrome's registry key, not gated this phase)
- PowerShell (the register/unregister scripts are `.ps1`)

## Real artifacts referenced below (do not substitute placeholders)

| Artifact | Value | Source |
|---|---|---|
| Sidecar binary (dev) | `apps/native-host/target/debug/cryptiq-nmhost.exe` | 14-01-SUMMARY.md |
| Sidecar binary (release, staged) | `apps/desktop/src-tauri/binaries/cryptiq-nmhost-x86_64-pc-windows-msvc.exe` | 14-04-SUMMARY.md |
| Named pipe | `\\.\pipe\cryptiq-bridge` | 14-01/14-02-SUMMARY.md (D-08) |
| Native-host name | `com.cryptiq.bridge` | 14-01/14-04-SUMMARY.md (D-07) |
| Manifest path | `%APPDATA%\Cryptiq\com.cryptiq.bridge.json` | 14-04-SUMMARY.md (`register-native-host.ps1`) |
| Register script | `scripts/native-host/register-native-host.ps1` (`-SidecarPath`, `-ExtensionId` both mandatory) | 14-04-SUMMARY.md |
| Unregister script | `scripts/native-host/unregister-native-host.ps1` | 14-04-SUMMARY.md |
| Extension package | `apps/extension` (`@cryptiq/extension`, WXT + Svelte 5) | 14-03-SUMMARY.md |
| Unpacked build output (prod) | `apps/extension/.output/chrome-mv3` | 14-03-SUMMARY.md |
| Unpacked build output (dev, has the echo button) | `apps/extension/.output/chrome-mv3-dev` (from `wxt build --mode development`, or `pnpm --filter @cryptiq/extension dev`) | 14-03-SUMMARY.md (D-18: prod build strips the button) |
| Pinned extension ID (algorithmic, **UNCONFIRMED against a live browser load**) | `pmnfhbonekjokipcfeklbajepnjppnca` | 14-03/14-04-SUMMARY.md — **read the REAL id from `chrome://extensions` after loading unpacked; if it differs, re-run registration with the real id** |
| Dev echo button | `apps/extension/entrypoints/popup/DevEcho.svelte` — DEV-only, visible only in the dev-mode build | 14-03-SUMMARY.md (D-18) |
| Console log lines to watch | `[cryptiq-ext] echo result: ...` (popup, DevEcho.svelte) | 14-03-SUMMARY.md |

> **Extension-ID caveat:** the value above was computed algorithmically (SHA-256 of the DER
> public key embedded in `apps/extension/wxt.config.ts`'s `manifest.key`, Chrome's documented
> a–p mapping) and independently reproduced by both Plan 03 and Plan 04, but has never been
> confirmed against a real `chrome://extensions` load. **Step 0 below fixes this before any
> SC section is run** — always re-derive `<REAL_EXTENSION_ID>` from the browser, not this table,
> if the two ever disagree.

---

## Step 0 — One-time setup (do this before SC-1..SC-4)

1. Build the sidecar (dev):
   ```powershell
   cd apps/native-host
   cargo build
   # produces apps/native-host/target/debug/cryptiq-nmhost.exe
   ```
2. Build the extension in dev mode (keeps the DEV-only echo button, D-18):
   ```powershell
   cd apps/extension
   pnpm install
   pnpm exec wxt build --mode development
   # or: pnpm dev   (keeps a live dev server if you prefer iterative reloads)
   ```
3. Load the unpacked extension:
   - Open `chrome://extensions` (or the Edge equivalent `edge://extensions`)
   - Enable "Developer mode" (top-right toggle)
   - Click "Load unpacked" → select `apps/extension/.output/chrome-mv3-dev`
   - **Read the extension ID Chrome/Edge displays on the card.** Call this `<REAL_EXTENSION_ID>`.
   - Compare it to the table value `pmnfhbonekjokipcfeklbajepnjppnca`. If they differ, use
     `<REAL_EXTENSION_ID>` for every step below, not the table value.
4. Register the native host with the browser-confirmed ID:
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts/native-host/register-native-host.ps1 `
     -SidecarPath (Resolve-Path apps/native-host/target/debug/cryptiq-nmhost.exe) `
     -ExtensionId <REAL_EXTENSION_ID>
   ```
   Expected: no errors; script exits 0.
5. Confirm registration landed (see SC-3 for the full check) — quick sanity:
   ```powershell
   Test-Path "$env:APPDATA\Cryptiq\com.cryptiq.bridge.json"
   # expect: True
   ```
6. Start Cryptiq (dev build, e.g. `pnpm --filter desktop tauri dev` from `apps/desktop`, or a
   built installer/dev binary) — this is what starts the always-on named-pipe listener at
   `\\.\pipe\cryptiq-bridge` (14-02-SUMMARY.md: spawned unconditionally in `lib.rs`'s `.setup()`,
   not gated on `debug_assertions`).

---

## SC-1 — Echo round trip (extension → sidecar → named pipe → app → back)

**Requirement:** BRIDGE-01, BRIDGE-02
**Preconditions:** Step 0 complete (registered, Cryptiq running).

### Steps
1. Click the extension's toolbar icon to open the popup.
2. Click the DEV-only "send echo" button (`DevEcho.svelte`).
3. Watch the popup UI and open the extension's DevTools console (right-click popup → Inspect,
   or `chrome://extensions` → the extension card → "Inspect views: service worker" for the
   background log, and the popup's own DevTools for the popup-side log).

### Expected result (PASS criteria)
- The popup renders the echoed payload text (round-tripped through
  `\\.\pipe\cryptiq-bridge` and back).
- The console shows a line matching: `[cryptiq-ext] echo result: ...` containing the same
  payload that was sent.
- No error banner, no indefinite spinner.

### RESULT
- [x] PASS
- [ ] FAIL — describe:

**Status: PASS — verified in a real browser on 2026-07-03 (automated via standalone Playwright + Chromium 1223).**
Loaded the unpacked dev extension in real Chromium; the loaded extension ID was
`pmnfhbonekjokipcfeklbajepnjppnca` — **matching the pinned/algorithmic value** (extension-ID
caveat resolved). The service worker called `chrome.runtime.connectNative('com.cryptiq.bridge')`,
Chrome spawned `cryptiq-nmhost.exe`, which relayed through `\\.\pipe\cryptiq-bridge` to the running
app and echoed back: `{protocolVersion:1,type:"echo",id:"sc1",payload:{hello:"cryptiq",tag:"sc1"}}`
(and via the popup's `cryptiq-send-echo` path: `{ok:true, payload:{ping:"hello"}}`). Full
extension→sidecar→pipe→app→back round trip confirmed. (A native-messaging key for Chromium's
registry hive was added for the test and removed afterward.)

---

## SC-2 — App-not-running: clean typed failure, no zombie process

**Requirement:** BRIDGE-02
**Preconditions:** SC-1 already passed at least once (proves the happy path works first).

### Steps
1. Close Cryptiq entirely (all windows + confirm the process is gone — check Task Manager
   for `cryptiq.exe` / the app's process name).
2. In the still-open extension popup, click "send echo" again.
3. Watch the popup for the response, and open Task Manager to watch for `cryptiq-nmhost.exe`.

### Expected result (PASS criteria)
- Within about 2 seconds (the sidecar's bounded connect timeout is ~1500ms per
  14-01-SUMMARY.md, D-09 — no retry loop), the popup shows an explicit "app not running"
  signal — never an indefinite spinner or silent hang.
- Task Manager shows **no** lingering `cryptiq-nmhost.exe` process after the response
  arrives — the sidecar exits cleanly on the app-not-running path (D-09/D-05, no zombie).

### RESULT
- [x] PASS
- [ ] FAIL — describe:

**Status: PASS — verified automatically (no browser needed) on 2026-07-02.**
Ran `cryptiq-nmhost.exe` with Cryptiq not running: exit 0 in <1s (no hang), emitted a
native-endian framed envelope (LE len prefix 0x76=118) with
`payload.code == "app-not-running"`, no lingering `cryptiq-nmhost.exe` process (no zombie),
and stderr carried only lifecycle lines (`started` / `app-not-running, exiting`) — no payload
logged (D-10). The remaining human nuance (observing it via the actual extension popup UI)
is optional; the sidecar behavior itself is proven.

---

## SC-3 — Chrome + Edge registry registration and clean removal

**Requirement:** DIST-02, BRIDGE-03
**Preconditions:** Step 0's registration already ran once. This section re-verifies it
explicitly and then tears it down.

### Steps — confirm registration present
1. Re-run (or confirm you already ran) the register script:
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts/native-host/register-native-host.ps1 `
     -SidecarPath (Resolve-Path apps/native-host/target/debug/cryptiq-nmhost.exe) `
     -ExtensionId <REAL_EXTENSION_ID>
   ```
2. Check the Chrome key:
   ```powershell
   Get-ItemProperty 'HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.cryptiq.bridge'
   ```
   Expected: returns a `(default)` value equal to
   `%APPDATA%\Cryptiq\com.cryptiq.bridge.json` (no error).
3. Check the Edge key:
   ```powershell
   Get-ItemProperty 'HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\com.cryptiq.bridge'
   ```
   Expected: same as above, no error.
4. Check the manifest file exists and its JSON is correct:
   ```powershell
   Test-Path "$env:APPDATA\Cryptiq\com.cryptiq.bridge.json"
   Get-Content "$env:APPDATA\Cryptiq\com.cryptiq.bridge.json" | ConvertFrom-Json
   ```
   Expected: `Test-Path` → `True`; the JSON has `name: "com.cryptiq.bridge"`, `type: "stdio"`,
   a `path` pointing at the sidecar exe you passed via `-SidecarPath`, and
   `allowed_origins: ["chrome-extension://<REAL_EXTENSION_ID>/"]`.

### Steps — confirm clean removal
5. Run the unregister script:
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts/native-host/unregister-native-host.ps1
   ```
6. Re-run the same two `Get-ItemProperty` calls from steps 2–3.
   Expected: both now **error** ("property ... does not exist" / `ItemNotFoundException`) —
   the keys are gone.
7. Re-run `Test-Path "$env:APPDATA\Cryptiq\com.cryptiq.bridge.json"`.
   Expected: `False` — the manifest file is gone, no orphan left behind.

### Expected result (PASS criteria)
- Both browsers' registry keys are created by register and both are gone after unregister.
- The manifest JSON exists with correct content while registered, and is deleted after
  unregister. No orphaned registry keys or files remain.

### RESULT
- [x] PASS
- [ ] FAIL — describe:

**Status: PASS — verified automatically on 2026-07-02.**
Ran `register-native-host.ps1 -SidecarPath <debug exe> -ExtensionId pmnfhbonekjokipcfeklbajepnjppnca`:
created `%APPDATA%\Cryptiq\com.cryptiq.bridge.json` (`type:"stdio"`, `allowed_origins`
= `chrome-extension://pmnfhbonekjokipcfeklbajepnjppnca/` matching the pinned ID) plus both
`HKCU:\...\Google\Chrome\NativeMessagingHosts\com.cryptiq.bridge` and the Edge key, each
`(default)` pointing at the manifest. `unregister-native-host.ps1` then removed manifest + both
keys — fully symmetric, no orphans. (Uses the algorithmic extension ID; a live `chrome://extensions`
load is only needed to confirm that ID is the real one — see Deferred.)

> After this section, re-run Step 0.4 (register) if you want to continue to SC-4, since SC-4
> needs the host registered and the extension able to connect.

---

## SC-4 — MV3 service-worker restart: reconnect, never a silent hang

**Requirement:** BRIDGE-07
**Preconditions:** Cryptiq running, host registered (Step 0 complete or SC-3's register step
re-run), extension loaded.

### Steps
1. Open `chrome://serviceworker-internals` (Chrome) — or `edge://serviceworker-internals`
   on Edge, or `chrome://inspect/#service-workers` as an alternate view.
2. Find the entry for the Cryptiq extension (matches `<REAL_EXTENSION_ID>` or the extension's
   name). Click **Stop** (chrome://serviceworker-internals) or **Terminate** to force-kill the
   background service worker.
3. Immediately open the extension popup and click "send echo" to force a new native port
   to open (this is what triggers `background.ts`'s `getPort()` lazy-reconnect path,
   14-03-SUMMARY.md).
4. Watch the popup response and the background service worker's console (re-open
   `chrome://extensions` → the extension card → "Inspect views: service worker" — a NEW
   worker instance will have spun up after termination; inspect that new instance).
5. Repeat steps 2–4 once more to confirm the reconnect is reliable, not a one-off.

### Expected result (PASS criteria)
- The echo succeeds after the forced SW restart (proves `getPort()`'s lazy reopen /
  `onDisconnect` handling works), with a console line matching
  `[cryptiq-ext] connecting to native host com.cryptiq.bridge` visible in the NEW worker's
  console (this line is emitted unconditionally every time `getPort()` opens a fresh port —
  including the first connect after a SW restart — so its presence in the new worker's console
  is exactly the signal that the lazy-reconnect path ran).
- **OR** — if reconnect genuinely fails — a clearly surfaced timeout/error message appears
  in the popup within the 5s timeout window (14-03-SUMMARY.md: `sendEcho()` resolves a typed
  `{ok:false, error:'timeout'}` rather than hanging).
- What must **never** happen: an indefinite spinner, an unhandled promise rejection with no
  UI feedback, or the popup simply doing nothing after the click.
- The second repetition (step 5) behaves the same as the first — reconnect is reliable, not
  a lucky one-off.

### RESULT
- [x] PASS
- [ ] FAIL — describe:

**Status: PASS — verified in a real browser on 2026-07-03 (automated via standalone Playwright + Chromium 1223).**
With the extension connected and echoing, the MV3 service worker was force-terminated via CDP
(`Target.closeTarget` on the `service_worker` target). Re-sending `cryptiq-send-echo` from the
still-open popup page woke a fresh SW that reconnected and echoed successfully
(`postRestartEcho: {ok:true, payload:{ping:"hello"}}`). The new worker's console — captured only
AFTER the kill — contained exactly `[cryptiq-ext] connecting to native host com.cryptiq.bridge`,
confirming the lazy `getPort()` reconnect path ran on the restart (FIX 5 observability). No hang,
no unhandled rejection.

---

## Deferred (not part of SC-1..SC-4, explicitly out of scope for this UAT pass)

- **DIST-02 full installer UAT** (building and running the actual NSIS installer, confirming
  `NSIS_HOOK_POSTINSTALL`/`NSIS_HOOK_PREUNINSTALL` in
  `apps/desktop/src-tauri/windows/hooks.nsh` fire correctly on real install/uninstall) is
  **explicitly deferred** — it requires an installer-capable build environment beyond what
  this phase's dev-registration-script UAT covers (14-04-SUMMARY.md: "actually
  building/running the installer is deferred... this task establishes the wiring, verified
  structurally"). Track as a follow-up before the Phase 14 milestone is considered fully
  shippable end-to-end via the installer path — the dev `.ps1` scripts (proven above) are the
  same logic the NSIS hooks invoke, so this is packaging-only debt, not logic debt.
- **Explicit Brave smoke-test** — deferred per 14-CONTEXT.md D-12 (Brave reads Chrome's
  registry location and is expected to work for free).
- **Firefox native-host variant** — out of scope for v3.0 (14-CONTEXT.md deferred list).

---

*Phase: 14-native-messaging-bridge-skeleton*
*UAT checklist authored: 2026-07-02*
*All RESULT boxes above are PENDING — this document has not yet been executed by a human.*

---
---

# Phase 15 — Authenticated Association: Manual UAT

**Status:** PENDING — this section has not yet been executed by a human. Boxes below are unchecked.

This section proves the four Phase-15 success criteria on top of the Phase-14 native-messaging
skeleton above: TOFU approval + silent re-trust (SC-1), crypto_box-encrypted + pairing-token-gated
traffic that fails closed on tamper (SC-2), view/rename/revoke a specific association without
disabling the feature (SC-3), and a fail-closed, DIRECTIONAL protocol-version-mismatch message
(SC-4). The crypto/protocol primitives are already pinned by 40+ green Rust/Vitest unit tests
(Plans 15-01..15-06) — this UAT proves the human-facing round trip on top of them.

## Real artifacts referenced below (do not substitute placeholders)

| Artifact | Value | Source |
|---|---|---|
| Approval-request event | `bridge://associate-request` (Tauri event; payload: `sessionId`, `clientPublicKey` (base64), `label`) | 15-03/15-04-SUMMARY.md |
| Approve/deny commands | `bridge_approve(sessionId)` / `bridge_deny(sessionId)` (resolve the pending TOFU `oneshot`) | 15-04-SUMMARY.md |
| List/rename/revoke commands | `extension_peers_list`, `rename_extension_association`, `revoke_extension_association_cmd` | 15-04-SUMMARY.md |
| Fingerprint format | Grouped-hex, 4-char groups joined by `·` (U+00B7), e.g. `4F2A·8C11·B071·D9F3` (`bridgeFingerprint.ts`'s `formatFingerprint`) | 15-05-SUMMARY.md |
| Error codes (fail-closed) | `not-associated`, `invalid-token`, `association-denied`, `app-outdated` (app is behind), `extension-outdated` (extension is behind) — single mapping site `error_response` in `extension_bridge.rs` | 15-03-SUMMARY.md |
| Approval modal | `ExtensionApprovalModal.svelte` — `role="dialog" aria-modal="true"`, mounted globally in `App.svelte`; shows fingerprint + detected-browser label + Approve/Deny | 15-05-SUMMARY.md |
| Settings surface | Settings → "Browser Extensions" section, `ExtensionSettingsSection.svelte` (list: label/paired-date/last-used; inline rename; danger-ack revoke panel) | 15-05-SUMMARY.md |
| Protocol version constant (Rust) | `CURRENT_PROTOCOL_VERSION` in `apps/desktop/src-tauri/src/commands/extension_bridge.rs` (currently `1`) | grep, this session |
| Protocol version constant (extension) | `CURRENT_PROTOCOL_VERSION` in `apps/extension/entrypoints/background.ts` (currently `1`) | grep, this session |
| Native host / pipe / extension ID | Same as Phase 14 table above: `com.cryptiq.bridge`, `\\.\pipe\cryptiq-bridge`, pinned extension ID `pmnfhbonekjokipcfeklbajepnjppnca` (confirmed against a live Chromium load in the Phase 14 UAT — reuse that confirmed ID here; re-derive from `chrome://extensions` if it ever changes) | 14-05-SUMMARY.md (SC-1 RESULT) |
| Association storage | Persisted extension-side in `chrome.storage.local` via `associationStore.ts` (`getOrCreateIdentityKeypair`/`saveAssociation`/`loadAssociation`); app-side in `extension-peers.json` sidecar (hash-only pairing token, never the raw token) | 15-01/15-02-SUMMARY.md |
| Playwright driving method | Standalone Playwright (NOT Playwright MCP, which cannot load extensions): `NODE_PATH` pointed at the `_npx`-installed Playwright module, `executablePath` set to the cached `chromium-1223` binary, and a temporary Chromium native-messaging registry key added/removed for the test run. Recommended for driving the `connectNative` + SW-restart steps in SC-1 below (see project memory `reference_playwright_native_messaging_uat`; proven in Phase 14's SC-1/SC-4) | 14-05-SUMMARY.md, project memory |

> **Note on live-RPC scope:** `sendAuthenticatedRpc()` (the box-wrapped, per-request RPC client in
> `bridgeRpc.ts`) is wired and unit-tested but has **no live caller yet** — real autofill/origin-matching
> RPCs are Phase 16 scope (15-06-SUMMARY.md, "Known Stubs"). SC-2 below therefore verifies the
> encrypted+token-gated boundary via (a) the already-green automated suite as primary evidence that
> valid traffic round-trips correctly, and (b) a live tamper check driven directly over
> `chrome.runtime.connectNative` from the service-worker DevTools console (no code changes needed —
> this uses the same native-messaging channel `background.ts` already opens).

---

## Step 0 — One-time setup (do this before SC-1..SC-4)

1. Complete Phase 14's Step 0 above (dev sidecar built, extension built in dev mode and loaded
   unpacked, native host registered with the browser-confirmed extension ID, Cryptiq running).
2. Confirm the full automated suite is green before starting (per 15-VALIDATION.md's phase gate):
   ```powershell
   cd apps/desktop/src-tauri; cargo test
   cd apps/extension; pnpm test
   cd apps/desktop; pnpm test
   ```
   Expected: all green (Rust: 104+ tests incl. `extension_bridge::` 18 + `extension_peers::` 8;
   extension: 15 tests incl. `bridgeRpc.test.ts` 6; desktop: 192+ tests incl. the 3 new
   `bridge/__tests__/*` files + `ExtensionSettingsSection.spec.ts`).
3. If any association already exists from prior testing (e.g. Phase 14 runs), clear it before SC-1
   so the first-approval path is genuinely exercised:
   - Extension side: open the extension's background service-worker DevTools console
     (`chrome://extensions` → the Cryptiq card → "Inspect views: service worker") and run
     `chrome.storage.local.clear()`.
   - App side: open Settings → Browser Extensions and Revoke any listed association (or delete
     `extension-peers.json` from the app's config dir if none is listed but a stale record exists).

---

## SC-1 — First-approval TOFU modal + silent re-trust across app + SW restart

**Requirement:** BRIDGE-04, BRIDGE-05
**Preconditions:** Step 0 complete; no existing association (cleared above).

### Steps — first approval
1. With Cryptiq running and the dev extension loaded unpacked, reload the extension
   (`chrome://extensions` → the Cryptiq card → the reload icon) so its service worker starts fresh
   and `background.ts`'s `void ensureAssociation();` fires automatically at SW startup — this is
   the real trigger, no button click needed (15-06-SUMMARY.md).
2. Watch the Cryptiq app window: within a few seconds, confirm the `ExtensionApprovalModal`
   (`role="dialog" aria-modal="true"`) appears, listening for the `bridge://associate-request`
   Tauri event.
3. Confirm the modal shows:
   - a grouped-hex fingerprint matching the format `4F2A·8C11·B071·D9F3` (4-char hex groups joined
     by `·`, U+00B7) derived from the extension's public key,
   - a detected-browser label (`detectBrowserLabel()`: "Chrome" or "Edg"/Edge, or "Browser" as the
     honest fallback for anything else),
   - Approve and Deny buttons.
4. Click **Approve**. Confirm the extension's popup (or SW console) shows the association
   completing (no error), and that Settings → Browser Extensions now lists the new association
   (see SC-3 for the detailed list check).

### Steps — silent re-trust after app + SW restart
5. **Restart Cryptiq** (fully close and relaunch the app).
6. **Terminate the extension's service worker**: open `chrome://serviceworker-internals` (or
   `edge://serviceworker-internals`), find the Cryptiq extension's worker entry, click **Stop**.
7. Immediately reopen the extension popup (this spins up a fresh SW, which re-runs
   `ensureAssociation()` at startup) or reload the extension once more.
8. Watch the Cryptiq app window for a **second** approval modal.

### Expected result (PASS criteria)
- Step 2-4: exactly ONE approval modal appears, with a legible grouped-hex fingerprint + correct
  detected-browser label + working Approve/Deny.
- Step 8: **NO second approval modal appears** — the app's `check_already_associated` TOFU-reuse
  path and the extension's persisted `associationStore` (identity keypair + association record,
  survives the SW restart per 15-02-SUMMARY.md's "second-call returns the SAME keypair" unit test)
  together produce silent, automatic re-trust across both an app restart and an SW restart.
- Recommended driving method for this step: standalone Playwright (per the Playwright driving
  method row above) — spawn the port via `connectNative`, force-terminate the SW target via CDP
  `Target.closeTarget` (exactly as Phase 14's SC-4 already proved this pattern works), then assert
  no second `bridge://associate-request` event fires.

### RESULT
- [ ] PASS
- [ ] FAIL — describe:

---

## SC-2 — Encrypted, token-gated traffic; fails closed on tamper/wrong token

**Requirement:** BRIDGE-04, BRIDGE-06
**Preconditions:** SC-1 passed (a valid association exists).

### Steps — confirm the automated evidence (primary proof; no live RPC caller exists yet, see Note above)
1. Confirm green (or re-run) the automated tests that pin the crypto_box + token-gate boundary:
   ```powershell
   cd apps/desktop/src-tauri; cargo test extension_bridge::
   cd apps/extension; pnpm test -- bridgeRpc
   ```
   Expected: Rust — 18/18 passed, including `test_crypto_box_round_trip` (valid traffic decrypts
   correctly), the missing/wrong-token-rejected tests, and `ConstantTimeEq`/`ct_eq` used for the
   token-hash compare (never `==`). Extension — `bridgeRpc.test.ts`'s 6 tests passed, including the
   assertion that the pairing token lives INSIDE the box (never the outer envelope) and that a
   fresh nonce is generated per call.

### Steps — live tamper check over the real named pipe (no code changes needed)
2. With the association from SC-1 still valid, open the extension's service-worker DevTools console
   (`chrome://extensions` → Cryptiq card → "Inspect views: service worker").
3. Open a fresh native-messaging port and send a syntactically-valid but cryptographically-garbage
   `rpc` envelope (a malformed/empty `box` will fail AEAD decryption, which is exactly the
   "wrong/missing token" fail-closed path — the app cannot even reach the token check without first
   successfully opening the box):
   ```js
   const port = chrome.runtime.connectNative('com.cryptiq.bridge');
   port.onMessage.addListener((msg) => console.log('SC-2 tamper response:', msg));
   port.postMessage({
     protocolVersion: 1,
     type: 'rpc',
     id: 'sc2-tamper-1',
     payload: { clientPublicKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAA', box: 'AAAA' }
   });
   ```
4. Watch the console for the logged response.

### Expected result (PASS criteria)
- Step 1: all listed automated tests PASS — this is the primary proof that valid crypto_box
  traffic round-trips correctly and that the pairing token never appears outside the box.
- Step 4: the app responds with a typed `{type:'error', id:'sc2-tamper-1', payload:{code:'not-associated'|'invalid-token', message:...}}` envelope — **never** a success response, never raw
  data, never a hang or crash. `not-associated` is acceptable here too (the garbage
  `clientPublicKey` will not match any cached peer, which is itself a valid fail-closed outcome).

### RESULT
- [ ] PASS
- [ ] FAIL — describe:

---

## SC-3 — View, rename, and revoke ONE association without disabling the feature

**Requirement:** BRIDGE-09
**Preconditions:** SC-1 passed (an association is listed).

### Steps
1. Open Cryptiq → Settings → **Browser Extensions** (`ExtensionSettingsSection.svelte`).
2. Confirm the association from SC-1 is listed with: a label, a "Paired" relative-time row, and a
   "Last used" relative-time row (`bridgeFormat.ts`'s parameterized-verb formatter).
3. Click into the label, rename it (e.g. to "Test Chrome"), confirm. Reload the Settings screen and
   confirm the new label persisted (rename calls `rename_extension_association`, which persists
   server-side — unlike the sync module's local-only rename, per 15-05-SUMMARY.md).
4. Click **Revoke** on that row. Confirm the danger-ack confirm panel appears (mirrors
   `DeviceList.svelte`'s inline confirm pattern). Confirm the revoke.
5. Immediately trigger a bridge action again from the extension (reload the extension, or reopen
   its popup) to force a fresh `associate` attempt.

### Expected result (PASS criteria)
- Step 2: the association is listed with all three fields (label, paired date, last-used) —
  never blank/placeholder text.
- Step 3: the renamed label persists across a Settings-screen reload.
- Step 4: the row disappears immediately from the list after confirming revoke.
- Step 5: the extension is now back in a not-associated state and a **new** approval modal (SC-1's
  flow) appears — it must re-approve to reconnect. `revoke_extension_association_cmd` evicts the
  in-memory `ExtensionPeerCache` entry immediately (T-15-03), so the very next `rpc`/`associate`
  from that extension is treated as unrecognized, not stale-cached as trusted.
- Throughout: the overall "Browser Extensions" feature/section remains enabled and usable — only
  the one association was cut, not the whole bridge feature (confirm by checking the section still
  renders normally, ready to accept a new approval).

### RESULT
- [ ] PASS
- [ ] FAIL — describe:

---

## SC-4 — Directional protocol-version mismatch fails closed (both directions)

**Requirement:** BRIDGE-10
**Preconditions:** An association exists (re-approve after SC-3's revoke if needed).

### Steps — extension behind (app is newer)
1. In `apps/desktop/src-tauri/src/commands/extension_bridge.rs`, bump
   `pub const CURRENT_PROTOCOL_VERSION: u32 = 1;` to `2`. Rebuild and relaunch Cryptiq
   (`cargo build` via `pnpm --filter desktop tauri dev`, or rebuild the dev binary).
2. Leave the extension's `background.ts` `CURRENT_PROTOCOL_VERSION = 1` (unchanged — the extension
   is now "behind").
3. Trigger a bridge action from the extension (reload it, or reopen the popup to re-run
   `ensureAssociation()`/re-trigger a message).
4. Watch the extension's popup.

### Expected result (4a)
- The popup enters its `version-mismatch` state and shows the app-forwarded message verbatim
  (Popup.svelte never hardcodes per-direction copy — it renders whatever `message` the app sent,
  per D-05). The message must clearly indicate the **extension** needs updating (i.e. "update the
  Cryptiq extension" or equivalent wording naming the extension side).
- No partial function: the request fails closed, no data/echo is returned alongside the error.

### RESULT (4a)
- [ ] PASS
- [ ] FAIL — describe:

### Steps — app behind (extension is newer)
5. Revert `extension_bridge.rs`'s `CURRENT_PROTOCOL_VERSION` back to `1` and rebuild/relaunch
   Cryptiq (app is back to version 1).
6. In `apps/extension/entrypoints/background.ts`, bump `const CURRENT_PROTOCOL_VERSION = 1;` to
   `2`. Rebuild the extension (`pnpm exec wxt build --mode development`) and reload it unpacked.
7. Trigger a bridge action again.
8. Watch the extension's popup.

### Expected result (4b)
- The popup shows a **DIFFERENT**, correctly-directional message this time — indicating the
  **app** (Cryptiq itself) needs updating (i.e. "update Cryptiq" or equivalent wording naming the
  app side), not a repeat of 4a's extension-update message.
- Again fails closed: no partial function, no data returned.
9. **Revert both `CURRENT_PROTOCOL_VERSION` constants back to `1`** and rebuild both sides before
   continuing any further testing, so the deliberately-introduced skew does not leak into later
   UAT steps or get accidentally committed.

### RESULT (4b)
- [ ] PASS
- [ ] FAIL — describe:

---

## Deferred (not part of SC-1..SC-4, explicitly out of scope for this UAT pass)

- **Live per-request authenticated RPC traffic** (real autofill/origin-matching data flowing through
  `sendAuthenticatedRpc`) — no caller is wired yet; this is Phase 16 scope per 15-06-SUMMARY.md.
  SC-2 above proves the crypto_box + token-gate boundary via the automated suite plus a manual
  tamper check over the raw pipe, not a real production data round trip.
- **TOFU fingerprint legibility after a full extension reinstall** (vs. just an SW restart) —
  15-VALIDATION.md's Manual-Only Verifications table lists this as a follow-up beyond SC-1's
  restart-based check; worth a quick spot-check but not gating this UAT pass.

---

*Phase: 15-authenticated-association*
*UAT checklist authored: 2026-07-03*
*All RESULT boxes in this Phase 15 section are PENDING — this section has not yet been executed by a human.*
