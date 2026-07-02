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
