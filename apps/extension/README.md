# Install the Cryptiq browser extension

The Cryptiq browser extension is a **thin client**: it holds no keys and does no crypto. It
talks to your already-running, already-unlocked Cryptiq desktop app over a local
native-messaging bridge (a small Rust sidecar → a named pipe the app owns). It fills one secret
at a time, only when you click, and **never** auto-submits. If the app is closed or locked, the
extension can do nothing.

There is no Chrome Web Store listing yet (that is deferred to v3.1). For v3.0 you install it in
**$0 developer mode** — you build it from source and load it unpacked. That is deliberate: the
whole point of Cryptiq is that **you built it, so you can audit it.**

- **Primary path — build from source** (recommended; you can read every line first).
- **Fallback path — a prebuilt folder** (for a non-dev friend who was handed a
  `chrome-mv3` folder).

> **Windows-only for v3.0.** The native-host registration scripts are PowerShell (`.ps1`) and
> the dev environment is Windows. macOS is **not yet documented / CI-built** — a macOS install
> path will come later. Linux is out of scope for Cryptiq v1.

---

## Prerequisites

- Windows 10/11 with **PowerShell**.
- A Chromium browser: **Chrome** or **Edge** (Brave piggybacks on Chrome's registry key and
  should work too, untested).
- The **Cryptiq desktop app** built and runnable locally (this repo's `apps/desktop`).
- For the build-from-source path: **Node ≥ 20 + pnpm 10** and a **Rust toolchain** (`cargo`).

---

## Install (build from source — primary path)

All commands run from the repository root unless a `cd` says otherwise.

### 1. Build the native-host sidecar

```powershell
cd apps/native-host
cargo build
# produces apps/native-host/target/debug/cryptiq-nmhost.exe
```

This is the small proxy binary Chrome spawns per connection. It is **not** the Cryptiq GUI —
it just relays bytes between the browser and the running app's named pipe (`\\.\pipe\cryptiq-bridge`).

### 2. Build the extension (production build)

```powershell
cd apps/extension
pnpm install
pnpm exec wxt build
# produces apps/extension/.output/chrome-mv3
```

Use the **production** build (`wxt build`, no `--mode development`) for a real install — it
strips the dev-only "send echo" affordance (`DevEcho.svelte`) so nothing dev-only ships.

### 3. Load the unpacked extension and read the REAL extension ID

1. Open `chrome://extensions` (or `edge://extensions`).
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked** and select `apps/extension/.output/chrome-mv3`.
4. **Read the extension ID Chrome/Edge shows on the extension card.** Call this
   `<REAL_EXTENSION_ID>`.

> **Extension-ID caveat — do not skip this.** The extension pins a deterministic ID,
> `pmnfhbonekjokipcfeklbajepnjppnca` (derived from the committed public key in `wxt.config.ts`).
> That value is **algorithmic and still browser-unconfirmed on your machine.** ALWAYS read the
> real ID from `chrome://extensions` after loading unpacked, and if it differs from the pinned
> value, use **your** real ID for registration below. Registering the wrong ID means the native
> host would trust the wrong extension — this is a security boundary, not a formality.

### 4. Register the native host with the browser-confirmed ID

```powershell
powershell -ExecutionPolicy Bypass -File scripts/native-host/register-native-host.ps1 `
  -SidecarPath (Resolve-Path apps/native-host/target/debug/cryptiq-nmhost.exe) `
  -ExtensionId <REAL_EXTENSION_ID>
```

Both `-SidecarPath` and `-ExtensionId` are **mandatory**. The script writes:

- the native-host manifest to `%APPDATA%\Cryptiq\com.cryptiq.bridge.json`
  (with `allowed_origins` **pinned to your one extension ID** — never a wildcard), and
- the Chrome **and** Edge `HKCU\...\NativeMessagingHosts\com.cryptiq.bridge` registry keys.

Quick sanity check:

```powershell
Test-Path "$env:APPDATA\Cryptiq\com.cryptiq.bridge.json"   # expect: True
```

> **Manual step only (DIST-02 deferred).** Dev-mode install does not run the NSIS installer, so
> you register the host by hand as above. The installer wiring exists
> (`apps/desktop/src-tauri/windows/hooks.nsh` shells out to this **same** script), but full
> installer auto-registration is deferred to a later phase (DIST-02).

### 5. Run Cryptiq and unlock your vault

Start the Cryptiq desktop app (e.g. `pnpm --filter desktop tauri dev` from `apps/desktop`, or a
built binary) and unlock your vault. The app owns the named-pipe listener; the extension can
only fill while the app is **running and unlocked**.

You're done. Click a login field's Cryptiq entry (or right-click → **Fill from Cryptiq**) to
fill. The first time an extension connects, the app shows a one-time **approval** dialog.

---

## Install (prebuilt folder — fallback for a non-dev friend)

If someone handed you a prebuilt `chrome-mv3` folder and a `cryptiq-nmhost.exe`, you can skip
the two build steps:

1. `chrome://extensions` → **Developer mode** on → **Load unpacked** → select the
   `chrome-mv3` folder → **read the real extension ID** off the card (same caveat as above).
2. Register the host, pointing `-SidecarPath` at wherever the `cryptiq-nmhost.exe` you were
   given lives:
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts/native-host/register-native-host.ps1 `
     -SidecarPath (Resolve-Path path\to\cryptiq-nmhost.exe) `
     -ExtensionId <REAL_EXTENSION_ID>
   ```
3. Run and unlock Cryptiq.

Building from source is still the honest, auditable path — prefer it if you can.

---

## Permissions — what each one is for, and why

The extension requests exactly **five** permissions. There is **no `host_permissions`, no
declarative `content_scripts`, and no `tabs` permission** — the extension never has standing
access to your pages or browsing history. Each permission traces to one live feature:

| Permission | Why it's needed | Scope / limit |
|---|---|---|
| `nativeMessaging` | Talk to the desktop app through the `cryptiq-nmhost` sidecar over the local named pipe (the entire bridge). | Local only; never a network port. Only the pinned extension ID is allowed to connect (`allowed_origins`). |
| `storage` | Persist the extension's own identity keypair + the app's returned public key + association label in `chrome.storage.local`, so a reconnect after a service-worker restart is silently re-trusted. | No secrets/passwords stored; browser-sandboxed local storage only. |
| `activeTab` | The popup reads the **current** tab's URL to build the `match-origin` request (which vault entries match this site). | Only the tab that triggered the popup, only on your gesture — not a standing per-origin grant. |
| `scripting` | Inject `fill.content.ts` on demand via `chrome.scripting.executeScript` **when you click Fill** — the content script is runtime-registered, never auto-run on page load. | Rides the `activeTab` gesture; no `host_permissions`, so no injection without your click. |
| `contextMenus` | Add the right-click **Fill from Cryptiq** / **Generate password** items on editable fields. | Only appears on your right-click; the handler uses the same `activeTab`-gated path as the popup. |

`commands._execute_action` in the manifest is **not** a permission — it's Chrome's reserved,
zero-code keyboard shortcut to open the popup (rebindable at `chrome://extensions/shortcuts`).

The production build is verified to **exclude** the dev-only `DevEcho` "send echo" affordance —
it exists only in `wxt build --mode development` builds.

---

## Turn it off

You can cut the extension connection for this device at any time, without deleting your
approved extensions: in the Cryptiq desktop app go to **Settings → Browser Extensions** and turn
off **"Allow browser extension connections."** Connections stop immediately (and stay off across
an app restart); your associations are kept, so flipping it back on resumes without re-approving.

To remove a single browser instead, use **Revoke** on its row.

## Uninstall / unregister the native host

```powershell
powershell -ExecutionPolicy Bypass -File scripts/native-host/unregister-native-host.ps1
```

This removes the manifest at `%APPDATA%\Cryptiq\com.cryptiq.bridge.json` and both browser
registry keys, leaving nothing orphaned. Then remove the unpacked extension from
`chrome://extensions`.

---

## Honest limits

- While the app is **unlocked and an extension is associated**, clicking Fill hands **exactly
  one** secret to the current page. That is the deal — click-to-fill is deliberate.
- The extension can't protect you from a compromised OS/browser, a malicious **other** extension
  in the same browser, or page-level XSS (a filled secret does land in that page's DOM).
- See the desktop app's **About → Security** screen for the full browser-extension threat model.
