# Phase 20 — Distribution & Hardening: Manual UAT (Phase Gate)

**Status:** PENDING human verification — the automated pre-UAT gate is GREEN (recorded below);
the three human scenarios (SC-1/SC-2/SC-3) have NOT yet been driven. All RESULT boxes are unchecked.

This is the **phase gate** for Phase 20. It proves the three ROADMAP Phase-20 success criteria
against the **running app + a real loaded extension** — the behaviors unit tests cannot prove:

- **SC-1 (DIST-01):** the documented `$0` dev-mode install works end-to-end following
  `apps/extension/README.md`, with no undocumented step.
- **SC-2 (UX-05):** the Settings kill-switch actually **stops** the extension connection on this
  device **and the OFF state persists across an app restart** (associations kept).
- **SC-3 (DOC-01):** the About/Security screen documents the extension's honest, both-sided threat
  model.

**Requires (single Windows machine — no 2nd PC needed this phase):**
- Cryptiq repo built locally (`apps/native-host` sidecar + `apps/desktop`).
- Chrome and/or Edge (Chromium-based; Brave piggybacks Chrome's registry key).
- PowerShell (the register/unregister scripts are `.ps1`).

---

## Automated pre-UAT gate (Task 1 — RECORDED)

Run before any human step, per the phase-gate discipline. **All green** (the sole svelte-check
error is the pre-existing, out-of-scope, deferred `syncOrchestration.test.ts:364` cast — it does
NOT gate this phase; tracked in `deferred-items.md`).

**Run:** 2026-07-06 (executor Task 1). Do NOT `cargo clean` (Smart App Control / build-script debt).

| Gate command | Result | Evidence |
|---|---|---|
| `pnpm --filter @cryptiq/core test` | ✅ PASS | 30 test files, **431 passed** (crypto/vault/entries/sync/config KATs) |
| `pnpm --filter @cryptiq/extension test` | ✅ PASS | 12 test files, **99 passed** (incl. `bridgeRpc` 11, `manifest` 6, `associationCrypto` 5) |
| `pnpm --filter @cryptiq/extension build` (`wxt build`, production) | ✅ PASS | Built `chrome-mv3` in ~6.2s, Σ 142.69 kB (`manifest.json`/`popup.html`/`background.js`/`fill.js`) |
| `pnpm --filter desktop exec svelte-check` | ✅ PASS (gate) | **943 files, 1 ERROR** — the KNOWN deferred `syncOrchestration.test.ts:364` `schemaVersion:99` cast (out of scope; not a Phase-20 regression). The trailing `svelte-check not found` line is the spurious Windows pnpm-exec artifact — read the COMPLETED line. |
| `cargo build --manifest-path apps/desktop/src-tauri/Cargo.toml` | ✅ PASS | Finished dev profile; 3 pre-existing dead-code warnings only (`sas_display`/`sas_raw`/`PairingSession` fields) — no errors |
| `cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml extension_bridge` | ✅ PASS | **33 passed; 0 failed** (incl. `test_wrong_token_rejected`, `test_process_rpc_full_pipeline_requires_both_box_open_and_token_match`, `test_version_mismatch_directional_message`, `test_associate_already_associated_key_is_silently_trusted_no_prompt`) |

**Gate verdict: GREEN.** Proceed to the human scenarios below.

---

## Real artifacts referenced below (do not substitute placeholders)

| Artifact | Value | Source |
|---|---|---|
| Sidecar binary (dev) | `apps/native-host/target/debug/cryptiq-nmhost.exe` | README §1 |
| Prod extension build output | `apps/extension/.output/chrome-mv3` | README §2 (`wxt build`, no `--mode development`) |
| Named pipe | `\\.\pipe\cryptiq-bridge` | 14-01/14-02-SUMMARY.md |
| Native-host name | `com.cryptiq.bridge` | 14-04-SUMMARY.md |
| Manifest path | `%APPDATA%\Cryptiq\com.cryptiq.bridge.json` | `register-native-host.ps1` |
| Register / unregister scripts | `scripts/native-host/register-native-host.ps1` / `unregister-native-host.ps1` (`-SidecarPath`, `-ExtensionId` both mandatory on register) | README §4 |
| Pinned extension ID (algorithmic; confirmed against a live Chromium load in Phase 14 SC-1) | `pmnfhbonekjokipcfeklbajepnjppnca` | 14-05-SUMMARY.md — **always read the REAL id from `chrome://extensions` after Load unpacked; if it differs, register with your real id** |
| Kill-switch config flag | `extensionBridgeEnabled?: boolean` (default `true`) in device-local `config.json`, NEVER `InnerDoc.settings` | 20-01-SUMMARY.md (D-04) |
| Kill-switch UI | Settings → **Browser Extensions**, toggle at the TOP: "Allow browser extension connections" | `ExtensionSettingsSection.svelte` (20-03, D-03) |
| Threat-model home | About → Security → **Threat Model** → "Browser extension" subsection | `AboutView.svelte` (20-04, D-12/D-13) |

> **Extension-ID caveat (do not skip):** the pinned value is algorithmic. ALWAYS read the real ID
> off the `chrome://extensions` card after Load unpacked, and register with that. Registering the
> wrong ID trusts the wrong extension — a security boundary, not a formality.

---

## Step 0 — One-time setup (do this before SC-1..SC-3)

This IS SC-1's install flow — perform it by following `apps/extension/README.md` verbatim (that
is exactly what SC-1 verifies). Summary of the README's primary build-from-source path:

1. **Build the sidecar:**
   ```powershell
   cd apps/native-host
   cargo build
   # produces apps/native-host/target/debug/cryptiq-nmhost.exe
   ```
2. **Build the extension (production):**
   ```powershell
   cd apps/extension
   pnpm install
   pnpm exec wxt build
   # produces apps/extension/.output/chrome-mv3 (prod — strips the dev-only DevEcho affordance)
   ```
3. **Load unpacked + read the REAL extension ID:** open `chrome://extensions` (or
   `edge://extensions`) → enable **Developer mode** → **Load unpacked** →
   `apps/extension/.output/chrome-mv3` → read `<REAL_EXTENSION_ID>` off the card (compare to the
   pinned value; use your real id if they differ).
4. **Register the native host with the browser-confirmed ID:**
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts/native-host/register-native-host.ps1 `
     -SidecarPath (Resolve-Path apps/native-host/target/debug/cryptiq-nmhost.exe) `
     -ExtensionId <REAL_EXTENSION_ID>
   Test-Path "$env:APPDATA\Cryptiq\com.cryptiq.bridge.json"   # expect: True
   ```
5. **Run Cryptiq and unlock your vault** (e.g. `pnpm --filter desktop tauri dev` from `apps/desktop`,
   or a built binary). The app owns the named-pipe listener; the extension can only fill while the
   app is running **and** unlocked.

---

## SC-1 — DIST-01: `$0` dev-mode install works end-to-end (following the README)

**Requirement:** DIST-01
**Verifies:** T-20-15 — the documented install is sufficient with no undocumented step.
**Preconditions:** Clean state (no prior registration/association is fine — but do the whole flow
from the README so a genuinely-first install is exercised).

### Steps
1. From a clean checkout state, follow **`apps/extension/README.md`** "Install (build from source —
   primary path)" top to bottom — the Step 0 summary above mirrors it, but read the README itself
   so any gap in *the README* surfaces.
2. Build the sidecar (`cd apps/native-host; cargo build`).
3. Build the extension in **production** mode (`cd apps/extension; pnpm install; pnpm exec wxt build`).
4. `chrome://extensions` → Developer mode → **Load unpacked** → `apps/extension/.output/chrome-mv3`.
5. **Read the REAL extension ID** off the card. If it differs from `pmnfhbonekjokipcfeklbajepnjppnca`,
   use your real id for step 6.
6. Run `register-native-host.ps1` with `-SidecarPath (Resolve-Path ...cryptiq-nmhost.exe)` and
   `-ExtensionId <REAL_EXTENSION_ID>`. Confirm
   `Test-Path "$env:APPDATA\Cryptiq\com.cryptiq.bridge.json"` → `True`.
7. Start Cryptiq and **unlock** your vault.
8. Navigate a browser tab to a site for which you have a vault entry (or add one first). Open the
   Cryptiq extension popup (or right-click a login field → **Fill from Cryptiq**).
9. On the **first** connection, approve the one-time association dialog in the Cryptiq app window
   (grouped-hex fingerprint + browser label + Approve/Deny). Approve.
10. Click the matching entry's **Fill** in the popup (or the context-menu Fill).

### Expected result (PASS criteria)
- Every README step is **sufficient as written** — you never had to improvise an undocumented step.
- The one-time approval dialog appears on first connect; after approving, the association is
  remembered.
- Clicking **Fill** fills the username + password into the page's login fields (click-to-fill;
  **never** auto-submits).
- If the app were closed or locked, the extension would do nothing — but here, unlocked + running,
  the fill succeeds end-to-end (extension → sidecar → `\\.\pipe\cryptiq-bridge` → app → back).

### RESULT
- [ ] PASS
- [ ] FAIL — describe (and note which README step was missing/wrong, if any):

---

## SC-2 — UX-05: kill-switch disables the connection AND persists across restart

**Requirement:** UX-05
**Verifies:** T-20-14 — OFF actually refuses a real extension connection (runtime, not UI-only) and
survives an app restart; associations are kept.
**Preconditions:** SC-1 passed (a valid association exists, fill works while ON).

### Steps — turn OFF and confirm it stops the connection
1. In the Cryptiq app, go to **Settings → Browser Extensions**.
2. Toggle **"Allow browser extension connections"** to **OFF** (the toggle at the TOP of the
   section, above the associations list).
3. Confirm the small note **"Connections are off — associations are kept"** appears, and that the
   existing association(s) are **still listed** below (not deleted).
4. From the browser, trigger a fresh extension request — open the popup and/or click **Fill** on a
   login page (force a new native-messaging connection; if the popup was open, close and reopen it).

### Expected result (2a — OFF stops it)
- The extension now shows a **disconnected / app-not-running** state — **NO fill happens**. The
  app-side named-pipe accept loop was cancelled (20-01 `cancel_tx`), so the sidecar cannot reach a
  listener.
- The associations list is **still shown** in Settings (paused, not forgotten).

### Steps — restart and confirm OFF persisted
5. **Fully quit** Cryptiq (all windows; confirm the process is gone in Task Manager).
6. **Relaunch** Cryptiq and unlock.
7. Open **Settings → Browser Extensions** and check the toggle state.
8. Trigger a fresh extension request again (popup / Fill).

### Expected result (2b — OFF survives restart)
- The toggle is **still OFF** after the restart (the `extensionBridgeEnabled:false` flag persisted
  in `config.json`; the boot spawn stayed gated off — 20-01 D-04).
- The extension **still cannot connect** — no fill, disconnected/app-not-running again.

### Steps — turn back ON and confirm silent resume
9. Toggle **"Allow browser extension connections"** back **ON**.
10. Trigger an extension request (popup / Fill on a matching site).

### Expected result (2c — ON resumes, no re-approval)
- The extension **connects again** and **Fill works** — WITHOUT a new approval dialog. The prior
  association is still trusted (associations were kept through the whole OFF→restart→ON cycle,
  D-02).

### RESULT
- [ ] PASS
- [ ] FAIL — describe (note which of 2a / 2b / 2c failed):

---

## SC-3 — DOC-01: About/Security documents the honest both-sided threat model

**Requirement:** DOC-01
**Preconditions:** none (this is a read/inspection of the running app's UI).

### Steps
1. In the Cryptiq app, open **About → Security** and scroll to the **Threat Model** section.
2. Find the **"Browser extension"** subsection.
3. Read both the **defends-against** list and the **does-NOT-defend-against** list.

### Expected result (PASS criteria)
- A dedicated **"Browser extension"** subsection exists within the Threat Model section.
- **Defends against** (green-check bullets) includes: thin client / no keys or crypto in the browser;
  wire-minimization (only the clicked secret crosses; pickers get metadata only); per-origin (eTLD+1)
  matching; explicit one-time association/approval; click-to-fill, never auto-submit; cross-origin
  iframe refusal.
- **Does NOT defend against** (red-X bullets) includes the **verbatim, unsoftened** line:
  > "While the app is unlocked and an extension is associated, clicking Fill hands exactly one secret
  > to the current page."
  plus: a compromised OS/browser; a **malicious other extension** in the same browser; **page-level
  XSS** (a filled secret does land in that page's DOM); residual DOM-clickjacking risk.
- The subsection **names the extension's permission set** — `nativeMessaging`, `storage`,
  `activeTab`, `scripting`, `contextMenus` — agreeing with the permission table in
  `apps/extension/README.md`.
- Tone/format matches the rest of the Threat Model section (concise bullets, the KeePass/Bitwarden
  honesty bar — no softening, no long prose).

### RESULT
- [ ] PASS
- [ ] FAIL — describe (note any missing bullet or softened wording):

---

## Sign-off

- [ ] SC-1 PASS · [ ] SC-2 PASS · [ ] SC-3 PASS → **Phase 20 gate cleared.**
- If any SC failed, record the failure above and route back to the owning plan
  (SC-1 → 20-02 README / 20-01 backend; SC-2 → 20-01 backend + 20-03 toggle; SC-3 → 20-04 AboutView).

---

*Phase: 20-distribution-hardening*
*Automated gate recorded: 2026-07-06 (GREEN). Human SC-1/SC-2/SC-3 boxes above are PENDING — this
document has not yet been executed by a human.*
