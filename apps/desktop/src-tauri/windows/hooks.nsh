; apps/desktop/src-tauri/windows/hooks.nsh
;
; DIST-02: NSIS installer hooks that reuse the EXACT SAME register/unregister
; .ps1 scripts from scripts/native-host/ — no NSIS-native WriteRegStr
; reimplementation (single source of truth, T-14-17). Both scripts are
; bundled to $INSTDIR\<name>.ps1 (install-dir root, alongside cryptiq.exe)
; via tauri.conf.json's bundle.resources MAP entry — the map VALUE is the
; destination path relative to $INSTDIR, so value "register-native-host.ps1"
; lands at $INSTDIR\register-native-host.ps1 (NOT a $INSTDIR\resources\
; subfolder — Tauri's NSIS bundler does not add a "resources" prefix for the
; map form). Array form would instead fold the "../../../" segments to "_up_"
; and stage under $INSTDIR\_up_\_up_\_up_\scripts\native-host\..., which the
; ExecWait calls below would silently miss — the map form pins stable names.
; VERIFIED by DIST-02 install-time smoke (2026-07-07): the earlier
; $INSTDIR\resources\... path failed with exit -196608 (file not found) and
; popped the POSTINSTALL failure MessageBox; $INSTDIR\... registers cleanly.
;
; D-14: the installer passes its own known install-dir path for the sidecar
; binary ($INSTDIR\cryptiq-nmhost.exe) — same script, different caller-
; supplied argument than the dev invocation (which passes target/debug).
;
; <PINNED_EXTENSION_ID> below is the D-15 stable extension ID derived from
; apps/extension/wxt.config.ts's manifest.key (SHA-256 of the DER public key,
; first 16 bytes mapped through a-p): pmnfhbonekjokipcfeklbajepnjppnca.
; Per 14-03-SUMMARY.md this was computed programmatically (not yet confirmed
; against a live chrome://extensions load) — reconfirm during Plan 05 UAT
; and update this literal if the browser-reported ID ever differs.

; NOTE: uses plain NSIS IntCmp (not LogicLib's ${If}) so this hook has zero
; dependency on whether LogicLib.nsh happens to be included by Tauri's
; generated installer template — IntCmp/Goto/labels are always available.

!macro NSIS_HOOK_POSTINSTALL
  DetailPrint "Registering Cryptiq native-messaging host..."
  ExecWait '"powershell.exe" -ExecutionPolicy Bypass -File "$INSTDIR\register-native-host.ps1" -SidecarPath "$INSTDIR\cryptiq-nmhost.exe" -ExtensionId "pmnfhbonekjokipcfeklbajepnjppnca"' $0
  IntCmp $0 0 postinstall_ok postinstall_warn postinstall_warn
  postinstall_warn:
    DetailPrint "WARNING: native-messaging host registration failed (exit code $0)."
    MessageBox MB_OK|MB_ICONEXCLAMATION "Cryptiq could not register its browser extension bridge (exit code $0). The browser extension will not be able to connect to Cryptiq until this is fixed. You can retry by running scripts\native-host\register-native-host.ps1 manually."
  postinstall_ok:
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  DetailPrint "Unregistering Cryptiq native-messaging host..."
  ExecWait '"powershell.exe" -ExecutionPolicy Bypass -File "$INSTDIR\unregister-native-host.ps1"' $0
  IntCmp $0 0 preuninstall_ok preuninstall_warn preuninstall_warn
  preuninstall_warn:
    DetailPrint "WARNING: native-messaging host unregistration failed (exit code $0)."
    MessageBox MB_OK|MB_ICONEXCLAMATION "Cryptiq could not fully remove its browser extension bridge registration (exit code $0). You may need to manually remove the registry keys under NativeMessagingHosts\com.cryptiq.bridge."
  preuninstall_ok:
!macroend
