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

; ExecWait sets its output variable to the exit code ONLY IF the process actually
; launches. If powershell.exe cannot be launched at all (missing, blocked by
; policy/AppLocker, PATH stripped), NSIS sets the ERROR FLAG and leaves $0 untouched —
; and NSIS registers initialize to "", which IntCmp coerces to 0, so a total launch
; failure jumped straight to *_ok: no DetailPrint, no MessageBox. That is the DIST-02
; silent-failure class re-entering through the very hook written to prevent it. (It
; survived DIST-02's smoke because that bug was -196608: powershell DID launch and
; returned a real non-zero code.) Hence, in both hooks below:
;   Push/Pop $0  — $0-$9 are process-GLOBAL and these macros are inlined into Tauri's
;                  generated installer sections; clobbering $0 could silently corrupt a
;                  value the template holds across the insertion point.
;   ClearErrors  — the error flag is sticky; clear it before ExecWait so IfErrors below
;                  reflects THIS call only.
;   StrCpy $0 "-1" — poison the register so a never-written $0 can never read as success.
;   IfErrors     — catch "could not launch at all", which the exit code cannot express.

!macro NSIS_HOOK_POSTINSTALL
  Push $0
  DetailPrint "Registering Cryptiq native-messaging host..."
  ClearErrors
  StrCpy $0 "-1"
  ExecWait '"powershell.exe" -ExecutionPolicy Bypass -File "$INSTDIR\register-native-host.ps1" -SidecarPath "$INSTDIR\cryptiq-nmhost.exe" -ExtensionId "pmnfhbonekjokipcfeklbajepnjppnca"' $0
  IfErrors postinstall_warn
  IntCmp $0 0 postinstall_ok postinstall_warn postinstall_warn
  postinstall_warn:
    DetailPrint "WARNING: native-messaging host registration failed (exit code $0)."
    ; The retry instruction MUST name $INSTDIR\register-native-host.ps1, not the
    ; repo-relative scripts\native-host\ source path: an end user who installed the NSIS
    ; bundle has no such directory, and the copy this hook actually invokes — the only one
    ; on their disk — is the one bundle.resources stages to $INSTDIR (see header). This is
    ; the sole recovery instruction on the only user-visible failure path of the extension
    ; bridge, so an unfollowable one is worth nothing.
    MessageBox MB_OK|MB_ICONEXCLAMATION "Cryptiq could not register its browser extension bridge (exit code $0). The browser extension will not be able to connect to Cryptiq until this is fixed.$\r$\n$\r$\nYou can retry by running this command:$\r$\npowershell -ExecutionPolicy Bypass -File $\"$INSTDIR\register-native-host.ps1$\" -SidecarPath $\"$INSTDIR\cryptiq-nmhost.exe$\" -ExtensionId pmnfhbonekjokipcfeklbajepnjppnca" /SD IDOK
  postinstall_ok:
  Pop $0
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  Push $0
  DetailPrint "Unregistering Cryptiq native-messaging host..."
  ClearErrors
  StrCpy $0 "-1"
  ExecWait '"powershell.exe" -ExecutionPolicy Bypass -File "$INSTDIR\unregister-native-host.ps1"' $0
  IfErrors preuninstall_warn
  IntCmp $0 0 preuninstall_ok preuninstall_warn preuninstall_warn
  preuninstall_warn:
    DetailPrint "WARNING: native-messaging host unregistration failed (exit code $0)."
    MessageBox MB_OK|MB_ICONEXCLAMATION "Cryptiq could not fully remove its browser extension bridge registration (exit code $0). You may need to manually remove the registry keys under NativeMessagingHosts\com.cryptiq.bridge." /SD IDOK
  preuninstall_ok:
  Pop $0
!macroend
