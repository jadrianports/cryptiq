# scripts/ci/install-smoke.ps1
#
# REL-03: Silently installs the REAL *-setup.exe produced by tauri-action, then
# proves native-host registration by READING BACK OS-layer state (HKCU registry
# keys, the manifest JSON, the sidecar binary) for BOTH Chrome and Edge — never
# by trusting the installer's own exit code. Then synchronously uninstalls
# (_?=$INSTDIR is MANDATORY, see below) and asserts the same state is gone.
#
# WHY registry read-back, not exit code (D-02a): the DIST-02 `-196608` bug
# shipped green precisely because hooks.nsh's POSTINSTALL/PREUNINSTALL hooks
# catch a failed registration into a MessageBox and still exit 0 — an
# exit-code-gated smoke would have passed on a completely broken install. This
# script is the only trustworthy gate: it reads the exact same HKCU keys,
# manifest path, and sidecar path that scripts/native-host/register-native-host.ps1
# (the single source of truth, also shelled out to by hooks.nsh) writes.
#
# Source: NSIS's ExecWait/_?= semantics confirmed via
# nsis.sourceforge.io/Docs/Chapter3.html ("_?= sets $INSTDIR. It also stops the
# uninstaller from copying itself to the temporary directory and running from
# there.") — a plain `/S` uninstall copies itself to %TEMP% and returns BEFORE
# the PREUNINSTALL hook completes, racing this script's post-uninstall assertions.

$ErrorActionPreference = 'Stop'

$setupExe = (Get-ChildItem -Path 'apps/desktop/src-tauri/target/release/bundle/nsis/*-setup.exe' `
  -ErrorAction Stop | Select-Object -First 1).FullName
$instDir  = Join-Path $env:LOCALAPPDATA 'Cryptiq'   # currentUser install mode default ($LOCALAPPDATA\<ProductName>)
$manifestPath = Join-Path $env:APPDATA 'Cryptiq\com.cryptiq.bridge.json'
$sidecarPath  = Join-Path $instDir 'cryptiq-nmhost.exe'

# --- ASSERT: CLEAN SLATE BEFORE INSTALL (D-02a corollary) ---
# Without this, the read-back below cannot distinguish "the POSTINSTALL hook wrote this"
# from "this was already here". The registry (default) assertion compares against
# $manifestPath, a DETERMINISTIC CONSTANT (%APPDATA%\Cryptiq\com.cryptiq.bridge.json) —
# identical whether the hook ran or not. So on a machine that already has Cryptiq
# registered (the documented dev workflow runs register-native-host.ps1 directly, and a
# prior real install leaves the same keys), this smoke would pass every assertion below
# against a COMPLETELY INERT installer. Only manifest.path partially saves it, and only
# when the stale registration happens to point at target/debug rather than $INSTDIR.
#
# CI runners are ephemeral so the shipping gate is sound today, but this script is also
# the project's designated LOCAL reproduction tool for the DIST-02 bug class — and in
# exactly that local use it was the "green but blind" pathology it exists to kill.
# (Confirmed real: the dev machine this was written on has a live registration.)
foreach ($browser in @('Google\Chrome', 'Microsoft\Edge')) {
  $keyPath = "HKCU:\Software\$browser\NativeMessagingHosts\com.cryptiq.bridge"
  if (Test-Path $keyPath) {
    throw "install-smoke: pre-existing registration at $keyPath — refusing to run, because a pass here would not prove the installer did anything. Run scripts/native-host/unregister-native-host.ps1 first."
  }
}
if (Test-Path $manifestPath) {
  throw "install-smoke: pre-existing manifest at $manifestPath — refusing to run (see above). Run scripts/native-host/unregister-native-host.ps1 first."
}
if (Test-Path $instDir) {
  throw "install-smoke: pre-existing install at $instDir — uninstall first (a leftover $INSTDIR would let the sidecar assertion pass on a stale binary)."
}

Write-Host "install-smoke: clean slate confirmed (no registration, manifest, or install dir)."
Write-Host "install-smoke: installing $setupExe silently..."

# --- INSTALL (bounded wait; NEVER gate on exit code) ---
$installProc = Start-Process -FilePath $setupExe -ArgumentList '/S' -PassThru
if (-not $installProc.WaitForExit(120000)) {
  $installProc.Kill()
  throw "install-smoke: installer did not exit within 120s (likely hung on an un-/SD'd MessageBox)"
}

# --- ASSERT: registry + manifest + sidecar, BOTH browsers (D-02b) ---
# ($manifestPath / $sidecarPath are hoisted above the install for the clean-slate check.)
foreach ($browser in @('Google\Chrome', 'Microsoft\Edge')) {
  $keyPath = "HKCU:\Software\$browser\NativeMessagingHosts\com.cryptiq.bridge"
  $val = (Get-ItemProperty -Path $keyPath -Name '(default)' -ErrorAction Stop).'(default)'
  if ($val -ne $manifestPath) { throw "install-smoke: $keyPath (default) = '$val', expected '$manifestPath'" }
}
if (-not (Test-Path $manifestPath)) { throw "install-smoke: manifest missing at $manifestPath" }
$manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
if ($manifest.path -ne $sidecarPath) { throw "install-smoke: manifest.path = '$($manifest.path)', expected '$sidecarPath'" }
if (-not (Test-Path $sidecarPath)) { throw "install-smoke: sidecar missing at $sidecarPath" }

Write-Host "install-smoke: POSTINSTALL registration verified (both browsers, manifest, sidecar)."

# --- UNINSTALL (synchronous — _?= is MANDATORY, not optional; see header note) ---
$uninstExe = Join-Path $instDir 'uninstall.exe'
$uninstProc = Start-Process -FilePath $uninstExe -ArgumentList '/S', "_?=$instDir" -PassThru
if (-not $uninstProc.WaitForExit(120000)) {
  $uninstProc.Kill()
  throw "install-smoke: uninstaller did not exit within 120s"
}
Start-Sleep -Seconds 2   # settle

# --- ASSERT: registry + manifest are GONE (D-02c). Do NOT assert $INSTDIR is
# empty — uninstall.exe cannot delete itself in-place under _?= (see header). ---
foreach ($browser in @('Google\Chrome', 'Microsoft\Edge')) {
  $keyPath = "HKCU:\Software\$browser\NativeMessagingHosts\com.cryptiq.bridge"
  if (Test-Path $keyPath) { throw "install-smoke: orphan registry key survived uninstall: $keyPath" }
}
if (Test-Path $manifestPath) { throw "install-smoke: orphan manifest survived uninstall: $manifestPath" }

Write-Host "install-smoke: PREUNINSTALL cleanup verified (both browsers, manifest gone)."
