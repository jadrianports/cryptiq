# scripts/native-host/register-native-host.ps1
#
# D-11/D-12/D-14: Writes the Chrome + Edge HKCU NativeMessagingHosts registry
# key (D-12) plus the native-host manifest JSON (BRIDGE-03) that Chrome uses
# to locate and spawn the cryptiq-nmhost.exe sidecar. The sidecar's absolute
# path is ALWAYS caller-supplied (D-14) — never hardcoded here — so the exact
# same script works in dev (target/debug) and production (installer $INSTDIR)
# with only the argument differing.
#
# This script (and its mirror, unregister-native-host.ps1) is the single
# source of truth for registration: apps/desktop/src-tauri/windows/hooks.nsh
# shells out to this SAME file on install — no divergent NSIS-native
# reimplementation (DIST-02, T-14-17).

param(
  [Parameter(Mandatory = $true)][string]$SidecarPath,
  [Parameter(Mandatory = $true)][string]$ExtensionId
)

$ErrorActionPreference = 'Stop'

$hostName = 'com.cryptiq.bridge'
$manifestDir = "$env:APPDATA\Cryptiq"
New-Item -ItemType Directory -Force -Path $manifestDir | Out-Null
$manifestPath = Join-Path $manifestDir "$hostName.json"

$manifest = [ordered]@{
  name            = $hostName
  description     = 'Cryptiq native messaging host'
  path            = $SidecarPath
  type            = 'stdio'
  allowed_origins = @("chrome-extension://$ExtensionId/")
} | ConvertTo-Json

Set-Content -Path $manifestPath -Value $manifest -Encoding UTF8

# D-12: register Chrome AND Edge; Brave piggybacks on the Chrome key for
# free and is not gated on its own test.
foreach ($browser in @('Google\Chrome', 'Microsoft\Edge')) {
  $keyPath = "HKCU:\Software\$browser\NativeMessagingHosts\$hostName"
  New-Item -Path $keyPath -Force | Out-Null
  Set-ItemProperty -Path $keyPath -Name '(default)' -Value $manifestPath
}

Write-Host "Registered $hostName -> $manifestPath (sidecar: $SidecarPath, extension: $ExtensionId)"
