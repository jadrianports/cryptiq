# scripts/native-host/unregister-native-host.ps1
#
# D-13: MIRRORS register-native-host.ps1 EXACTLY — removes the manifest JSON
# and BOTH the Chrome and Edge HKCU NativeMessagingHosts keys, leaving no
# orphaned registry key or manifest file behind (T-14-14). No parameters:
# the manifest path is deterministic ($env:APPDATA\Cryptiq\com.cryptiq.bridge.json)
# so uninstall never needs to know where the sidecar binary lived.
#
# WR-03: this script MUST be able to exit non-zero. It previously set
# $ErrorActionPreference = 'SilentlyContinue' AND passed -ErrorAction
# SilentlyContinue to every Remove-Item, suppressing every failure mode twice
# over — so it could not fail, `IntCmp $0 0` in hooks.nsh's PREUNINSTALL always
# took the _ok branch, and that hook's warning MessageBox was DEAD CODE that
# could never fire. It also printed "removed" unconditionally, whether or not
# anything was removed.
#
# The distinction that matters: an artifact that is ALREADY GONE is not a
# failure (uninstall must stay idempotent), but an artifact that is present and
# REFUSES to be removed is — that is the only case a user can act on, and the
# only case worth surfacing a dialog for.

$ErrorActionPreference = 'Stop'

$hostName = 'com.cryptiq.bridge'
$manifestPath = "$env:APPDATA\Cryptiq\$hostName.json"

$targets = @($manifestPath)
foreach ($browser in @('Google\Chrome', 'Microsoft\Edge')) {
  $targets += "HKCU:\Software\$browser\NativeMessagingHosts\$hostName"
}

$removed = 0
$absent = 0
$failures = 0

foreach ($path in $targets) {
  if (-not (Test-Path -Path $path)) {
    $absent++
    continue
  }
  try {
    Remove-Item -Path $path -Force -Recurse
    $removed++
  } catch {
    Write-Warning "unregister-native-host: FAILED to remove '$path': $($_.Exception.Message)"
    $failures++
  }
}

if ($failures -gt 0) {
  Write-Host "Unregister INCOMPLETE for $hostName ($removed removed, $absent already absent, $failures FAILED)."
  exit 1
}

Write-Host "Unregistered $hostName ($removed removed, $absent already absent)."
