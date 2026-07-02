# scripts/native-host/unregister-native-host.ps1
#
# D-13: MIRRORS register-native-host.ps1 EXACTLY — removes the manifest JSON
# and BOTH the Chrome and Edge HKCU NativeMessagingHosts keys, leaving no
# orphaned registry key or manifest file behind (T-14-14). No parameters:
# the manifest path is deterministic ($env:APPDATA\Cryptiq\com.cryptiq.bridge.json)
# so uninstall never needs to know where the sidecar binary lived.

$ErrorActionPreference = 'SilentlyContinue'

$hostName = 'com.cryptiq.bridge'
$manifestPath = "$env:APPDATA\Cryptiq\$hostName.json"

Remove-Item -Path $manifestPath -Force -ErrorAction SilentlyContinue

foreach ($browser in @('Google\Chrome', 'Microsoft\Edge')) {
  $keyPath = "HKCU:\Software\$browser\NativeMessagingHosts\$hostName"
  Remove-Item -Path $keyPath -Force -ErrorAction SilentlyContinue
}

Write-Host "Unregistered $hostName (manifest + both browser registry keys removed, if present)"
