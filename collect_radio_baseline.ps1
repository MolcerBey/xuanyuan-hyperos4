param([string]$AdbPath = 'C:\adb\adb.exe')
$ErrorActionPreference = 'Stop'
$state = (& $AdbPath get-state 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $state -ne 'device') {
    throw 'Exactly one authorized ADB phone must be connected.'
}
$device = (& $AdbPath shell getprop ro.product.device | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $device -ne 'xuanyuan') {
    throw 'Connected device is not xuanyuan.'
}
# Read only a fixed list of software/hardware identifiers. No APK extraction,
# phone numbers, SIM identifiers, IMEI, serial numbers, app data, writes or reboot.
$properties = @(
    'ro.product.device', 'ro.product.model', 'ro.product.vendor.model',
    'ro.boot.hardware.sku', 'ro.build.version.release',
    'ro.build.version.incremental', 'ro.vendor.build.version.incremental',
    'gsm.version.baseband', 'ro.miui.region', 'ro.product.mod_device'
)
$values = [ordered]@{}
foreach ($property in $properties) {
    $value = (& $AdbPath shell getprop $property | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw "Cannot read software property: $property" }
    $values[$property] = $value
}
$destination = Join-Path $PSScriptRoot 'work\radio-baseline.json'
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) | Out-Null
$values | ConvertTo-Json | Set-Content -LiteralPath $destination -Encoding UTF8
$values | ConvertTo-Json
