param([string]$AdbPath = 'C:\adb\adb.exe')
$ErrorActionPreference = 'Stop'
# Read APK files only. No app data, account files, package changes or reboot.
$device = (& $AdbPath shell getprop ro.product.device 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $device -ne 'xuanyuan') {
    throw 'An authorized xuanyuan ADB device must be connected.'
}
$destination = Join-Path $PSScriptRoot 'inputs\phone-apps'
New-Item -ItemType Directory -Force -Path $destination | Out-Null
$known = @('com.android.chrome', 'com.android.vending', 'com.google.android.gms', 'com.google.android.gsf')
$libraries = & $AdbPath shell pm list packages trichrome
if ($LASTEXITCODE -ne 0) { throw 'Cannot enumerate Chrome shared libraries.' }
$known += @($libraries | ForEach-Object { ($_ -replace '^package:', '').Trim() } | Where-Object { $_ -match '^com\.google\.android\.trichromelibrary[\w.]*$' })
$records = @()
foreach ($package in ($known | Select-Object -Unique)) {
    $paths = & $AdbPath shell pm path $package
    if ($LASTEXITCODE -ne 0) { throw "Cannot read package paths: $package" }
    $packageDirectory = Join-Path $destination $package
    New-Item -ItemType Directory -Force -Path $packageDirectory | Out-Null
    $index = 0
    foreach ($line in $paths) {
        if ($line -notmatch '^package:(/[^\r\n]+\.apk)$') { continue }
        $source = $Matches[1]
        $filename = '{0:D2}-{1}' -f $index, [IO.Path]::GetFileName($source)
        $target = Join-Path $packageDirectory $filename
        & $AdbPath pull $source $target
        if ($LASTEXITCODE -ne 0) { throw "APK read failed: $package" }
        $records += [pscustomobject]@{ package=$package; file="$package/$filename"; sha256=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant(); size=(Get-Item -LiteralPath $target).Length }
        $index++
    }
}
$records | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $destination 'manifest.json') -Encoding UTF8
Write-Output 'APK copies saved locally under inputs/phone-apps. No phone settings changed.'
