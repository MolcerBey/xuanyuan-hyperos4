param([string]$InputRoot='work/customization-audit/out/unsigned-overlays',
      [string]$Report='work/customization-audit/reports/translations.json',
      [string]$OutputRoot='assets/turkish-overlays')
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
Add-Type -AssemblyName System.Security
$inputDirectory = (Resolve-Path -LiteralPath $InputRoot).Path
$reportPath = (Resolve-Path -LiteralPath $Report).Path
$outputDirectory = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot $OutputRoot))
if (Test-Path -LiteralPath $outputDirectory) { throw 'Use a fresh signed overlay output directory.' }
$evidence = Get-Content -Raw -LiteralPath $reportPath | ConvertFrom-Json
if ($evidence.original_apks_modified -ne $false -or $evidence.preview_signing_key -ne $false -or $evidence.signing_status -cne 'unsigned-local-signing-required') {
    throw 'Expected unsigned resource-only compilation report.'
}
$expectedPackages = @($evidence.targets | ForEach-Object { $_.overlays })
$apks = @(Get-ChildItem -LiteralPath $inputDirectory -Filter '*.apk' -Recurse -File)
if ($apks.Count -ne $expectedPackages.Count -or $apks.Count -lt 1) { throw 'Unexpected overlay count.' }
foreach ($apk in $apks) {
    if ($apk.BaseName -cnotmatch '^com\.molcer\.os\.tr\.[a-z0-9_]+\.g[0-9]+$' -or $expectedPackages -cnotcontains $apk.BaseName) {
        throw 'Unexpected overlay package filename.'
    }
}
$java = Join-Path $PSScriptRoot '.tools/jre21/jdk-21.0.13+9-jre/bin/java.exe'
$sdk = Join-Path $PSScriptRoot '.tools/android-build-tools/android-37.0'
$jar = Join-Path $sdk 'lib/apksigner.jar'
$certificate = Join-Path $PSScriptRoot 'keys/rro-certificate.der'
$certificateHash = (Get-FileHash -LiteralPath $certificate -Algorithm SHA256).Hash.ToLowerInvariant()
$privateRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '.private'))
$temporary = Join-Path $privateRoot ('sign-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporary | Out-Null
$entropy = [Text.Encoding]::UTF8.GetBytes('Molcer OS RRO signing identity v1')
$plain = $null
try {
    $protected = [IO.File]::ReadAllBytes((Join-Path $privateRoot 'rro-key.dpapi'))
    $plain = [Security.Cryptography.ProtectedData]::Unprotect($protected, $entropy, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    $secret = [Text.Encoding]::UTF8.GetString($plain) | ConvertFrom-Json
    if ($secret.schema -ne 1) { throw 'Unexpected local key schema.' }
    $pfxPath = Join-Path $temporary 'identity.p12'
    $passwordPath = Join-Path $temporary 'password.txt'
    [IO.File]::WriteAllBytes($pfxPath, [Convert]::FromBase64String($secret.pfx))
    [IO.File]::WriteAllText($passwordPath, $secret.password, (New-Object Text.UTF8Encoding($false)))
    $secret = $null
    New-Item -ItemType Directory -Path $outputDirectory | Out-Null
    $records = @()
    foreach ($apk in $apks) {
        $badging = & (Join-Path $sdk 'aapt2.exe') dump badging $apk.FullName
        if ($LASTEXITCODE -ne 0 -or ($badging -join "`n") -notmatch ("(?m)^package: name='" + [regex]::Escape($apk.BaseName) + "'")) { throw 'Overlay package identity mismatch.' }
        $manifest = (& (Join-Path $sdk 'aapt2.exe') dump xmltree $apk.FullName --file AndroidManifest.xml) -join "`n"
        if ($LASTEXITCODE -ne 0 -or $manifest -notmatch 'hasCode[^\n]*(?:false|0x0\b)' -or $manifest -match '(?m)^\s*E: (?:activity|service|receiver|provider|uses-permission)\b') { throw 'Overlay has unexpected executable components or permissions.' }
        $aligned = Join-Path $temporary 'aligned.apk'
        & (Join-Path $sdk 'zipalign.exe') -f -p 4 $apk.FullName $aligned
        if ($LASTEXITCODE -ne 0) { throw 'Overlay alignment failed.' }
        $signed = Join-Path $outputDirectory $apk.Name
        & $java -jar $jar sign --ks $pfxPath --ks-type PKCS12 --ks-pass "file:$passwordPath" --min-sdk-version 37 --out $signed $aligned
        if ($LASTEXITCODE -ne 0) { throw 'Overlay signing failed.' }
        $verification = (& $java -jar $jar verify --verbose --print-certs --min-sdk-version 37 --max-sdk-version 37 $signed) -join "`n"
        if ($LASTEXITCODE -ne 0 -or !$verification.Contains("certificate SHA-256 digest: $certificateHash")) { throw 'Permanent certificate verification failed.' }
        $target = @($evidence.targets | Where-Object { $_.overlays -ccontains $apk.BaseName })
        if ($target.Count -ne 1) { throw 'Ambiguous target binding.' }
        $records += @{package=$apk.BaseName; path=($OutputRoot.Replace('\','/').TrimEnd('/') + '/' + $apk.Name); destination=('overlay/MolcerTurkish/' + $apk.Name); size=(Get-Item -LiteralPath $signed).Length; sha256=(Get-FileHash -LiteralPath $signed -Algorithm SHA256).Hash.ToLowerInvariant(); unsigned_sha256=(Get-FileHash -LiteralPath $apk.FullName -Algorithm SHA256).Hash.ToLowerInvariant(); target_apk=$target[0].target_apk; target_apk_sha256=$target[0].target_apk_sha256}
    }
    $index = @{schema=1; signing_identity='Molcer OS Resource Overlays'; signer_certificate_sha256=$certificateHash; source_report_sha256=(Get-FileHash -LiteralPath $reportPath -Algorithm SHA256).Hash.ToLowerInvariant(); permanent_local_signature=$true; original_apks_modified=$false; runtime_verified=$false; overlays=$records; credit=$evidence.credit}
    [IO.File]::WriteAllText((Join-Path $outputDirectory 'manifest.json'), (($index | ConvertTo-Json -Depth 10) + "`n"), (New-Object Text.UTF8Encoding($false)))
} finally {
    if ($plain) { [Array]::Clear($plain,0,$plain.Length) }
    $secret = $null
    $resolved = [IO.Path]::GetFullPath($temporary)
    if (!$resolved.StartsWith($privateRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected cleanup location.' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
Write-Output "Signed $($apks.Count) own resource overlays with permanent local identity."
