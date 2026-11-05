param([Parameter(Mandatory=$true)][string]$Requests, [Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
Add-Type -AssemblyName System.Security
$requestPath = (Resolve-Path -LiteralPath $Requests).Path
$outputPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot $Output))
if (Test-Path -LiteralPath $outputPath) { throw 'Refusing to replace existing signatures.' }
$validationPath = "$outputPath.validation.json"
& '.tools/python/python.exe' validate_signing_requests.py $requestPath --output $validationPath
if ($LASTEXITCODE -ne 0) { throw 'Signing-scope validation failed.' }
$validation = Get-Content -Raw -LiteralPath $validationPath | ConvertFrom-Json
$actual = (Get-FileHash -LiteralPath $requestPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -cne $validation.requests_sha256 -or !$validation.scope_verified) { throw 'Request changed after validation.' }
$entropy = [Text.Encoding]::UTF8.GetBytes('Molcer OS AVB signing identity v1')
$protected = [IO.File]::ReadAllBytes((Join-Path $PSScriptRoot '.private/avb-key.dpapi'))
$plain = [Security.Cryptography.ProtectedData]::Unprotect($protected, $entropy, [Security.Cryptography.DataProtectionScope]::CurrentUser)
$rsa = New-Object Security.Cryptography.RSACryptoServiceProvider
$rsa.PersistKeyInCsp = $false
try {
    $rsa.FromXmlString([Text.Encoding]::UTF8.GetString($plain))
    $public = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'keys/avb-public.xml'))
    if ($rsa.ToXmlString($false) -cne $public) { throw 'Private identity differs from approved public key.' }
    $responses = @()
    foreach ($item in $validation.requests) {
        $digest = New-Object byte[] 32
        for ($i=0; $i -lt 32; $i++) { $digest[$i] = [Convert]::ToByte($item.digest_sha256.Substring($i*2, 2), 16) }
        $signature = $rsa.SignHash($digest, 'SHA256')
        if (!$rsa.VerifyHash($digest, 'SHA256', $signature)) { throw 'Local RSA roundtrip failed.' }
        $responses += @{partition=$item.partition; unsigned_blob_sha256=$item.unsigned_blob_sha256; digest_sha256=$item.digest_sha256; signature_hex=([BitConverter]::ToString($signature)).Replace('-','').ToLowerInvariant()}
    }
    if ((Get-FileHash -LiteralPath $requestPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $actual) { throw 'Request changed during signing.' }
    $result = @{schema=1; requests_sha256=$actual; signatures=$responses} | ConvertTo-Json -Depth 8
    [IO.File]::WriteAllText($outputPath, $result + "`n", (New-Object Text.UTF8Encoding($false)))
} finally {
    [Array]::Clear($plain, 0, $plain.Length)
    $rsa.Dispose()
}
Write-Output 'Signed two validated AVB digests locally. Output contains public signatures only.'
