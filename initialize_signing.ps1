$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
Add-Type -AssemblyName System.Security
$privateDirectory = Join-Path $PSScriptRoot '.private'
$privateFile = Join-Path $privateDirectory 'avb-key.dpapi'
$publicDirectory = Join-Path $PSScriptRoot 'keys'
$publicFile = Join-Path $publicDirectory 'avb-public.xml'
if ((Test-Path -LiteralPath $privateFile) -or (Test-Path -LiteralPath $publicFile)) {
    throw 'Signing identity already exists; refusing to replace it.'
}
New-Item -ItemType Directory -Path $privateDirectory -Force | Out-Null
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
& icacls.exe $privateDirectory /inheritance:r /grant:r "${identity}:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict signing-key directory permissions.' }
New-Item -ItemType Directory -Path $publicDirectory -Force | Out-Null
$rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider(4096)
$rsa.PersistKeyInCsp = $false
try {
    $entropy = [Text.Encoding]::UTF8.GetBytes('Molcer OS AVB signing identity v1')
    $plain = [Text.Encoding]::UTF8.GetBytes($rsa.ToXmlString($true))
    try {
        $protected = [Security.Cryptography.ProtectedData]::Protect($plain, $entropy, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        [IO.File]::WriteAllBytes($privateFile, $protected)
    } finally {
        [Array]::Clear($plain, 0, $plain.Length)
    }
    [IO.File]::WriteAllText($publicFile, $rsa.ToXmlString($false), (New-Object Text.UTF8Encoding($false)))
} finally {
    $rsa.Dispose()
}
Write-Output 'Created a persistent RSA4096 signing identity. Private key is DPAPI-protected for this Windows user and remains local.'
