$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
Add-Type -AssemblyName System.Security
$privateDirectory = Join-Path $PSScriptRoot '.private'
$privateFile = Join-Path $privateDirectory 'rro-key.dpapi'
$publicFile = Join-Path $PSScriptRoot 'keys/rro-certificate.der'
if ((Test-Path -LiteralPath $privateFile) -or (Test-Path -LiteralPath $publicFile)) {
    throw 'APK signing identity already exists; refusing to replace it.'
}
New-Item -ItemType Directory -Path $privateDirectory -Force | Out-Null
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
& icacls.exe $privateDirectory /inheritance:r /grant:r "${identity}:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict signing-key directory permissions.' }
New-Item -ItemType Directory -Path (Split-Path -Parent $publicFile) -Force | Out-Null
$rsa = [Security.Cryptography.RSA]::Create(4096)
$random = [Security.Cryptography.RandomNumberGenerator]::Create()
$certificate = $null
try {
    $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=Molcer OS Resource Overlays', $rsa, [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $certificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddYears(30))
    $randomBytes = New-Object byte[] 32
    $random.GetBytes($randomBytes)
    $password = [Convert]::ToBase64String($randomBytes)
    $pfx = $certificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $password)
    $record = @{ schema = 1; password = $password; pfx = [Convert]::ToBase64String($pfx) } | ConvertTo-Json -Compress
    $plain = [Text.Encoding]::UTF8.GetBytes($record)
    try {
        $entropy = [Text.Encoding]::UTF8.GetBytes('Molcer OS RRO signing identity v1')
        $protected = [Security.Cryptography.ProtectedData]::Protect($plain, $entropy, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        [IO.File]::WriteAllBytes($privateFile, $protected)
        [IO.File]::WriteAllBytes($publicFile, $certificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert))
    } finally {
        [Array]::Clear($plain, 0, $plain.Length)
        [Array]::Clear($pfx, 0, $pfx.Length)
        [Array]::Clear($randomBytes, 0, $randomBytes.Length)
        $record = $null
        $password = $null
    }
} finally {
    if ($certificate) { $certificate.Dispose() }
    $random.Dispose()
    $rsa.Dispose()
}
$fingerprint = (Get-FileHash -LiteralPath $publicFile -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Output "Created permanent local RRO signing identity. Public certificate SHA256: $fingerprint"
