<#
.SYNOPSIS
    Tests PingFederate client authentication by certificate (private_key_jwt and tls_client_auth)
    and the transport options on the PingFederate calls.

.DESCRIPTION
    Needs the test certificates and the PingFederate mock started WITH the certificate directory:

        tests/LocalServer/make-client-certs.sh /tmp/svc-mtls
        python3 tests/LocalServer/pingfed_mock.py /tmp/svc-mtls &     # ports 18090 to 18093 and 18094 (mutual TLS)
        pwsh -NoProfile -NonInteractive -File tests/LocalServer/Invoke-PingFederateCertTests.ps1 `
            -ModulePath ./ServiceAPI.psd1 -CertDir /tmp/svc-mtls

    The browser and the interactivity check are replaced inside the module (a background job
    follows the authorization URL), and the vault is not used: the secret client is stubbed, and
    the certificate clients must never ask for it. Uses a throwaway HOME. Linux only.
#>
param(
    [Parameter(Mandatory)][string]$ModulePath,
    [Parameter(Mandatory)][string]$CertDir
)
$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSEdition -eq 'Desktop' -or (Test-Path Variable:\IsWindows) -and $IsWindows) {
    throw 'These tests are written for Linux (they isolate state through HOME). Run them on a Linux host or in WSL.'
}

# .NET on Linux reads SSL_CERT_FILE when the process starts: re-launch once with it set
$roots = Join-Path $CertDir 'roots.pem'
if ($env:SSL_CERT_FILE -ne $roots) {
    $env:SSL_CERT_FILE = $roots
    & (Get-Process -Id $PID).Path -NoProfile -NonInteractive -File $PSCommandPath -ModulePath $ModulePath -CertDir $CertDir
    exit $LASTEXITCODE
}

$work = Join-Path ([IO.Path]::GetTempPath()) ('pfc-' + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $work | Out-Null
$env:HOME = $work
$ca = Join-Path $CertDir 'ca.crt'

$script:pass = 0; $script:fail = 0
function T($name, [scriptblock]$test) {
    try { $r = & $test; if ($r -eq $true) { $script:pass++; "PASS  $name" } else { $script:fail++; "FAIL  $name -> $r" } }
    catch { $script:fail++; "FAIL  $name -> EXC: $($_.Exception.Message -replace '\s+', ' ')" }
}
function ErrorOf([scriptblock]$test) { try { & $test | Out-Null; $null } catch { ($_.Exception.Message -replace '\s+', ' ') } }

Import-Module $ModulePath -Force 3>$null
$m = Get-Module ServiceAPI

# Replace the browser, the interactivity check and the secret client inside the module
& $m {
    $script:SecretClientCalls = 0
    Set-Item -Path 'function:script:Test-ServiceApiInteractive' -Value { $true }
    Set-Item -Path 'function:script:Open-ServiceApiBrowser' -Value {
        param($Url)
        Start-Job -ArgumentList $Url -ScriptBlock {
            param($u); Start-Sleep -Milliseconds 600
            # PowerShell refuses an HTTPS to HTTP redirect by default; a browser follows it to the loopback listener
            try { Invoke-WebRequest $u -UseBasicParsing -AllowInsecureRedirect | Out-Null } catch { }
        } | Out-Null
        $true
    }
    Set-Item -Path 'function:script:Get-PingFederateClient' -Value {
        param($Service, $Environment, $Vault)
        $script:SecretClientCalls++
        [PSCustomObject]@{ ClientId = 'test-client'; ClientSecret = (ConvertTo-SecureString 'secret:with:colons' -AsPlainText -Force) }
    }
}
function Mock-Log($base) { Invoke-RestMethod "$base/_log" }
function Mock-Reset { foreach ($b in 'http://127.0.0.1:18090', 'https://localhost:18094') { Invoke-RestMethod "$b/_reset" | Out-Null } }
function Cache($svc) { & $m { param($k) $global:ServiceSSOTokens[$k] } "$svc-prod" }
function Login($svc) { Set-ServiceCredential -Service $svc -Environment prod -AuthType SSO -Force }

$rsa = New-ServiceClientCertificate -CertificatePath (Join-Path $CertDir 'client-rsa.crt') -KeyPath (Join-Path $CertDir 'client-rsa.key')
$ec  = New-ServiceClientCertificate -CertificatePath (Join-Path $CertDir 'client-ec.crt') -KeyPath (Join-Path $CertDir 'client-ec.key')
$bad = New-ServiceClientCertificate -CertificatePath (Join-Path $CertDir 'untrusted.crt') -KeyPath (Join-Path $CertDir 'untrusted.key')
$plain = 'http://127.0.0.1:18090'
$mtls  = 'https://localhost:18094'
Mock-Reset

# ----------------------------------------------------------------------------
'--- client assertion ---'
$resolvedRsa = & $m { param($s) Get-ServiceClientCertificate -Certificate $s } $rsa
$resolvedEc  = & $m { param($s) Get-ServiceClientCertificate -Certificate $s } $ec
function Parse-Jwt($jwt) {
    $p = $jwt.Split('.')
    $dec = { param($t) $t = $t.Replace('-', '+').Replace('_', '/'); switch ($t.Length % 4) { 2 { $t += '==' } 3 { $t += '=' } }; [Convert]::FromBase64String($t) }
    [pscustomobject]@{
        Header  = [Text.Encoding]::UTF8.GetString((& $dec $p[0])) | ConvertFrom-Json
        Claims  = [Text.Encoding]::UTF8.GetString((& $dec $p[1])) | ConvertFrom-Json
        Input   = [Text.Encoding]::ASCII.GetBytes("$($p[0]).$($p[1])")
        Sig     = & $dec $p[2]
    }
}
T 'RS256 assertion: header, claims and a signature that verifies with the certificate' {
    $jwt = & $m { param($r) New-ServiceClientAssertion -Certificate $r -ClientId 'test-client' -Audience 'https://as.example.com/token', 'https://as.example.com' } $resolvedRsa
    $j = Parse-Jwt $jwt
    $pub = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($resolvedRsa.Certificate)
    $ok = $pub.VerifyData($j.Input, $j.Sig, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $ok -and $j.Header.alg -eq 'RS256' -and $j.Header.x5t -and $j.Claims.iss -eq 'test-client' -and $j.Claims.sub -eq 'test-client' -and
        @($j.Claims.aud).Count -eq 2 -and $j.Claims.jti -and ($j.Claims.exp - $j.Claims.iat) -eq 120
}
T 'ES256 assertion verifies with the EC certificate' {
    $jwt = & $m { param($r) New-ServiceClientAssertion -Certificate $r -ClientId 'test-client' -Audience 'https://as.example.com' } $resolvedEc
    $j = Parse-Jwt $jwt
    $pub = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($resolvedEc.Certificate)
    $pub.VerifyData($j.Input, $j.Sig, [Security.Cryptography.HashAlgorithmName]::SHA256) -and $j.Header.alg -eq 'ES256' -and $j.Sig.Length -eq 64
}
T 'Each assertion has its own jti' {
    $a = & $m { param($r) (New-ServiceClientAssertion -Certificate $r -ClientId 'c' -Audience 'a') } $resolvedRsa
    $b = & $m { param($r) (New-ServiceClientAssertion -Certificate $r -ClientId 'c' -Audience 'a') } $resolvedRsa
    (Parse-Jwt $a).Claims.jti -ne (Parse-Jwt $b).Claims.jti
}

# ----------------------------------------------------------------------------
'--- private_key_jwt ---'
Register-CustomService -ServiceName pingjwt -BaseUrl $plain -SSOProvider PingFederate -OidcClientId test-client `
    -OidcClientAuth private_key_jwt -ClientCertificate $rsa -Force | Out-Null
T 'Sign-in with a signed assertion; no secret is read' {
    Login pingjwt
    $c = Cache 'pingjwt'
    $log = @(Mock-Log $plain | Where-Object { $_.grant -eq 'authorization_code' })
    ($c.AuthMode -eq 'jwt') -and ($c.Token -is [securestring]) -and ($c.RefreshToken -is [securestring]) -and
        ($log.Count -eq 1) -and ($log[0].auth -eq 'jwt') -and ((& $m { $script:SecretClientCalls }) -eq 0)
}
T 'A stale token refreshes silently with a fresh assertion' {
    Mock-Reset
    & $m { $global:ServiceSSOTokens['pingjwt-prod'].ExpiresAt = [DateTime]::UtcNow.AddMinutes(1) }
    Get-ServiceCredential -Service pingjwt -Environment prod -AuthType SSO | Out-Null
    $log = @(Mock-Log $plain | Where-Object { $_.grant -eq 'refresh_token' })
    ($log.Count -eq 1) -and ($log[0].auth -eq 'jwt') -and ((Cache 'pingjwt').ExpiresAt -gt [DateTime]::UtcNow.AddMinutes(50))
}
Register-CustomService -ServiceName pingec -BaseUrl $plain -SSOProvider PingFederate -OidcClientId test-client `
    -OidcClientAuth private_key_jwt -ClientCertificate $ec -Force | Out-Null
T 'Sign-in with an ES256 assertion' { Login pingec; (Cache 'pingec').AuthMode -eq 'jwt' }
Register-CustomService -ServiceName pingjwtbad -BaseUrl $plain -SSOProvider PingFederate -OidcClientId test-client `
    -OidcClientAuth private_key_jwt -ClientCertificate $bad -Force | Out-Null
T 'A certificate the client is not registered with is refused, with a hint' {
    (ErrorOf { Login pingjwtbad }) -match "invalid_client.*registered with this certificate"
}
T 'private_key_jwt without a client id says so' {
    Register-CustomService -ServiceName pingnoid -BaseUrl $plain -SSOProvider PingFederate -OidcClientAuth private_key_jwt -ClientCertificate $rsa -Force | Out-Null
    (ErrorOf { Login pingnoid }) -match 'needs the client id'
}
T 'private_key_jwt without a certificate says so' {
    Register-CustomService -ServiceName pingnocert -BaseUrl $plain -SSOProvider PingFederate -OidcClientAuth private_key_jwt -OidcClientId test-client -Force 3>$null | Out-Null
    (ErrorOf { Login pingnocert }) -match 'needs a client certificate'
}

# ----------------------------------------------------------------------------
'--- tls_client_auth (mutual TLS) ---'
Mock-Reset
Register-CustomService -ServiceName pingtls -BaseUrl $mtls -SSOProvider PingFederate -OidcClientId test-client `
    -OidcClientAuth tls_client_auth -ClientCertificate $rsa -Force | Out-Null
T 'Sign-in over mutual TLS on the .NET transport' {
    Login pingtls
    $log = @(Mock-Log $mtls | Where-Object { $_.grant -eq 'authorization_code' })
    ((Cache 'pingtls').AuthMode -eq 'tls') -and ($log.Count -eq 1) -and ($log[0].auth -eq 'tls')
}
T 'A stale token refreshes over mutual TLS' {
    Mock-Reset
    & $m { $global:ServiceSSOTokens['pingtls-prod'].ExpiresAt = [DateTime]::UtcNow.AddMinutes(1) }
    Get-ServiceCredential -Service pingtls -Environment prod -AuthType SSO | Out-Null
    $log = @(Mock-Log $mtls | Where-Object { $_.grant -eq 'refresh_token' })
    ($log.Count -eq 1) -and ($log[0].auth -eq 'tls')
}
Register-CustomService -ServiceName pingtlscurl -BaseUrl $mtls -SSOProvider PingFederate -OidcClientId test-client `
    -OidcClientAuth tls_client_auth -ClientCertificate $rsa -Transport Curl -CaBundle $ca -Force | Out-Null
T 'Sign-in over mutual TLS on the curl transport' {
    Mock-Reset
    $out = Set-ServiceCredential -Service pingtlscurl -Environment prod -AuthType SSO -Force -Verbose 4>&1
    $log = @(Mock-Log $mtls | Where-Object { $_.grant -eq 'authorization_code' })
    ((Cache 'pingtlscurl').AuthMode -eq 'tls') -and ($log[0].auth -eq 'tls') -and
        (@($out | Where-Object { $_ -is [System.Management.Automation.VerboseRecord] -and $_.Message -match 'curl' }).Count -gt 0)
}
Register-CustomService -ServiceName pingtlsec -BaseUrl $mtls -SSOProvider PingFederate -OidcClientId test-client `
    -OidcClientAuth tls_client_auth -ClientCertificate $ec -Force | Out-Null
T 'A certificate the client is not bound to is refused, with a hint' { (ErrorOf { Login pingtlsec }) -match "invalid_client.*mutual TLS" }
T 'tls_client_auth without a certificate says so' {
    Register-CustomService -ServiceName pingtlsnone -BaseUrl $mtls -SSOProvider PingFederate -OidcClientId test-client -OidcClientAuth tls_client_auth -Force 3>$null | Out-Null
    (ErrorOf { Login pingtlsnone }) -match 'needs a client certificate'
}

# ----------------------------------------------------------------------------
'--- secret client over the curl transport ---'
Mock-Reset
Register-CustomService -ServiceName pingsecretcurl -BaseUrl $plain -SSOProvider PingFederate -Transport Curl -Force | Out-Null
T 'Discovery and the token calls use the service transport' {
    $before = & $m { $script:SecretClientCalls }
    $out = Set-ServiceCredential -Service pingsecretcurl -Environment prod -AuthType SSO -Force -Verbose 4>&1
    $curlLines = @($out | Where-Object { $_ -is [System.Management.Automation.VerboseRecord] -and $_.Message -match '\(curl\)' })
    $log = @(Mock-Log $plain | Where-Object { $_.grant -eq 'authorization_code' })
    ($curlLines.Count -ge 2) -and ($log[0].auth -eq 'basic') -and ((& $m { $script:SecretClientCalls }) -eq ($before + 1))
}

# ----------------------------------------------------------------------------
'--- registration and persistence ---'
Register-CustomService -ServiceName pingpersist -BaseUrl $mtls -SSOProvider PingFederate -OidcClientId test-client `
    -OidcClientAuth tls_client_auth -ClientCertificate $rsa -Transport Curl -CaBundle $ca -Persistent -Force | Out-Null
$servicesJson = Join-Path (& $m { $script:ServiceApiConfigPath }) 'services.json'
T 'services.json holds the client id, method and certificate location' {
    $e = (Get-Content $servicesJson -Raw | ConvertFrom-Json).pingpersist.prod
    ($e.OidcClientId -eq 'test-client') -and ($e.OidcClientAuth -eq 'tls_client_auth') -and ($e.ClientCertificate.Source -eq 'Pem') -and ($e.Transport -eq 'Curl')
}
Import-Module $ModulePath -Force 3>$null
T 'They survive a module reload' {
    $e = $global:ServiceRegistry['pingpersist']['prod']
    ($e.OidcClientId -eq 'test-client') -and ($e.OidcClientAuth -eq 'tls_client_auth') -and ($e.ClientCertificate.KeyPath -like '*client-rsa.key')
}
T 'An unknown OidcClientAuth value is refused' { (ErrorOf { Register-CustomService -ServiceName x -BaseUrl $plain -OidcClientAuth nonsense -Force }) -match 'does not belong to the set' }

"`nRESULT: $script:pass passed, $script:fail failed"
Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
if ($script:fail -gt 0) { exit 1 }
