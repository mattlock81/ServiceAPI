<#
.SYNOPSIS
    Tests client-certificate authentication (mutual TLS) and the curl/OpenSSL transport.

.DESCRIPTION
    Needs the mutual-TLS test server and its certificates:

        tests/LocalServer/make-client-certs.sh /tmp/svc-mtls
        python3 tests/LocalServer/mtls_server.py /tmp/svc-mtls &      # prints "mtls ready"; ports 18447 to 18449
        pwsh -NoProfile -NonInteractive -File tests/LocalServer/Invoke-ClientCertificateTests.ps1 `
            -ModulePath ./ServiceAPI.psd1 -CertDir /tmp/svc-mtls

    Covers New-ServiceClientCertificate; the .NET transport with a PFX (with and without a
    password), a PEM pair (plain and encrypted), an EC key and the certificate store; the
    registered-service default, the per-request override and persistence (no password reaches
    services.json); and the curl/OpenSSL transport for each of those, a TLS 1.3 only server,
    untrusted certificates, the error surface, and that no secret appears on curl's command line.
    No SecretManagement is needed: the vault password lookup is stubbed inside the module. Uses a
    throwaway HOME and trusts the test CA through SSL_CERT_FILE. Linux only.
#>
param(
    [Parameter(Mandatory)][string]$ModulePath,
    [Parameter(Mandatory)][string]$CertDir
)
$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSEdition -eq 'Desktop' -or (Test-Path Variable:\IsWindows) -and $IsWindows) {
    throw 'These tests are written for Linux (they isolate state through HOME and read /proc). Run them on a Linux host or in WSL.'
}

# .NET on Linux reads SSL_CERT_FILE when the process starts, so a late change is ignored. Re-launch
# once with it set (the child inherits the environment) and pass the exit code back.
$roots = Join-Path $CertDir 'roots.pem'
if ($env:SSL_CERT_FILE -ne $roots) {
    $env:SSL_CERT_FILE = $roots
    & (Get-Process -Id $PID).Path -NoProfile -NonInteractive -File $PSCommandPath -ModulePath $ModulePath -CertDir $CertDir
    exit $LASTEXITCODE
}

$work = Join-Path ([IO.Path]::GetTempPath()) ('cct-' + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $work | Out-Null
$env:HOME = $work
$ca = Join-Path $CertDir 'ca.crt'                      # curl is given the CA explicitly

$script:pass = 0; $script:fail = 0
function T($name, [scriptblock]$test) {
    try { $r = & $test; if ($r -eq $true) { $script:pass++; "PASS  $name" } else { $script:fail++; "FAIL  $name -> $r" } }
    catch { $script:fail++; "FAIL  $name -> EXC: $($_.Exception.Message -replace '\s+', ' ')" }
}
function ErrorOf([scriptblock]$test) { try { & $test | Out-Null; $null } catch { ($_.Exception.Message -replace '\s+', ' ') } }

Import-Module $ModulePath -Force 3>$null
$m = Get-Module ServiceAPI

$secret = ConvertTo-SecureString 'client-pass-1' -AsPlainText -Force
$req    = 'https://localhost:18447'   # client certificate required
$opt    = 'https://localhost:18448'   # client certificate optional
$tls13  = 'https://localhost:18449'   # required, TLS 1.3 only

function Spec-Pfx    { New-ServiceClientCertificate -PfxPath (Join-Path $CertDir 'client-rsa.pfx') -Password $secret }
function Spec-PfxNP  { New-ServiceClientCertificate -PfxPath (Join-Path $CertDir 'client-rsa-nopass.pfx') }
function Spec-Pem    { New-ServiceClientCertificate -CertificatePath (Join-Path $CertDir 'client-rsa.crt') -KeyPath (Join-Path $CertDir 'client-rsa.key') }
function Spec-PemEnc { New-ServiceClientCertificate -CertificatePath (Join-Path $CertDir 'client-rsa.crt') -KeyPath (Join-Path $CertDir 'client-rsa.enc.key') -Password $secret }
function Spec-Ec     { New-ServiceClientCertificate -CertificatePath (Join-Path $CertDir 'client-ec.crt') -KeyPath (Join-Path $CertDir 'client-ec.key') }
function Spec-Bad    { New-ServiceClientCertificate -CertificatePath (Join-Path $CertDir 'untrusted.crt') -KeyPath (Join-Path $CertDir 'untrusted.key') }

function Call($base, $spec, [string]$transport = 'DotNet', [string]$endpoint = 'whoami', [string]$authType = 'Certificate') {
    $p = @{ BaseUrl = $base; Endpoint = $endpoint; AuthType = $authType; Silent = $true }
    if ($spec)                { $p['ClientCertificate'] = $spec }
    if ($transport -eq 'Curl') { $p['Transport'] = 'Curl'; $p['CaBundle'] = $ca }
    Invoke-APIRequest @p
}

# ----------------------------------------------------------------------------
'--- descriptor ---'
T 'PFX descriptor records the source and an absolute path' { $s = Spec-Pfx; $s.Source -eq 'Pfx' -and [IO.Path]::IsPathRooted($s.Path) -and $s.PSObject.TypeNames[0] -eq 'ServiceApi.ClientCertificate' }
T 'PEM descriptor records both files' { $s = Spec-Pem; $s.Source -eq 'Pem' -and $s.KeyPath -like '*client-rsa.key' }
T 'A missing file is refused' { (ErrorOf { New-ServiceClientCertificate -PfxPath (Join-Path $CertDir 'nope.pfx') }) -match 'was not found' }
T 'A short thumbprint is refused' { (ErrorOf { New-ServiceClientCertificate -Thumbprint 'ABCD' }) -match 'not a valid SHA-1 thumbprint' }
T 'A thumbprint is normalised' { (New-ServiceClientCertificate -Thumbprint ('ab:cd ' * 10).Trim()).Thumbprint -eq ('ABCD' * 10) }

# ----------------------------------------------------------------------------
'--- .NET transport ---'
T 'PFX with a password' { (Call $req (Spec-Pfx)).client_cn -eq 'svc-client-rsa' }
T 'PFX with an empty password' { (Call $req (Spec-PfxNP)).client_cn -eq 'svc-client-rsa' }
T 'PEM pair' { (Call $req (Spec-Pem)).client_cn -eq 'svc-client-rsa' }
T 'PEM pair with an encrypted key' { (Call $req (Spec-PemEnc)).client_cn -eq 'svc-client-rsa' }
T 'EC key' { (Call $req (Spec-Ec)).client_cn -eq 'svc-client-ec' }
T 'Two certificates in a row each present their own identity' {
    $a = (Call $req (Spec-Pem)).client_cn; $b = (Call $req (Spec-Ec)).client_cn; $c2 = (Call $req (Spec-Pem)).client_cn
    ($a -eq 'svc-client-rsa') -and ($b -eq 'svc-client-ec') -and ($c2 -eq 'svc-client-rsa')
}
T 'AuthType Certificate sends no Authorization header' { $r = Call $req (Spec-Pem); -not ($r.headers.PSObject.Properties.Name -contains 'Authorization') }
T 'A certificate the CA did not issue is refused by the server' { (ErrorOf { Call $req (Spec-Bad) }) -match 'failed' }
T 'AuthType Certificate with no certificate says what to do' { (ErrorOf { Invoke-APIRequest -BaseUrl $req -Endpoint whoami -AuthType Certificate -Silent }) -match 'needs a client certificate' }
T 'The optional-certificate port sees no certificate when none is sent' { (Call $opt $null 'DotNet' 'whoami' 'None').client_presented -eq $false }
T 'A certificate can accompany another AuthType' { (Call $opt (Spec-Pem) 'DotNet' 'whoami' 'None').client_cn -eq 'svc-client-rsa' }
T 'A wrong PFX password is refused, even after the file was opened with the right one' {
    $null = Call $req (Spec-Pfx)
    $bad = New-ServiceClientCertificate -PfxPath (Join-Path $CertDir 'client-rsa.pfx') -Password (ConvertTo-SecureString 'wrong' -AsPlainText -Force)
    (ErrorOf { Call $req $bad }) -match 'could not be opened with the supplied password'
}
T 'The error surface is kept: status, body and message' {
    try { Call $req (Spec-Pem) 'DotNet' 'status/404' | Out-Null; 'no error' }
    catch { ($_.Exception.Response.StatusCode.value__ -eq 404) -and ($_.ErrorDetails.Message -match 'status/404') -and ($_.Exception.Message -match '404') }
}

# ----------------------------------------------------------------------------
'--- certificate store ---'
$pfxForStore = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
    (Join-Path $CertDir 'client-rsa.pfx'), 'client-pass-1',
    [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet)
$store = [Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser')
$store.Open('ReadWrite'); $store.Add($pfxForStore); $store.Close()
$thumb = $pfxForStore.Thumbprint
T 'Store certificate by thumbprint' { (Call $req (New-ServiceClientCertificate -Thumbprint $thumb)).client_cn -eq 'svc-client-rsa' }
T 'Store certificate by full subject' { (Call $req (New-ServiceClientCertificate -Subject 'CN=svc-client-rsa')).client_cn -eq 'svc-client-rsa' }
T 'Store certificate by plain name' { (Call $req (New-ServiceClientCertificate -Subject 'svc-client-rsa')).client_cn -eq 'svc-client-rsa' }
T 'A thumbprint that is not in the store is reported' { (ErrorOf { Call $req (New-ServiceClientCertificate -Thumbprint ('0' * 40)) }) -match 'No certificate with a private key' }

# ----------------------------------------------------------------------------
'--- registered service: default, override, persistence ---'
function Set-VaultStub {
    # Stand in for the vault: record the label asked for and return the test passphrase.
    # A forced import builds a fresh module, so this is applied again after each one.
    & (Get-Module ServiceAPI) {
        $script:VaultLabels = @()
        Set-Item -Path 'function:script:Get-ServiceCredential' -Value {
            param($Service, $Environment, $AuthType, $Label, $Vault)
            $script:VaultLabels += $Label
            @{ Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('cert:client-pass-1')) }
        }
    }
}
Set-VaultStub
Register-CustomService -ServiceName partner -BaseUrl $req -ClientCertificate (Spec-Pem) -Force | Out-Null
T 'A registered certificate is the default for AuthType Certificate' { (Invoke-APIRequest -Service partner -Endpoint whoami -AuthType Certificate -Silent).client_cn -eq 'svc-client-rsa' }
T 'A certificate passed to the request overrides the default' { (Invoke-APIRequest -Service partner -Endpoint whoami -AuthType Certificate -ClientCertificate (Spec-Ec) -Silent).client_cn -eq 'svc-client-ec' }
T 'The vault is asked for the clientcert label when a PFX needs a password' {
    Register-CustomService -ServiceName partnerpfx -BaseUrl $req -ClientCertificate (New-ServiceClientCertificate -PfxPath (Join-Path $CertDir 'client-rsa.pfx')) -Force | Out-Null
    $r = Invoke-APIRequest -Service partnerpfx -Endpoint whoami -AuthType Certificate -Silent
    ($r.client_cn -eq 'svc-client-rsa') -and ((& $m { $script:VaultLabels }) -contains 'clientcert')
}
Register-CustomService -ServiceName persisted -BaseUrl $req -ClientCertificate (Spec-Pfx) -Transport Curl -CaBundle $ca -Persistent -Force | Out-Null
$servicesJson = Join-Path (& $m { $script:ServiceApiConfigPath }) 'services.json'
T 'services.json holds the certificate location, transport and CA bundle' {
    $e = (Get-Content $servicesJson -Raw | ConvertFrom-Json).persisted.prod
    ($e.ClientCertificate.Source -eq 'Pfx') -and ($e.ClientCertificate.Path -like '*client-rsa.pfx') -and ($e.Transport -eq 'Curl') -and ($e.CaBundle -eq $ca)
}
T 'services.json never holds the password' { -not ((Get-Content $servicesJson -Raw) -match 'client-pass-1') -and -not ((Get-Content $servicesJson -Raw) -match '"Password"') }
Import-Module $ModulePath -Force 3>$null
$m = Get-Module ServiceAPI
Set-VaultStub
T 'The persisted certificate, transport and CA bundle survive a module reload' {
    $e = $global:ServiceRegistry['persisted']['prod']
    ($e.ClientCertificate.Source -eq 'Pfx') -and ($null -eq $e.ClientCertificate.Password) -and ($e.Transport -eq 'Curl') -and ($e.CaBundle -eq $ca)
}

# ----------------------------------------------------------------------------
'--- curl/OpenSSL transport ---'
T 'curl built with OpenSSL is found' { (& $m { Get-ServiceCurlPath -Refresh }) -match 'curl' }
T 'curl: PFX with a password' { (Call $req (Spec-Pfx) 'Curl').client_cn -eq 'svc-client-rsa' }
T 'curl: PFX with an empty password' { (Call $req (Spec-PfxNP) 'Curl').client_cn -eq 'svc-client-rsa' }
T 'curl: PEM pair' { (Call $req (Spec-Pem) 'Curl').client_cn -eq 'svc-client-rsa' }
T 'curl: PEM pair with an encrypted key' { (Call $req (Spec-PemEnc) 'Curl').client_cn -eq 'svc-client-rsa' }
T 'curl: EC key on a TLS 1.3 only server' { $r = Call $tls13 (Spec-Ec) 'Curl'; ($r.client_cn -eq 'svc-client-ec') -and ($r.tls -eq 'TLSv1.3') }
T 'curl: store certificate (exported to a temporary PFX)' { (Call $req (New-ServiceClientCertificate -Thumbprint $thumb) 'Curl').client_cn -eq 'svc-client-rsa' }
T 'curl: a certificate the CA did not issue is refused' { (ErrorOf { Call $req (Spec-Bad) 'Curl' }) -match 'curl exit code' }
T 'curl: an untrusted server certificate says how to fix it' {
    (ErrorOf { Invoke-APIRequest -BaseUrl $req -Endpoint whoami -AuthType Certificate -ClientCertificate (Spec-Pem) -Transport Curl -Silent }) -match 'exit code 60.*-CaBundle'
}
T 'curl: a missing CA bundle file is reported' { (ErrorOf { Invoke-APIRequest -BaseUrl $req -Endpoint whoami -AuthType Certificate -ClientCertificate (Spec-Pem) -Transport Curl -CaBundle (Join-Path $work 'none.pem') -Silent }) -match 'CA bundle .* was not found' }
T 'curl: body, headers with quotes and backslashes, and query string arrive intact' {
    $r = Invoke-APIRequest -Method POST -BaseUrl $req -Endpoint 'whoami?x=1&y=two' -AuthType Certificate -ClientCertificate (Spec-Pem) -Transport Curl -CaBundle $ca `
        -Body @{ a = 1; b = 'two' } -Headers @{ 'X-Test' = 'abc"def\ghi' } -Silent
    ($r.method -eq 'POST') -and ($r.query -eq 'x=1&y=two') -and ($r.headers.'X-Test' -eq 'abc"def\ghi') -and (($r.body | ConvertFrom-Json).b -eq 'two') -and ($r.headers.'Content-Type' -like 'application/json*')
}
T 'curl: the error surface is kept: status, body and message' {
    try { Call $req (Spec-Pem) 'Curl' 'status/404' | Out-Null; 'no error' }
    catch { ($_.Exception.Response.StatusCode.value__ -eq 404) -and ($_.ErrorDetails.Message -match 'status/404') -and ($_.Exception.Message -match '404 \(Not Found\)') }
}
T 'curl: a header with a line break is refused' { (ErrorOf { Invoke-APIRequest -BaseUrl $req -Endpoint whoami -AuthType Certificate -ClientCertificate (Spec-Pem) -Transport Curl -CaBundle $ca -Headers @{ 'X-Bad' = "a`r`nInjected: yes" } -Silent }) -match 'line break' }
T 'curl: no temporary files are left behind' { @(Get-ChildItem ([IO.Path]::GetTempPath()) -Filter 'svcapi-*' -ErrorAction SilentlyContinue).Count -eq 0 }
T 'curl: no secret appears on the command line while a request is running' {
    $job = Start-Job -ArgumentList $ModulePath, $CertDir, $work, $env:SSL_CERT_FILE -ScriptBlock {
        param($mod, $dir, $home2, $ssl)
        $env:HOME = $home2; $env:SSL_CERT_FILE = $ssl
        Import-Module $mod -Force 3>$null
        $spec = New-ServiceClientCertificate -PfxPath (Join-Path $dir 'client-rsa.pfx') -Password (ConvertTo-SecureString 'client-pass-1' -AsPlainText -Force)
        Invoke-APIRequest -BaseUrl 'https://localhost:18447' -Endpoint 'sleep/4' -AuthType Certificate -ClientCertificate $spec -Transport Curl -CaBundle (Join-Path $dir 'ca.crt') `
            -Headers @{ Authorization = 'Bearer super-secret-bearer' } -Silent | Out-Null
    }
    $seen = @()
    for ($i = 0; $i -lt 30 -and $seen.Count -eq 0; $i++) {
        Start-Sleep -Milliseconds 200
        $seen = @(Get-ChildItem /proc -Directory | Where-Object { $_.Name -match '^\d+$' } | ForEach-Object {
            $f = "/proc/$($_.Name)/cmdline"
            if (Test-Path $f) { $c = (Get-Content $f -Raw -ErrorAction SilentlyContinue) -replace "`0", ' '; if ($c -match 'curl' -and $c -match '-K') { $c } }
        })
    }
    Wait-Job $job -Timeout 30 | Out-Null; Remove-Job $job -Force
    ($seen.Count -gt 0) -and ($seen[0] -notmatch 'client-pass-1|super-secret|client-rsa|localhost') -and ($seen[0] -match '-K -')
}
T 'curl is chosen by the registered service and a request can switch back' {
    $viaCurl = Invoke-APIRequest -Service persisted -Endpoint whoami -AuthType Certificate -Silent -Verbose 4>&1
    $curlUsed = @($viaCurl | Where-Object { $_ -is [System.Management.Automation.VerboseRecord] -and $_.Message -match 'curl' }).Count -gt 0
    $viaNet = Invoke-APIRequest -Service persisted -Endpoint whoami -AuthType Certificate -Transport DotNet -Silent -Verbose 4>&1
    $netUsed = @($viaNet | Where-Object { $_ -is [System.Management.Automation.VerboseRecord] -and $_.Message -match '\(curl\)|Transport: curl' }).Count -eq 0
    $curlUsed -and $netUsed
}

# ----------------------------------------------------------------------------
$store = [Security.Cryptography.X509Certificates.X509Store]::new('My', 'CurrentUser')
$store.Open('ReadWrite'); $store.Remove($pfxForStore); $store.Close()
"`nRESULT: $script:pass passed, $script:fail failed"
Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
if ($script:fail -gt 0) { exit 1 }
