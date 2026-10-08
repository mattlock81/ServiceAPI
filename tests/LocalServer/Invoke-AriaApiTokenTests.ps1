<#
.SYNOPSIS
    Tests of the AriaApiToken SSO provider against the local test server's Aria emulation.

.DESCRIPTION
    Start the server first (see ../README.md). The server emulates three Aria deployments by port:
    18080 (csp-authorize), 18081 (oauth-tenant) and 18082 (iaas-login only). Uses a throwaway HOME
    and two KeePass key-file vaults. Run non-interactively so a prompt fails instead of hanging:

        pwsh -NoProfile -NonInteractive -File Invoke-AriaApiTokenTests.ps1 -ModulePath <repo>/ServiceAPI.psd1

    These tests prove the module against the emulation only. The call shapes are not yet
    verified against a real Aria tenant; use Invoke-AriaApiTokenProbe for that.
#>
param([Parameter(Mandatory)][string]$ModulePath)
$ErrorActionPreference = 'Stop'

# These tests point HOME at a throwaway folder. That isolates the module's data files and the
# SecretManagement registrations on Linux only; on Windows they would use the real profile.
if ($PSVersionTable.PSEdition -eq 'Desktop' -or (Test-Path Variable:\IsWindows) -and $IsWindows) {
    throw 'These tests are written for Linux (they isolate state through HOME). Run them on a Linux host or in WSL.'
}

$work = Join-Path ([IO.Path]::GetTempPath()) ('sat-' + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $work | Out-Null
$env:HOME = $work
$script:pass = 0; $script:fail = 0
function T($name, [scriptblock]$test) {
    try { $r = & $test; if ($r -eq $true) { $script:pass++; "PASS  $name" } else { $script:fail++; "FAIL  $name -> $r" } }
    catch { $script:fail++; "FAIL  $name -> EXC: $($_.Exception.Message)" }
}
function ErrorOf([scriptblock]$test) { try { & $test | Out-Null; $null } catch { ($_.Exception.Message -replace '\s+', ' ') } }

foreach ($n in 'testvault', 'testvault2') {
    Register-KeePassSecretVault -Name $n -Path (Join-Path $work "$n.kdbx") -KeyPath (Join-Path $work "$n.key") -UseMasterPassword:$false -Create 2>&1 | Out-Null
}
Import-Module $ModulePath -Force 3>$null
Set-ServiceVault -Name testvault

$base = 'http://127.0.0.1'
function Reg($svc, $port, $tenant) {
    $p = @{ ServiceName = $svc; BaseUrl = "${base}:$port"; SSOProvider = 'AriaApiToken' }
    if ($tenant) { $p['SSOTenant'] = $tenant }
    Register-CustomService @p | Out-Null
}
function Store($svc, $secret, $vault = 'testvault') {
    & (Get-Module ServiceAPI) {
        param($s, $t, $v)
        Set-Secret -Name "$s-apitoken-prod" -Secret $t -Vault $v
        Write-VaultIndex -ServiceKey "$s-prod" -Label 'apitoken' -Vault $v
    } $svc $secret $vault
}
function Cache($svc) { & (Get-Module ServiceAPI) { param($k) $global:ServiceSSOTokens[$k] } "$svc-prod" }
function ExchangePosts { (Invoke-RestMethod "${base}:18080/_log") | Where-Object { $_.method -eq 'POST' } | ForEach-Object { $_.path } }
function ResetLog { Invoke-RestMethod "${base}:18080/_reset" | Out-Null }

Reg 'ariacsp'   18080 $null;          Store 'ariacsp'   ':api-token-valid'
Reg 'ariaoauth' 18081 'aria-example'; Store 'ariaoauth' ':api-token-valid'
Reg 'ariaiaas'  18082 $null;          Store 'ariaiaas'  ':api-token-valid'
Reg 'ariabad'   18080 $null;          Store 'ariabad'   ':api-token-expired'
Reg 'ariakey'   18080 $null;          Store 'ariakey'   'somekey:api-token-valid'
Reg 'ariavault2' 18080 $null;         Store 'ariavault2' ':api-token-valid' 'testvault2'
Reg 'arianone'  18080 $null

"--- the three Aria deployments ---"
T 'csp deployment: the csp bearer is rejected by the probe, so the iaas-login bearer is chosen' {
    $r = Invoke-APIRequest -Service ariacsp -Endpoint 'iaas/api/projects' -AuthType SSO
    $c = Cache 'ariacsp'
    ($r.totalElements -eq 0) -and ($c.Provider -eq 'AriaApiToken') -and ($c.BearerMode -eq 'iaas') -and ($c.ExchangeMode -eq 'iaas-login')
}
T 'oauth deployment (tenant registered): the oauth-tenant bearer is accepted' {
    $r = Invoke-APIRequest -Service ariaoauth -Endpoint 'iaas/api/projects' -AuthType SSO
    $c = Cache 'ariaoauth'
    ($r.totalElements -eq 0) -and ($c.BearerMode -eq 'oauth') -and ($c.ExchangeMode -eq 'oauth-tenant')
}
T 'iaas-only deployment: the first two shapes are refused and iaas-login is used' {
    $r = Invoke-APIRequest -Service ariaiaas -Endpoint 'iaas/api/projects' -AuthType SSO
    $c = Cache 'ariaiaas'
    ($r.totalElements -eq 0) -and ($c.BearerMode -eq 'iaas') -and ($c.ExchangeMode -eq 'iaas-login')
}

"--- caching and refresh ---"
T 'a second call reuses the cached bearer (no new exchange)' {
    ResetLog
    Invoke-APIRequest -Service ariacsp -Endpoint 'iaas/api/projects' -AuthType SSO | Out-Null
    @(ExchangePosts).Count -eq 0
}
T 'a stale bearer is exchanged again, trying the cached shape first' {
    ResetLog
    (Cache 'ariacsp').ExpiresAt = [DateTime]::UtcNow.AddMinutes(-1)
    Invoke-APIRequest -Service ariacsp -Endpoint 'iaas/api/projects' -AuthType SSO | Out-Null
    $posts = @(ExchangePosts)
    ($posts.Count -eq 1) -and ($posts[0] -eq '/iaas/api/login')
}
T 'a new process needs no interaction (session cache cleared, API token read from the vault)' {
    & (Get-Module ServiceAPI) { $global:ServiceSSOTokens.Clear() }
    (Invoke-APIRequest -Service ariacsp -Endpoint 'iaas/api/projects' -AuthType SSO).totalElements -eq 0
}
T 'the bearer is held as a SecureString and the API token is not cached' {
    $c = Cache 'ariacsp'
    ($c.Token -is [securestring]) -and (-not $c.ContainsKey('ApiToken')) -and (-not $c.ContainsKey('RefreshToken'))
}

"--- failures ---"
T 'an invalid API token fails, lists each shape, and does not leak the token' {
    $m = ErrorOf { Invoke-APIRequest -Service ariabad -Endpoint 'iaas/api/projects' -AuthType SSO }
    ($m -match 'refused by every call shape') -and ($m -match 'csp-authorize=400') -and ($m -match 'iaas-login=400') -and ($m -notmatch 'api-token-expired')
}
T 'a missing API token fails fast when unattended (no hang)' {
    $m = ErrorOf { Invoke-APIRequest -Service arianone -Endpoint 'iaas/api/projects' -AuthType SSO }
    [bool]$m
}
T 'a token stored with a key is refused with instructions' {
    $m = ErrorOf { Invoke-APIRequest -Service ariakey -Endpoint 'iaas/api/projects' -AuthType SSO }
    $m -match 'without a key'
}

"--- vaults ---"
T '-Vault reads the API token from a named vault' {
    & (Get-Module ServiceAPI) { $global:ServiceSSOTokens.Clear() }
    (Invoke-APIRequest -Service ariavault2 -Endpoint 'iaas/api/projects' -AuthType SSO -Vault testvault2).totalElements -eq 0
}

"--- probe ---"
T 'the probe reports every shape and bearer acceptance, and never prints the token' {
    $out = (& { & (Get-Module ServiceAPI) { Invoke-AriaApiTokenProbe -Service ariacsp } } *>&1 | ForEach-Object { "$_" }) -join "`n"
    ($out -match 'csp-authorize') -and ($out -match 'iaas-login') -and ($out -match 'accepted') -and ($out -match 'rejected') -and ($out -notmatch 'api-token-valid')
}
T 'the probe on the oauth deployment shows the oauth-tenant shape' {
    $out = (& { & (Get-Module ServiceAPI) { Invoke-AriaApiTokenProbe -Service ariaoauth } } *>&1 | ForEach-Object { "$_" }) -join "`n"
    ($out -match 'oauth-tenant\s+-> 200 OK') -and ($out -match 'csp-authorize\s+-> HTTP 404')
}

"`nRESULT: $script:pass passed, $script:fail failed"
Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
