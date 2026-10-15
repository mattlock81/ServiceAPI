<#
.SYNOPSIS
    Tests of the PingFederate SSO provider against a mock PingFederate.

.DESCRIPTION
    Start the mock first (see ../README.md): python3 pingfed_mock.py. It listens on 18090 (both
    client authentication methods), 18091 (client_secret_post only), 18092 (no refresh token) and
    18093 (id_token with the wrong nonce). The browser is replaced by a background job that follows
    the authorization URL, and the OAuth client is supplied in place of the vault, so the run needs
    no SecretManagement. Uses a throwaway HOME. Run non-interactively:

        pwsh -NoProfile -NonInteractive -File Invoke-PingFederateTests.ps1 -ModulePath <repo>/ServiceAPI.psd1

    These tests prove the module against the mock only. Use Invoke-PingFederateProbe for the real
    server.
#>
param([Parameter(Mandatory)][string]$ModulePath)
$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSEdition -eq 'Desktop' -or (Test-Path Variable:\IsWindows) -and $IsWindows) {
    throw 'These tests are written for Linux (they isolate state through HOME). Run them on a Linux host or in WSL.'
}

$work = Join-Path ([IO.Path]::GetTempPath()) ('spt-' + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $work | Out-Null
$env:HOME = $work
$script:pass = 0; $script:fail = 0
function T($name, [scriptblock]$test) {
    try { $r = & $test; if ($r -eq $true) { $script:pass++; "PASS  $name" } else { $script:fail++; "FAIL  $name -> $r" } }
    catch { $script:fail++; "FAIL  $name -> EXC: $($_.Exception.Message)" }
}
function ErrorOf([scriptblock]$test) { try { & $test | Out-Null; $null } catch { ($_.Exception.Message -replace '\s+', ' ') } }

Import-Module $ModulePath -Force 3>$null
$m    = Get-Module ServiceAPI
$base = 'http://127.0.0.1'

# Replace the vault lookup, the interactivity check and the browser inside the module. Applied
# again after every import, because a forced import builds a fresh module.
function Set-ModuleOverrides {
& (Get-Module ServiceAPI) {
    $script:TestClientSecret = 'secret:with:colons'
    $script:BrowserOpens     = 0
    Set-Item -Path 'function:script:Get-PingFederateClient' -Value {
        param($Service, $Environment, $Vault)
        [PSCustomObject]@{ ClientId = 'test-client'; ClientSecret = (ConvertTo-SecureString $script:TestClientSecret -AsPlainText -Force) }
    }
    Set-Item -Path 'function:script:Test-ServiceApiInteractive' -Value { $true }
    Set-Item -Path 'function:script:Open-ServiceApiBrowser' -Value {
        param($Url)
        $script:BrowserOpens++
        Start-Job -ArgumentList $Url -ScriptBlock {
            param($u); Start-Sleep -Milliseconds 600
            try { Invoke-WebRequest $u -UseBasicParsing | Out-Null } catch { }
        } | Out-Null
        $true
    }
}
}
Set-ModuleOverrides
function Opens { & $m { $script:BrowserOpens } }
function Reg($svc, $port, $extra = @{}) {
    Register-CustomService -ServiceName $svc -BaseUrl "${base}:$port" -SSOProvider PingFederate -Force @extra | Out-Null
}
function Cache($svc) { & $m { param($k) $global:ServiceSSOTokens[$k] } "$svc-prod" }
function MockLog($port) { Invoke-RestMethod "${base}:$port/_log" }
foreach ($p in 18090..18093) { Invoke-RestMethod "${base}:$p/_reset" | Out-Null }

'--- scope catalogue ---'
T 'Default scope is openid profile ad' { (& $m { Resolve-PingFederateScope }) -eq 'openid profile ad' }
T 'Scopes are split on spaces and commas, deduplicated, openid added first' { (& $m { Resolve-PingFederateScope -Scope 'profile, ad rel ad' }) -eq 'openid profile ad rel' }
T 'Catalogue holds every requested scope' {
    $c = & $m { Resolve-PingFederateScope -Catalogue }
    $want = 'ad', 'app', 'brf', 'camkeys', 'coi', 'eci', 'lac', 'profile', 'rel'
    @($want | Where-Object { -not $c.Contains($_) }).Count -eq 0
}
T 'ad releases groups; rel releases uid' { $c = & $m { Resolve-PingFederateScope -Catalogue }; ($c['ad'] -join ',') -eq 'groups' -and ($c['rel'] -join ',') -eq 'uid' }
T 'profile releases the nine profile claims' {
    $c = & $m { Resolve-PingFederateScope -Catalogue }
    $c['profile'].Count -eq 9 -and 'securityClearance' -in $c['profile'] -and 'dutyOrg' -in $c['profile']
}
T 'Unknown scope warns and is still sent' {
    $w = $null; $r = & $m { Resolve-PingFederateScope -Scope 'ad bogus' } 3>&1
    (($r | Where-Object { $_ -is [string] }) -eq 'openid ad bogus') -and (@($r | Where-Object { $_ -is [Management.Automation.WarningRecord] }).Count -eq 1)
}

'--- discovery ---'
T 'Discovery is used when published' { (& $m { Get-PingFederateEndpoint -Authority 'http://127.0.0.1:18090' }).Source -eq 'discovery' }
T 'Default paths are used when discovery fails' {
    $e = & $m { Get-PingFederateEndpoint -Authority 'http://127.0.0.1:18099' }
    $e.Source -eq 'default' -and $e.TokenEndpoint -eq 'http://127.0.0.1:18099/as/token.oauth2'
}

'--- registration and persistence ---'
T 'Oidc settings persist and reload' {
    Register-CustomService -ServiceName pingpersist -BaseUrl "${base}:18090" -SSOProvider PingFederate -OidcAuthority "${base}:18090/" `
        -OidcScope 'profile, ad  app' -OidcRedirectUri 'http://127.0.0.1:47900/callback' -Persistent -Force | Out-Null
    $e = (& $m { Read-ServiceConfig })['pingpersist']['prod']
    $e.OidcAuthority -eq "${base}:18090" -and $e.OidcScope -eq 'profile ad app' -and $e.OidcRedirectUri -eq 'http://127.0.0.1:47900/callback' -and $e.SSOProvider -eq 'PingFederate'
}
T 'Oidc settings survive a module reload (Phase 5)' {
    Import-Module $ModulePath -Force 3>$null
    Set-ModuleOverrides
    $e = $global:ServiceRegistry['pingpersist']['prod']
    $e.OidcScope -eq 'profile ad app' -and $e.OidcRedirectUri -eq 'http://127.0.0.1:47900/callback'
}
$m = Get-Module ServiceAPI
T 'Non-http OidcAuthority is refused' { (ErrorOf { Register-CustomService -ServiceName pingbad -BaseUrl "${base}:18090" -SSOProvider PingFederate -OidcAuthority 'ftp://x' -Force }) -match 'must start with http' }

'--- login ---'
T 'Non-interactive session refuses a browser login' {
    & $m { Set-Item -Path 'function:script:Test-ServiceApiInteractive' -Value { $false } }
    Reg 'pingni' 18090
    $e = ErrorOf { Set-ServiceCredential -Service pingni -Environment prod -AuthType SSO -Force }
    & $m { Set-Item -Path 'function:script:Test-ServiceApiInteractive' -Value { $true } }
    $e -match 'non-interactive'
}

Reg 'pingok' 18090 @{ OidcScope = 'openid profile ad rel'; OidcRedirectUri = 'http://127.0.0.1:47812/callback' }
T 'Browser login stores the token, refresh token, scope and claims' {
    $w = Set-ServiceCredential -Service pingok -Environment prod -AuthType SSO -Force 3>&1
    $c = Cache 'pingok'
    ($c.Provider -eq 'PingFederate') -and ($c.Token -is [securestring]) -and ($c.RefreshToken -is [securestring]) -and
        ($c.Scope -eq 'openid profile ad') -and ($c.Claims.groups.Count -eq 2) -and ($c.Claims.displayName -eq 'Test Account') -and
        ($c.ExpiresAt -gt [DateTime]::UtcNow.AddMinutes(50))
}
T 'A scope PingFederate did not grant produces a warning' {
    & $m { $global:ServiceSSOTokens.Remove('pingok-prod') }
    $out = Set-ServiceCredential -Service pingok -Environment prod -AuthType SSO -Force 3>&1
    @($out | Where-Object { $_ -is [Management.Automation.WarningRecord] -and $_.Message -match 'did not grant.*rel' }).Count -eq 1
}
T 'Client authentication used basic first' {
    $codeCalls = @(MockLog 18090 | Where-Object { $_.grant -eq 'authorization_code' })
    $codeCalls.Count -ge 1 -and @($codeCalls | Where-Object { $_.auth -ne 'basic' }).Count -eq 0
}
T 'Stale token refreshes silently, without opening the browser' {
    $before = Opens
    & $m { $global:ServiceSSOTokens['pingok-prod'].ExpiresAt = [DateTime]::UtcNow.AddMinutes(1) }
    $headers = Get-ServiceCredential -Service pingok -Environment prod -AuthType SSO
    ($headers['Authorization'] -like 'Bearer at-*') -and ((Opens) -eq $before) -and
        (@(MockLog 18090 | Where-Object { $_.grant -eq 'refresh_token' }).Count -ge 1) -and ((Cache 'pingok').ExpiresAt -gt [DateTime]::UtcNow.AddMinutes(50))
}
T 'A dead refresh token falls back to the browser' {
    Invoke-RestMethod "${base}:18090/_reset" | Out-Null
    $before = Opens
    & $m { $global:ServiceSSOTokens['pingok-prod'].ExpiresAt = [DateTime]::UtcNow.AddMinutes(1) }
    Get-ServiceCredential -Service pingok -Environment prod -AuthType SSO | Out-Null
    (Opens) -eq ($before + 1)
}
T 'Claims survive a silent refresh that returns no id_token' {
    $c = Cache 'pingok'; $null -ne $c.Claims -and $c.Claims.ContainsKey('groups')
}

Reg 'pingpost' 18091
T 'Falls back to client_secret_post when basic is refused, and remembers it' {
    Set-ServiceCredential -Service pingpost -Environment prod -AuthType SSO -Force
    $c = Cache 'pingpost'
    $log = MockLog 18091
    ($c.AuthMode -eq 'post') -and (@($log | Where-Object { $_.auth -eq 'none' -or $_.auth -eq 'basic' }).Count -ge 1)
}
T 'No refresh token issued: login repeats through the browser' {
    Reg 'pingnorf' 18092
    Set-ServiceCredential -Service pingnorf -Environment prod -AuthType SSO -Force
    $c = Cache 'pingnorf'
    $before = Opens
    & $m { $global:ServiceSSOTokens['pingnorf-prod'].ExpiresAt = [DateTime]::UtcNow.AddMinutes(1) }
    Get-ServiceCredential -Service pingnorf -Environment prod -AuthType SSO | Out-Null
    ($null -eq $c.RefreshToken) -and ((Opens) -eq ($before + 1))
}
T 'id_token with the wrong nonce is refused' {
    Reg 'pingnonce' 18093
    (ErrorOf { Set-ServiceCredential -Service pingnonce -Environment prod -AuthType SSO -Force }) -match 'nonce does not match'
}
T 'Wrong client secret is refused with both methods named' {
    & $m { $script:TestClientSecret = 'wrong' }
    Reg 'pingsecret' 18090
    $e = ErrorOf { Set-ServiceCredential -Service pingsecret -Environment prod -AuthType SSO -Force }
    & $m { $script:TestClientSecret = 'secret:with:colons' }
    $e -match 'client_secret_basic and client_secret_post were refused'
}
T 'The client secret never appears in the error text' {
    & $m { $script:TestClientSecret = 'hunter2-visible?' }
    $e = ErrorOf { Set-ServiceCredential -Service pingsecret -Environment prod -AuthType SSO -Force }
    & $m { $script:TestClientSecret = 'secret:with:colons' }
    $e -notmatch 'hunter2'
}

'--- redirect listener ---'
T 'Non-loopback redirect URI is rejected' { (ErrorOf { & $m { Wait-PingFederateCallback -RedirectUri 'https://example.com/cb' -State 's' } }) -match 'http loopback' }
T 'Forged state is ignored; the right state ends the wait' {
    $r = & $m {
        Wait-PingFederateCallback -RedirectUri 'http://127.0.0.1:47813/callback' -State 'good' -TimeoutSeconds 30 -AfterStart {
            Start-Job -ScriptBlock {
                Start-Sleep -Milliseconds 600
                try { Invoke-WebRequest 'http://127.0.0.1:47813/callback?code=evil&state=bad' -UseBasicParsing | Out-Null } catch { }
                Invoke-WebRequest 'http://127.0.0.1:47813/callback?code=CODE1&state=good' -UseBasicParsing | Out-Null
            } | Out-Null
        }.GetNewClosure()
    }
    $r -eq 'CODE1'
}
T 'An error redirect with the right state throws the OAuth error' {
    (ErrorOf {
        & $m {
            Wait-PingFederateCallback -RedirectUri 'http://127.0.0.1:47814/callback' -State 'good' -TimeoutSeconds 30 -AfterStart {
                Start-Job -ScriptBlock {
                    Start-Sleep -Milliseconds 600
                    try { Invoke-WebRequest 'http://127.0.0.1:47814/callback?error=access_denied&error_description=nope&state=good' -UseBasicParsing | Out-Null } catch { }
                } | Out-Null
            }.GetNewClosure()
        }
    }) -match 'access_denied'
}

"`nRESULT: $script:pass passed, $script:fail failed"
Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
if ($script:fail -gt 0) { exit 1 }
