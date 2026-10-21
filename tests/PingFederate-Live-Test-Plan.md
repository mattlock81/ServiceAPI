# PingFederate provider: live test plan

For an AI tool (or a person) to run against a real PingFederate server. It tests the `PingFederate` SSO provider of the ServiceAPI PowerShell module. The provider has only been tested against a local mock, so every result here is new evidence.

Placeholders are in `<angle brackets>`. Never write a real host name, client id, secret, token, group name or user name into a report.

---

## 0. Rules for the tool running this plan

1. **Never print, log, echo or store a secret.** That covers the client secret, any access, refresh or id token, and any claim value. The module and the probe print names only; keep it that way. If a command would print a value, do not run it.
2. **Steps marked HUMAN need a person.** Entering the client secret and signing in through the browser cannot be done by the tool. Stop, tell the person exactly what to do, and wait for them to say it is done.
3. **Run the steps in order.** If a step fails, record the failure, run only the cleanup in section 9, and report. Do not retry a failed sign-in more than once: repeated failures can lock the client or the account.
4. **Do not change anything outside this plan.** Do not edit module files, PingFederate configuration, or other registered services. Use only the service name `pingtest` and the environment `test`.
5. **Report honestly.** A step that was skipped, blocked or not run is reported as such, with the reason. Never mark a step PASS from memory or by inference.
6. Everything is **PowerShell 7** (`pwsh`) unless a step says otherwise.

---

## 1. Parameters (the person fills these in before the run)

| Name | Meaning | Value |
|---|---|---|
| `<PF_BASE_URL>` | PingFederate base URL, for example `https://host:9031` (no trailing path) | |
| `<REDIRECT_URI>` | The redirect URI registered on the client. Must be `http` and `127.0.0.1` or `localhost` | default `http://127.0.0.1:8080/callback`; the port assigned to the application can be given with `-OidcRedirectPort` |
| `<API_URL>` | Optional. A second host whose API accepts the bearer. Leave empty to use PingFederate's own userinfo endpoint | |
| `<API_ENDPOINT>` | Optional. A cheap read-only endpoint on `<API_URL>` (or `idp/userinfo.openid` on PingFederate) that returns 2xx for a valid bearer | `idp/userinfo.openid` |
| `<VAULT>` | Optional. A registered SecretManagement vault name for the client credential | session only if empty |
| `<MODULE_PATH>` | Path to `ServiceAPI.psd1` | |

The client is a confidential client: authorization code grant enabled, PKCE disabled, client id and secret. The person has both; the tool never needs them.

---

## 2. Preflight

**T01 Environment.** Run:

```powershell
$PSVersionTable.PSVersion.ToString()
$PSVersionTable.Platform
Import-Module '<MODULE_PATH>' -Force
$m = Get-Module ServiceAPI
$m.Version.ToString()
& $m { Get-Command Invoke-PingFederateLogin, Invoke-PingFederateProbe, Resolve-PingFederateScope, Wait-PingFederateCallback | Select-Object -ExpandProperty Name }
(Get-Command Register-CustomService).Parameters.Keys | Where-Object { $_ -like 'Oidc*' }
```

Expected: PowerShell 7.x; the four private functions listed; `OidcAuthority`, `OidcScope` and `OidcRedirectUri` present. Record the PowerShell version, the platform and the module version.

**T02 Reachability.** Run (no credentials involved):

```powershell
try { (Invoke-WebRequest -Uri '<PF_BASE_URL>/.well-known/openid-configuration' -UseBasicParsing).StatusCode } catch { $_.Exception.Message }
```

Expected: `200`. A certificate error here means the private CA is not trusted on this host: record the error message (not the host name) and stop; the module has the same dependency. A `404` is acceptable (discovery not published; the module falls back to the default paths); record it.

**T03 Discovery as the module sees it.**

```powershell
& $m { $e = Get-PingFederateEndpoint -Authority '<PF_BASE_URL>'; [pscustomobject]@{ Source = $e.Source; AuthMethods = ($e.AuthMethods -join ','); TokenEndpointPath = ([uri]$e.TokenEndpoint).AbsolutePath; AuthorizationEndpointPath = ([uri]$e.AuthorizationEndpoint).AbsolutePath } }
```

Expected: `Source` is `discovery` or `default`. Record Source, the advertised auth methods and the two paths. Do not record the host.

---

## 3. Register the service and store the client

**T04 Register (session only).**

```powershell
Register-CustomService -ServiceName pingtest -Environment test -BaseUrl '<PF_BASE_URL>' -SSOProvider PingFederate `
    -OidcRedirectUri '<REDIRECT_URI>' -OidcScope 'openid profile ad' -Force
$global:ServiceRegistry['pingtest']['test'] | Select-Object SSOProvider, OidcScope, OidcRedirectUri | Format-List
```

Expected: provider `PingFederate`, scope `openid profile ad`, the redirect URI as given.

**T05 Store the client. HUMAN.** Ask the person to run, in their own terminal, in the same PowerShell session if the credential is session-only:

```powershell
Set-ServiceCredential -Service pingtest -Environment test -AuthType Basic -Label oidcclient
```

(adding `-Vault <VAULT>` when a vault is used) and to enter the client id as the user name and the client secret as the password. Wait for confirmation. If the person uses `-Vault`, the credential survives a new process (needed by T13); otherwise T13 is SKIPPED.

---

## 4. Sign in

**T06 First login. HUMAN (browser).** Tell the person a browser tab will open and they must sign in. If no browser opens, the module prints a URL: the person opens it in a browser on the same host. Then run:

```powershell
& $m { Invoke-PingFederateProbe -Service pingtest -Environment test -Verbose }
```

Expected output lines (names only): `Endpoints from`, `Client auth` (`basic` or `post`), `Scope requested`, `Scope granted`, `Refresh token` (`issued` or `not issued`), `Expires (UTC)`, `id_token claims`, and one line per granted catalogued scope with claims present and absent.

Record, verbatim except for the host: endpoint source, client auth method, requested versus granted scope, refresh token issued or not, the expiry, the id_token claim names, the per-scope present/absent lines, and any warning. A "did not grant the scope(s)" warning is a finding, not a failure.

PASS when the login completes and a bearer is cached. FAIL when it errors; record the error text (it carries the HTTP status and OAuth error only). Common causes: `invalid_client` (wrong id or secret, or not a confidential client), `invalid_grant` or a redirect error (the redirect URI on the client differs from `<REDIRECT_URI>`), a timeout (the browser is on another host, or another process holds the port).

**T07 The cached entry has no secrets in the places it should not.**

```powershell
& $m {
  $c = $global:ServiceSSOTokens['pingtest-test']
  [pscustomobject]@{
    Provider = $c.Provider; AuthMode = $c.AuthMode; Scope = $c.Scope
    HasRefreshToken = [bool]$c.RefreshToken
    TokenType = $c.Token.GetType().Name
    MinutesToExpiry = [math]::Round(($c.ExpiresAt - [DateTime]::UtcNow).TotalMinutes, 1)
    ClaimNames = (@($c.Claims.Keys) | Sort-Object) -join ','
  }
}
```

Expected: `TokenType` is `SecureString`, a positive `MinutesToExpiry`. Record the table. Do not print `$c.Token`, `$c.RefreshToken` or `$c.Claims` values.

---

## 5. Use the token

**T08 A real call.**

```powershell
Invoke-APIRequest -Service pingtest -Environment test -Endpoint '<API_ENDPOINT>' -AuthType SSO -Verbose 4>&1 | Where-Object { $_ -is [System.Management.Automation.VerboseRecord] } | ForEach-Object { $_.Message }
```

If `<API_URL>` is set, first register it (`Register-CustomService -ServiceName pingapi -Environment test -BaseUrl '<API_URL>' -SSOProvider PingFederate -OidcAuthority '<PF_BASE_URL>' -OidcRedirectUri '<REDIRECT_URI>' -Force`) and call it with `-Service pingapi`. It needs its own T05/T06 (the same client; the person re-enters it or uses the vault).

Expected: the call returns without error (HTTP 2xx). Do not print the response body; record only that it succeeded, or the HTTP status and message if it threw. A `401` or `403` means the API does not accept this bearer or this identity: record which, and run T16.

---

## 6. Refresh

**T09 Silent refresh.** Skip (SKIPPED, reason "no refresh token issued") if T06 said `not issued`.

```powershell
& $m { $global:ServiceSSOTokens['pingtest-test'].ExpiresAt = [DateTime]::UtcNow.AddMinutes(1) }
$v = Get-ServiceCredential -Service pingtest -Environment test -AuthType SSO -Verbose 4>&1
$v | Where-Object { $_ -is [System.Management.Automation.VerboseRecord] -and $_.Message -match 'Stored SSO token' } | ForEach-Object { $_.Message -replace '\[.*?\]','[..]' }
```

Expected: no browser opens, and the verbose line contains `(refresh,`. FAIL if a browser opens or the line says `(browser,`. Record the line.

**T10 Dead refresh token falls back to the browser. HUMAN (browser).** Only if T09 passed.

```powershell
& $m { $c = $global:ServiceSSOTokens['pingtest-test']; $c.RefreshToken = (ConvertTo-SecureString 'not-a-real-refresh-token' -AsPlainText -Force); $c.ExpiresAt = [DateTime]::UtcNow.AddMinutes(1) }
Get-ServiceCredential -Service pingtest -Environment test -AuthType SSO -Verbose 4>&1 | Where-Object { $_ -is [System.Management.Automation.VerboseRecord] -and $_.Message -match 'rejected|Stored SSO token' } | ForEach-Object { $_.Message -replace '\[.*?\]','[..]' }
```

Expected: a verbose line saying the refresh token was rejected (`invalid_grant`), the browser opens (the person signs in again, or PingFederate's own session signs them in silently), and the final line contains `(browser,`. Record both lines. If PingFederate answers something other than `invalid_grant` for a bad refresh token (for example `invalid_request`), the module throws instead of falling back: record the exact error. That is a finding to report, not a plan failure.

---

## 7. Scopes

**T11 The full catalogue.** Request every scope the person says the client may use:

```powershell
Register-CustomService -ServiceName pingtest -Environment test -BaseUrl '<PF_BASE_URL>' -SSOProvider PingFederate `
    -OidcRedirectUri '<REDIRECT_URI>' -OidcScope 'openid profile ad app brf camkeys coi eci lac rel' -Force
& $m { $global:ServiceSSOTokens.Remove('pingtest-test') }
& $m { Invoke-PingFederateProbe -Service pingtest -Environment test }
```

HUMAN: the person signs in again if prompted. Record requested versus granted scope, the claim names, and the per-scope present/absent lines.

**T12 Isolate each refused scope.** For every scope that T11 reported as not granted, request only `openid <scope>`, repeating the three commands of T11 with that single scope, and record the result (granted, or the exact `invalid_scope` error). Stop after at most eight scopes. This tells the person which scopes the client may request.

Also answer, from T11 and T12 only: **do the scope names `app`, `brf`, `camkeys`, `coi`, `eci`, `lac` and `rel` work as plain names?** If they all fail with `invalid_scope` but PingFederate documents `app:app`, `brf:brf` and so on, say so; the module's scope handling then needs to change.

---

## 8. Robustness

**T13 New process, no prompts.** Only if the client is in a vault (T05 used `-Vault`) and T06 issued a refresh token; otherwise SKIPPED. The cache is per process, so a refresh token does not survive; this checks the non-interactive message and that nothing hangs:

```powershell
$tmp = Join-Path ([IO.Path]::GetTempPath()) 'pingtest-noni.ps1'
@'
Import-Module $env:PINGTEST_MODULE -Force
try { Get-ServiceCredential -Service pingtest -Environment test -AuthType SSO | Out-Null; 'unexpected success' }
catch { $_.Exception.Message }
'@ | Set-Content -LiteralPath $tmp
$env:PINGTEST_MODULE = '<MODULE_PATH>'
pwsh -NoProfile -NonInteractive -File $tmp
Remove-Item $tmp
```

Expected: completes within seconds with a message that a browser login is needed and the session is non-interactive. FAIL if it hangs, prompts, or opens a browser. Run with a 60 second timeout.

**T14 Wrong redirect URI is reported clearly. HUMAN-aware.** Calls the login directly with a redirect URI that is not registered on the client, and a 30 second timeout (nothing is printed except the outcome):

```powershell
& $m {
  $c = Get-PingFederateClient -Service pingtest -Environment test
  try { Invoke-PingFederateLogin -Authority '<PF_BASE_URL>' -ClientId $c.ClientId -ClientSecret $c.ClientSecret `
          -RedirectUri 'http://127.0.0.1:47999/callback' -TimeoutSeconds 30 | Out-Null; 'unexpected success' }
  catch { $_.Exception.Message }
}
```

Expected: PingFederate shows an error page about the redirect URI in the browser (the person reports what it says, without any host names), and the command ends after about 30 seconds with "Timed out ... waiting for the PingFederate login". FAIL if it reports success or hangs past 60 seconds.

**T15 Unknown scope warns.**

```powershell
& $m { Resolve-PingFederateScope -Scope 'openid ad notarealscope' } 3>&1 | ForEach-Object { if ($_ -is [System.Management.Automation.WarningRecord]) { 'WARNING: ' + $_.Message } else { $_ } }
```

Expected: a warning naming `notarealscope`, and `openid ad notarealscope` returned. (No server call.)

**T16 Probe endpoint and 403 handling. Optional.** Only if T08 returned `403`, or the person wants it. Register a probe endpoint and repeat T08:

```powershell
Register-CustomService -ServiceName pingtest -Environment test -BaseUrl '<PF_BASE_URL>' -SSOProvider PingFederate -OidcRedirectUri '<REDIRECT_URI>' -ProbeEndpoint '<API_ENDPOINT>' -Force
```

Record whether the 403 is reported as an authorisation denial (the bearer passed the probe) or the token was refreshed and retried.

**T17 Persistence round trip.**

```powershell
Register-CustomService -ServiceName pingtest -Environment test -BaseUrl '<PF_BASE_URL>' -SSOProvider PingFederate -OidcRedirectUri '<REDIRECT_URI>' -OidcScope 'openid profile ad' -Persistent -Force
Import-Module '<MODULE_PATH>' -Force
$global:ServiceRegistry['pingtest']['test'] | Select-Object SSOProvider, OidcScope, OidcRedirectUri | Format-List
```

Expected: the three values survive a module reload. (Cleanup in section 9 removes the persisted entry.)

---

## 9. Cleanup (always run, even after a failure)

```powershell
Clear-ServiceCredential -Service pingtest -Environment test -AuthType SSO -Force
Clear-ServiceCredential -Service pingtest -Environment test -AuthType Basic -Label oidcclient -Force
# Remove the persisted registration written by T17
$m = Get-Module ServiceAPI
$dir  = & $m { $script:ServiceApiConfigPath }
$file = Join-Path $dir 'services.json'
if (Test-Path $file) {
  $j = Get-Content $file -Raw | ConvertFrom-Json
  foreach ($name in 'pingtest','pingapi','pingmtls') {
    if ($j.PSObject.Properties[$name]) { $j.PSObject.Properties.Remove($name) }
  }
  $j | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $file -Encoding UTF8
}
$global:ServiceRegistry.Remove('pingtest'); $global:ServiceRegistry.Remove('pingapi'); $global:ServiceRegistry.Remove('pingmtls')
```

Also remove the `clientcert` credential if T18 stored one: `Clear-ServiceCredential -Service pingtest -Environment test -AuthType Basic -Label clientcert -Force`. Confirm nothing named `pingtest`, `pingapi` or `pingmtls` remains, and that no secret was written to a file or a transcript. If `-Vault` was used, the vault entry is removed by the `Clear-ServiceCredential` Basic line; confirm with `Get-ServiceVault`.

---

## 9a. Optional: client certificates and the curl transport (Appendix)

Run these only if the person has a service that requires a client certificate, or wants the curl/OpenSSL transport checked on this host. Extra parameters (the person fills them in):

| Name | Meaning | Value |
|---|---|---|
| `<MTLS_API_URL>` | Base URL of an API that requires a TLS client certificate | |
| `<MTLS_ENDPOINT>` | A cheap read-only endpoint on it | |
| `<PFX_PATH>` | A PKCS#12 file with the client certificate and key (or use a PEM pair or store certificate) | |
| `<CA_BUNDLE>` | A PEM file of the CAs that sign the API's server certificate (needed for the curl transport on Windows) | |

**T18 Describe and open the certificate.** The person stores the PFX password first if it has one: `Set-ServiceCredential -Service pingtest -Environment test -AuthType Basic -Label clientcert` (HUMAN; any user name, the password is the secret). Then:

```powershell
$cert = New-ServiceClientCertificate -PfxPath '<PFX_PATH>'
& $m { param($c) $r = Get-ServiceClientCertificate -Certificate $c -Service pingtest -Environment test; [pscustomobject]@{ Source = $r.Source; HasPrivateKey = $r.Certificate.HasPrivateKey; NotAfter = $r.Certificate.NotAfter.ToString('yyyy-MM-dd') } } $cert
```

Expected: `HasPrivateKey` is `True` and `NotAfter` is in the future. Do not record the subject or thumbprint.

**T19 Real call, .NET transport.**

```powershell
Invoke-APIRequest -BaseUrl '<MTLS_API_URL>' -Endpoint '<MTLS_ENDPOINT>' -AuthType Certificate -ClientCertificate $cert -Silent | Out-Null; 'ok'
```

Expected: `ok`. A TLS failure names the cause; record the message without host names. If the server also needs a bearer, repeat with `-AuthType Token` or `SSO` and the same `-ClientCertificate`.

**T20 The same call, curl transport.**

```powershell
Invoke-APIRequest -BaseUrl '<MTLS_API_URL>' -Endpoint '<MTLS_ENDPOINT>' -AuthType Certificate -ClientCertificate $cert -Transport Curl -CaBundle '<CA_BUNDLE>' -Silent | Out-Null; 'ok'
```

Expected: `ok`. Record which curl was used: `& $m { Get-ServiceCurlPath }` (path only). On Windows the curl must be the OpenSSL one from Git for Windows; the System32 `curl.exe` is refused with a message, which is itself a result to record. An exit code 60 means the CA bundle does not contain the API's issuing CA.

**T21 Registered default and override.**

```powershell
Register-CustomService -ServiceName pingmtls -Environment test -BaseUrl '<MTLS_API_URL>' -ClientCertificate $cert -Transport Curl -CaBundle '<CA_BUNDLE>' -Force
Invoke-APIRequest -Service pingmtls -Environment test -Endpoint '<MTLS_ENDPOINT>' -AuthType Certificate -Silent | Out-Null; 'curl default ok'
Invoke-APIRequest -Service pingmtls -Environment test -Endpoint '<MTLS_ENDPOINT>' -AuthType Certificate -Transport DotNet -Silent | Out-Null; 'dotnet override ok'
```

Expected: both lines. Add `pingmtls` to the cleanup list.

**T22 Windows only: a certificate-store certificate.** The person gives a thumbprint of a certificate in `Cert:\CurrentUser\My` with a private key. Repeat T19 and T20 with `$cert = New-ServiceClientCertificate -Thumbprint '<THUMBPRINT>'`. Expected: T19 passes whether or not the key is exportable; T20 passes only if the key is exportable, otherwise it stops with a message saying so. Record both outcomes. Also record whether a PFX load left a key container in the profile (`certutil -user -store My` is not needed; note only if the person sees one).

## 9b. Optional: PingFederate certificate client authentication (Appendix)

Run these only if the PingFederate client can authenticate by certificate. The person configures the client in PingFederate first: for `private_key_jwt`, register the certificate (or its JWKS) on the client and allow the signing algorithm; for `tls_client_auth`, set the client's authentication to mutual TLS and bind the certificate.

**T23 private_key_jwt.**

```powershell
$cert = New-ServiceClientCertificate -PfxPath '<PFX_PATH>'
Register-CustomService -ServiceName pingtest -Environment test -BaseUrl '<PF_BASE_URL>' -SSOProvider PingFederate `
    -OidcClientId '<CLIENT_ID>' -OidcClientAuth private_key_jwt -ClientCertificate $cert `
    -OidcRedirectUri '<REDIRECT_URI>' -OidcScope 'openid profile ad' -Force
& $m { Invoke-PingFederateProbe -Service pingtest -Environment test }
```

HUMAN: sign in at the browser. Expected: the probe reports `Client auth : jwt` and a granted scope. If PingFederate answers `invalid_client`, the message already hints at the cause; record the exact error and answer **open item 18**: which `aud` does PingFederate accept (the token endpoint, the issuer, or either), and does it need a `kid` rather than matching by certificate? Do not record the client id.

**T24 tls_client_auth.** PingFederate often serves mutual TLS on a separate port. If the token endpoint for certificate clients is on another URL, say so: the module currently uses one authority for the authorization and the token calls (open item 18), so this may need a change. Otherwise:

```powershell
Register-CustomService -ServiceName pingtest -Environment test -BaseUrl '<PF_BASE_URL>' -SSOProvider PingFederate `
    -OidcClientId '<CLIENT_ID>' -OidcClientAuth tls_client_auth -ClientCertificate $cert `
    -OidcRedirectUri '<REDIRECT_URI>' -Force
& $m { Invoke-PingFederateProbe -Service pingtest -Environment test }
```

Expected: `Client auth : tls`. Repeat once with `-Transport Curl -CaBundle '<CA_BUNDLE>'` on the registration. Record the outcomes.

## 10. Report (return this, filled in, to the person)

Redact every host name, user name, client id, group name and claim value. Claim **names**, scope names, HTTP statuses, OAuth error codes and module messages are fine.

```
Date/time (UTC):
Tool and model that ran the plan:
PowerShell version / platform:
Module version / branch:

| Step | Result (PASS / FAIL / SKIPPED / BLOCKED) | Evidence (names, statuses, error codes only) |
|------|------------------------------------------|----------------------------------------------|
| T01 Environment | | |
| T02 Reachability | | |
| T03 Discovery | | source: ; auth methods: |
| T04 Register | | |
| T05 Store client (HUMAN) | | |
| T06 First login (HUMAN) | | client auth: ; refresh token: ; granted scope: ; claims: |
| T07 Cached entry | | |
| T08 Real call | | status: |
| T09 Silent refresh | | |
| T10 Dead refresh token (HUMAN) | | |
| T11 Full scope catalogue | | requested vs granted: |
| T12 Refused scopes isolated | | |
| T13 New process, non-interactive | | |
| T14 Wrong redirect URI | | |
| T15 Unknown scope warning | | |
| T16 Probe endpoint / 403 | | |
| T17 Persistence round trip | | |
| T18 Certificate opens (appendix) | | |
| T19 mTLS call, .NET (appendix) | | |
| T20 mTLS call, curl (appendix) | | curl used: |
| T21 Registered default and override (appendix) | | |
| T22 Store certificate, Windows (appendix) | | |
| T23 PingFederate private_key_jwt (appendix) | | accepted aud: |
| T24 PingFederate tls_client_auth (appendix) | | |
| Cleanup | | |

Questions to answer in plain words:
1. Is OIDC discovery published, and which client authentication method did the server accept?
2. Was a refresh token issued? If not, which client setting is the likely cause?
3. Which of the scopes ad, app, brf, camkeys, coi, eci, lac, profile, rel were granted, and which refused?
4. Do the scope names work as plain names (app, brf, ...), or are literal strings such as app:app needed?
5. Which of the expected claims (groups, displayName, dutyOrg, email, employeeType, givenName, nationality, org, preferred_username, securityClearance, uid) were absent from the id_token?
6. If the appendices were run: did the curl transport work on this host (which curl, which TLS version if known), did the certificate load on this edition of PowerShell, and what did PingFederate accept as the assertion audience?
7. Anything surprising, any error message that was unclear, any step that needed a workaround.
```
