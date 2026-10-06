# ServiceAPI

**Version**: 2.10.0  
**Author**: Matthew Sillett  
**Organisation**:

---

## Overview

ServiceAPI is a PowerShell module that provides a unified REST API framework for interacting with multiple services. It supports Basic Auth, static Token, SSO OAuth, QueryParam (credential delivered via URL query string rather than a header), and None (unauthenticated) authentication modes via a persistent service registry pattern, with optional credential persistence through Microsoft SecretManagement vault integration.

SSO providers currently supported: `GCloud` (Google Cloud SDK), `AzureCLI` (Azure CLI), `Aria` (VMware Aria Automation — REST-native, no CLI tool required), and `AriaOidc` (Aria / VCF Automation via the portal's OIDC browser session, with a Violentmonkey courier userscript delivering the token to a loopback listener).

Services are registered once with a BaseUrl and stored in a user-scoped `services.json` file. Credentials are resolved automatically from the vault, from in-memory global state, or via interactive prompt — in that order. All public functions share a unified `-AuthType` parameter with tab completion, and the `-Service` parameter tab-completes from the live registry.

ServiceAPI degrades gracefully when optional dependencies (`SysCommon`, `Microsoft.PowerShell.SecretManagement`) are absent.

Current state, design decisions, open items and planned scope are tracked in [docs/Rehydration.md](docs/Rehydration.md). Start there when picking up the project; this readme is the identity record.

---

## Installation

```powershell
Import-Module ServiceAPI
```

---

## Quick Start

```powershell
# Register a service (persists to services.json)
Register-CustomService -ServiceName myapi -BaseUrl 'https://api.example.com/v1' -Persistent

# Store credentials in vault
Set-ServiceCredential -Service myapi -Environment prod -AuthType Basic

# Make a GET request
Invoke-APIRequest -Service myapi -Endpoint 'users/me'

# Make a POST request
$body = @{ name = 'example'; enabled = $true }
Invoke-APIRequest -Service myapi -Endpoint 'resources' -Method POST -Body $body

# Store a token credential
Set-ServiceCredential -Service myapi -Environment prod -AuthType Token

# Make a token-authenticated request
Invoke-APIRequest -Service myapi -Endpoint 'resources' -AuthType Token
```

---

## Functions

| Function | Description |
|----------|-------------|
| `Invoke-APIRequest` | Execute REST API calls against registered or ad-hoc services |
| `Register-CustomService` | Register a service BaseUrl in the persistent service registry |
| `Set-ServiceCredential` | Store Basic Auth, Token, or SSO credentials in global state — and, for Token always and for service+environment-specific Basic Auth, in the vault automatically |
| `Get-ServiceCredential` | Resolve authentication headers for a service (called internally) |
| `Get-ServiceConfig` | Resolve BaseUrl and merged headers for a service (called internally) |
| `Clear-ServiceCredential` | Remove stored credentials from global state and, for targeted Basic/Token clears, automatically from the vault |


---

## Examples

### Basic Auth

```powershell
# Register service and store credentials
Register-CustomService -ServiceName myapi -BaseUrl 'https://api.example.com/v1' -Persistent
Set-ServiceCredential -Service myapi -Environment prod -AuthType Basic

# GET request
Invoke-APIRequest -Service myapi -Endpoint 'users/me'

# POST request with body
$body = @{ fields = @{ summary = 'New item'; type = 'task' } }
Invoke-APIRequest -Service myapi -Endpoint 'items' -Method POST -Body $body
```

### Token Authentication

```powershell
# Store token credential in vault
Set-ServiceCredential -Service myapi -Environment prod -AuthType Token

# Token request — vault resolved automatically
Invoke-APIRequest -Service myapi -Endpoint 'resources' -AuthType Token

# Named vault label
Set-ServiceCredential -Service myapi -Environment prod -AuthType Token -Label readonly
Invoke-APIRequest -Service myapi -Endpoint 'resources' -AuthType Token -Label readonly
```

### SSO Authentication

```powershell
# Register service with SSO provider
Register-CustomService -ServiceName mycloud -BaseUrl 'https://api.example.com' -SSOProvider GCloud -Persistent

# SSO request — token acquired and refreshed automatically
Invoke-APIRequest -Service mycloud -Endpoint 'projects' -AuthType SSO
```

Supported providers: `GCloud`, `AzureCLI`, `Aria`, `AriaOidc`. SSO tokens are cached in `$global:ServiceSSOTokens` with an expiry timestamp and refreshed automatically when within 5 minutes of expiry — never stored in the vault, regardless of provider.

#### Aria (VMware Aria Automation)

Unlike `GCloud`/`AzureCLI`, Aria is REST-native rather than CLI-based. It sources its underlying domain-account credential via `Get-ServiceCredential -AuthType Basic` under the service's own name with label `'ssoidentity'` (so that credential is itself vault-backed — the first SSO call for Aria can bootstrap it interactively if it isn't already stored), then performs a two-step exchange: a CSP refresh-token request, followed by an IaaS bearer-token request.

```powershell
# Register with Aria — SSODomain is optional on domain-joined systems (falls back to the
# joined domain automatically); set it explicitly on non-domain-joined machines
Register-CustomService -ServiceName aria -BaseUrl 'https://aria.example.com' -SSOProvider Aria -SSODomain 'CorpDomain' -Persistent

# Bootstraps the 'ssoidentity' Basic credential interactively on first use, then
# performs the CSP/IaaS token exchange. Subsequent calls reuse the cached bearer
# token until it needs refreshing.
Invoke-APIRequest -Service aria -Endpoint 'iaas/api/projects' -AuthType SSO
```

#### AriaOidc (Aria / VCF Automation via the portal's OIDC session)

For tenants where the `Aria` username/password exchange is rejected, `AriaOidc` reuses the portal's own browser login. The SPA keeps its tokens in memory only, so a small Violentmonkey userscript (the courier) forwards the SPA's own `/oidc/oauth2/token` response to a loopback listener started by `Invoke-AriaOidcLogin`. The listener binds to `127.0.0.1` only and accepts a single POST that carries the courier header, a matching origin, and both an access and a refresh token.

The first call opens the portal in the default browser. After that, the cached refresh token — opaque, non-rotating, valid for the browser session (about 8 hours) — is exchanged silently for a new bearer token whenever the cached one is within 5 minutes of expiry, and the browser is only opened again if that exchange is rejected. The refresh token is held in memory in `$global:ServiceSSOTokens` and is never stored in the vault. The browser path needs a person at the keyboard, so `AriaOidc` is not suitable for unattended automation.

```powershell
# SSOTenant is the tenant name shown after 'service=tenant:' in the portal login redirect.
# BaseUrl is the host root only — no /tenant/... suffix.
Register-CustomService -ServiceName aria-example -BaseUrl 'https://aria.example.com' -SSOProvider AriaOidc -SSOTenant 'my-tenant' -Persistent

# First call opens the portal; later calls refresh silently until the session ends.
Invoke-APIRequest -Service aria-example -Endpoint 'iaas/api/about' -AuthType SSO
```

The courier ships inside the module, so there is no separate file to obtain. The first time on a browser, the login prints an install URL (`http://127.0.0.1:47811/aria-oidc-courier.user.js`); the loopback listener serves the script, rendered for the registered host, and Violentmonkey offers to install it. Install it once, enable it, and reload the portal tab. The listener binds `127.0.0.1:47811` by default; do not run another listener on that port at the same time.

The refresh exchange adapts to the tenant. Aria v9 does not advertise unauthenticated clients, so `Invoke-AriaOidcRefresh` tries a ladder of call shapes (bare with `tm_ui`, bare, `client_id` in the body, Basic `client_id:`) and caches the one that works; the client id is read from the access token's `aud` claim. The bearer that `Invoke-APIRequest` sends is chosen by test: the OIDC access token when the IaaS API accepts it, otherwise the token `iaas/api/login` issues for the OIDC refresh token.

To see which call shapes and which bearer a tenant accepts (statuses only — no tokens are printed), run this after one successful SSO call:

```powershell
& (Get-Module ServiceAPI) { Invoke-AriaOidcProbe -Service aria-example }
```

### Certificate-Aware Transport

Every request the module makes is sent by the private `Invoke-ServiceApiHttpRequest`, which replaces `Invoke-RestMethod`. `Invoke-RestMethod` cannot accept a per-request certificate validation callback, so it cannot reach hosts whose certificate chain trips the .NET name-constraints false positive: a leaf certificate that carries IP-address names, issued by a CA whose permitted subtrees are DNS-only. An internal Aria CA produces this shape.

When the platform reports no certificate errors, the certificate is accepted unchanged. Otherwise the chain is rebuilt with the name check relaxed, and the following still apply:

- The chain must end in a trusted root. Intermediates that the server sent are used even when no local store holds them.
- The host name must match a DNS name or an IP address in the certificate, exactly or through a single left-most-label wildcard.
- Revocation is not checked, because CRL and OCSP endpoints are normally unreachable from a restricted network.

Output and errors match `Invoke-RestMethod`, so existing `catch` blocks continue to work. Only the scheme, host and path of a request are written to the verbose stream, because a `QueryParam` request carries credentials in its query string. On Windows PowerShell 5.1, a JSON response larger than about 2 MB cannot be parsed.

### SSO 403 Handling and Probe Endpoints

An HTTP 403 from Aria means authenticated but not authorised: the bearer is valid and the identity lacks permission. A 401 means the token is stale. A token refresh can fix a 401 and can never fix a 403, so an SSO request that receives a 403 is refreshed and retried once only when a refresh could change the outcome:

1. Guard 1 sends the current bearer to the service's probe endpoint. When the probe succeeds, the token is valid, the 403 is an authorisation denial, and the refresh is skipped.
2. Guard 2 compares the bearer before and after the refresh. When it is unchanged, the retry is skipped because it would repeat the 403.

When a guard cannot decide, the request falls back to refresh-and-retry. The probe endpoint is resolved in this order: the `-ProbeEndpoint` registered for the service, then the `AriaOidc` default `iaas/api/projects?$top=1`, then none (Guard 1 is skipped).

```powershell
# Register a service with an explicit probe endpoint (optional for AriaOidc, which has a default)
Register-CustomService -ServiceName aihc -BaseUrl 'https://<aria-host>' `
    -SSOProvider AriaOidc -SSOTenant '<tenant>' `
    -ProbeEndpoint 'iaas/api/projects?$top=1' -Persistent
```

A request that is forbidden for an identity without permission reports the original 403 and a warning that the bearer is valid. No token exchange or browser login occurs.

### Unauthenticated Service

```powershell
# Register a local service that requires no auth
Register-CustomService -ServiceName localservice -BaseUrl 'http://localhost:8080/api' -Persistent

# Request with no credential resolution
Invoke-APIRequest -Service localservice -Endpoint 'status' -AuthType None

# Ad-hoc request to a dynamic URI — no service registration required
Invoke-APIRequest -BaseUrl 'http://localhost:54235/session/abc123' -Endpoint 'keyboard' -Method Put -Body $effect -AuthType None
```

### Query Parameter Authentication

For services whose login endpoint expects credentials as query string parameters rather than an `Authorization` header (e.g. Synology DSM's `auth.cgi`). `AuthType QueryParam` reuses the full Basic Auth resolution chain internally (vault, four-tier in-memory fallback, interactive prompt) by recursing with `-AuthType Basic`, then decodes the result into a plain `UserName`/`Password` object rather than setting a header. Because it's vault-backed like Basic, it's also eligible for the 403 retry behaviour.

```powershell
Register-CustomService -ServiceName synology -BaseUrl 'http://192.168.1.254:7000/webapi' -Persistent

# {user} and {pass} placeholders in -Endpoint are substituted with the resolved,
# URL-encoded credential — no Authorization header is sent
Invoke-APIRequest -Service synology -AuthType QueryParam `
    -Endpoint 'auth.cgi?api=SYNO.API.Auth&version=3&method=login&account={user}&passwd={pass}&session=ServiceAPI&format=sid'
```

### Custom Service Registration

```powershell
# Persistent — survives module reload
Register-CustomService -ServiceName myapi -BaseUrl 'https://api.example.com/v1' -Environment prod -Persistent

# Session only — not written to services.json
Register-CustomService -ServiceName tempapi -BaseUrl 'https://temp.example.com' -Environment prod

# Multiple environments
Register-CustomService -ServiceName myapi -BaseUrl 'https://api.example.com/v1' -Environment prod -Persistent
Register-CustomService -ServiceName myapi -BaseUrl 'https://qa.example.com/v1' -Environment qa -Persistent
Invoke-APIRequest -Service myapi -Endpoint 'users' -Environment qa
```

### Session-Only Credentials

```powershell
# Credential stored in memory only — not written to vault
Set-ServiceCredential -Service myapi -Environment prod -AuthType Basic -SessionOnly
Invoke-APIRequest -Service myapi -Endpoint 'users/me' -AuthType Basic -SessionOnly
```

> **Note**: `-SessionOnly` on `Set-ServiceCredential` currently only affects `Invoke-APIRequest`/`Get-ServiceCredential`'s *read* path (bypassing vault lookup on resolution). `Set-ServiceCredential` itself does not yet accept `-SessionOnly` — service+environment-specific Basic Auth and all Token storage are written to the vault unconditionally when SecretManagement is available. Use `-Global`, `-Service`-only, or `-Environment`-only storage modes if you need credentials that never touch the vault.

### Clearing Credentials (Basic/Token — vault included automatically)

```powershell
# Clears the in-memory credential for jira-prod AND the matching vault entry
# (jira-default-prod), since v2.6.0 of Clear-ServiceCredential
Clear-ServiceCredential -Service jira -Environment prod -AuthType Basic -Force

# Clear a specific labelled credential — -Label defaults to 'default'
Clear-ServiceCredential -Service jira -Environment prod -AuthType Token -Label readonly -Force

# Global/service-global/environment-wide Basic Auth credentials are in-memory only —
# there is no corresponding vault key, so -Global clearing never touches the vault
Clear-ServiceCredential -Global -AuthType Basic -Force
```


---

## Explicit Header Authentication

Callers can bypass service registration and stored credentials by supplying:

- `BaseUrl`
- `Headers` containing `Authorization`
- `Endpoint`

In this mode, no service registration is required, no credential lookup is performed, and the supplied Authorization header is honoured as authoritative. Standard headers are still used as a base and caller headers are layered on top.

```powershell
$headers = @{ Authorization = "Bearer $token" }
Invoke-APIRequest -BaseUrl 'https://api.example.com/v1' -Headers $headers -Endpoint 'resources'
```

---

## Config-Driven Header Precedence

When requests use registered service configuration, headers are resolved in this order:

1. `New-StandardHeaders`
2. Registered `DefaultHeaders`
3. Credential-derived headers — only when `Authorization` is not already supplied by `DefaultHeaders`
4. `-Headers` passed to `Invoke-APIRequest` — final override layer

If registered `DefaultHeaders` already provides a non-empty `Authorization` header, `Get-ServiceConfig` skips credential lookup and returns the merged headers as-is.

---

## Credential Fallback

For Basic Auth, credentials are resolved in a 6-tier order:

1. `$global:ServiceCredentials["service-env"]`
2. `$global:ServiceCredentials["service"]`
3. `$global:ServiceCredentials["*-env"]`
4. `$global:ServiceCredentials["*"]`
5. Vault lookup via `Resolve-VaultCredential` (requires `Microsoft.PowerShell.SecretManagement`)
6. Interactive `Get-Credential` prompt

For Token Auth, resolution order is:

1. `$global:ServiceTokens["service-env"]` (label-matched)
2. Vault lookup via `Resolve-VaultCredential`
3. Interactive prompt

For SSO, a cached token is returned if valid. If expired or absent, `Invoke-SSOProviderToken` acquires a new token from the registered provider (`GCloud`, `AzureCLI`, or `Aria`). For `Aria`, refresh additionally resolves the underlying domain-account credential via a nested `Get-ServiceCredential -AuthType Basic -Label ssoidentity` call and the domain via registry `SSODomain` or the local domain-joined system. `AriaOidc` is acquired by `Invoke-AriaOidcLogin` instead (through `Set-ServiceCredential`), which exchanges the cached refresh token or opens a browser login.

`QueryParam` reuses the Basic Auth resolution chain above in full (recursing internally with `-AuthType Basic`), then decodes the resolved credential into a plain `UserName`/`Password` object instead of building a header — see [Query Parameter Authentication](#query-parameter-authentication).

Handled errors use `Debug-Error` when `SysCommon` is available. If `SysCommon` is unavailable, ServiceAPI falls back to native PowerShell error output. `-Silent` suppresses handled-error output while rethrowing exceptions to the caller.

---

## Vault Integration

ServiceAPI integrates with `Microsoft.PowerShell.SecretManagement` for persistent credential storage across sessions. Vault support is optional — the module degrades gracefully when the module is absent.

**Since v2.7.0 (`Set-ServiceCredential`) / v2.6.0 (`Clear-ServiceCredential`), vault sync is automatic and symmetric for the storage modes that map to a valid vault key:**

- `Set-ServiceCredential -Service <svc> -Environment <env> -AuthType Basic` writes to `$global:ServiceCredentials` **and** the vault, as `<svc>-<label>-<env>` (label defaults to `'default'`).
- `Set-ServiceCredential -AuthType Token` has always written to both — unchanged.
- `Clear-ServiceCredential -Service <svc> -Environment <env> -AuthType Basic|Token` removes the matching in-memory entry **and** the vault secret + its `credential-index.json` entry, for the label given by `-Label` (defaults `'default'`).
- **Global, service-global, and environment-wide Basic Auth storage** (`-Global`, `-Service` only, or `-Environment` only) remain **session-only** on both `Set-ServiceCredential` and `Clear-ServiceCredential` — the vault's `{service}-{label}-{environment}` naming convention has no valid key for these modes, and `Get-ServiceCredential`'s vault resolution path only ever looks up an exact `service`+`environment` pair.
- `SSO` credentials are never vault-stored by either function — unchanged.
- The vault write/removal is wrapped in try/catch and only ever downgrades to a warning — a vault failure (e.g. the vault is unavailable) never blocks the in-memory operation from completing.
- If `SecretStore` is locked when a vault write/remove fires, `Set-Secret`/`Remove-Secret` triggers the native OS-level password prompt automatically (standard `Microsoft.PowerShell.SecretStore` behaviour with `Authentication Password`) — no extra code is needed in ServiceAPI for this.

```powershell
# Register a vault (first time only)
Register-SecretVault -Name 'LocalStore' -ModuleName 'Microsoft.PowerShell.SecretStore' -DefaultVault
Set-SecretStoreConfiguration -Scope CurrentUser -Authentication Password -PasswordTimeout 3600

# Store credentials — written to vault automatically
Set-ServiceCredential -Service myapi -Environment prod -AuthType Basic
Set-ServiceCredential -Service myapi -Environment prod -AuthType Token

# Clear a credential — removed from memory AND vault automatically
Clear-ServiceCredential -Service myapi -Environment prod -AuthType Token -Force

# Verify vault contents
Get-SecretInfo | Format-Table Name, Type, VaultName
Get-Content "$env:LOCALAPPDATA\ServiceAPI\credential-index.json"
```

Vault labels are tracked in a machine-local `credential-index.json` at `$env:LOCALAPPDATA\ServiceAPI\`. This index is never committed to source control. `Clear-ServiceCredential` keeps it in sync via the new `Remove-VaultIndex` private function (mirrors `Write-VaultIndex`).

### SecretStore limitation and multiple vaults

`Microsoft.PowerShell.SecretStore` is one store per Windows user. Its documentation states that scope `AllUsers` is not supported, and registering several SecretStore vaults under different names does not create separate stores: every registration shares the same secrets and the same lock configuration. A locked vault for sensitive credentials and an unlocked vault for automation therefore cannot both be SecretStore. Vault registrations are also per user and per machine.

ServiceAPI v2.9.0 reads and writes only a vault registered with the name `LocalStore`.

**Planned (not available in v2.9.0):** support for more than one vault, using another SecretManagement extension (`SecretManagement.KeePass` has been tested on Windows) alongside or instead of SecretStore. The intended design is a saved default vault, a `-Vault` parameter to override it, and the vault name recorded per label in `credential-index.json`. A suggested separation uses generic vault names by capability:

| Vault name | Suggested contents |
|---|---|
| `automation` | Credentials used by unattended scripts, unlocked for non-interactive use |
| `local-systems` | Credentials for systems on the local network |
| `online-accounts` | Credentials for internet-facing accounts and APIs |

Sharing credentials between users (export and import) is a separate follow-up and is not part of this design.


---

## Module Structure

```text
ServiceAPI/
├── ServiceAPI.psm1
├── ServiceAPI.psd1
├── docs/
│   └── Rehydration.md
└── functions/
    ├── Private/
    │   ├── ConvertFromJwtPayload.ps1
    │   ├── ConvertSecureStringToPlainText.ps1
    │   ├── ConvertVaultSecretToCredential.ps1
    │   ├── GetAriaCourierScript.ps1
    │   ├── GetServiceProbeEndpoint.ps1
    │   ├── InitializeServiceConfig.ps1
    │   ├── InitializeVaultIndex.ps1
    │   ├── InvokeAriaOidcLogin.ps1
    │   ├── InvokeAriaOidcProbe.ps1
    │   ├── InvokeAriaOidcRefresh.ps1
    │   ├── InvokeCredentialPrompt.ps1
    │   ├── InvokeServiceApiHttpRequest.ps1
    │   ├── InvokeServiceSsoRetry.ps1
    │   ├── InvokeSSOProviderToken.ps1
    │   ├── NewServiceKey.ps1
    │   ├── NewStandardHeaders.ps1
    │   ├── ReadServiceConfig.ps1
    │   ├── ReadVaultIndex.ps1
    │   ├── RemoveVaultIndex.ps1
    │   ├── ResolveVaultCredential.ps1
    │   ├── TestIsTokenValue.ps1
    │   ├── TestServiceBearer.ps1
    │   ├── WaitAriaCourierToken.ps1
    │   ├── WriteServiceApiHandledError.ps1
    │   ├── WriteServiceConfig.ps1
    │   └── WriteVaultIndex.ps1
    └── Public/
        ├── ClearServiceCredential.ps1
        ├── GetServiceConfig.ps1
        ├── GetServiceCredential.ps1
        ├── InvokeAPIRequest.ps1
        ├── RegisterCustomService.ps1
        └── SetServiceCredential.ps1
```

User data files are stored outside the module directory and are never committed to source control:

| File | Location | Purpose |
|------|----------|---------|
| `services.json` | `$env:APPDATA\ServiceAPI\` | Persistent service registry — BaseUrl, SSOProvider, SSODomain, SSOTenant and ProbeEndpoint per service/environment |
| `credential-index.json` | `$env:LOCALAPPDATA\ServiceAPI\` | Machine-local vault label index — tracks which named credentials exist per service key |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 2.10.0 | 06Oct26 | Consolidates the v2.9.1 to v2.9.3 work and extends it. New private Invoke-ServiceApiHttpRequest replaces every Invoke-RestMethod call (certificate-aware transport, wildcard and IP-address name matching, shared client). SSO requests that receive HTTP 403 refresh and retry once through Invoke-ServiceSsoRetry, guarded by a bearer probe and a token-change check. New -ProbeEndpoint parameter on Register-CustomService (2.6.0), persisted via Write-ServiceConfig and Read-ServiceConfig (1.4.0) and forwarded by the Phase 5 load. Shared Test-ServiceBearer and Get-ServiceProbeEndpoint. Invoke-APIRequest 2.8.0, Set-ServiceCredential 2.8.1, Invoke-SSOProviderToken 1.3.0, Resolve-VaultCredential 1.2.1, Invoke-AriaOidcLogin 1.3.0. Every PowerShell file that contains non-ASCII characters now carries a UTF-8 BOM, so the module loads on Windows PowerShell 5.1. |
| 2.9.0 | 01Oct26 | Added AriaOidc as a supported -SSOProvider for Aria / VCF Automation tenants. Authenticates through the portal's own OIDC browser session: new private functions Invoke-AriaOidcLogin, Invoke-AriaOidcRefresh, Get-AriaCourierScript, Wait-AriaCourierToken and ConvertFrom-JwtPayload, plus an Invoke-AriaOidcProbe diagnostic. The courier userscript is a template inside the module, served by the loopback listener for a one-time install. Invoke-AriaOidcLogin exchanges a cached refresh token silently (trying a ladder of call shapes and caching the one that works) or, when the session has ended, opens the portal in the default browser and receives the SPA's token response from the Violentmonkey courier userscript on a loopback listener (127.0.0.1 only). The refresh token is held in memory in $global:ServiceSSOTokens and never stored in the vault. Set-ServiceCredential (2.8.0) owns the AriaOidc refresh cycle and Get-ServiceCredential (2.7.0) delegates to it when stale. New -SSOTenant parameter on Register-CustomService (2.5.0), persisted via Write-ServiceConfig (1.3.0) / Read-ServiceConfig (1.3.0). Fixed module load dropping a persisted SSODomain — Phase 5 now forwards both SSODomain and SSOTenant to Register-CustomService. |
| 2.8.0 | 17Aug26 | Set-ServiceCredential (2.7.0) and Clear-ServiceCredential (2.6.0) now keep the vault in sync automatically for service+environment-specific Basic Auth and all Token credentials — Set writes to the vault, Clear removes from it (Remove-Secret + new Remove-VaultIndex private function). Added -Label to Clear-ServiceCredential (defaults 'default') so the correct vault entry is targeted. Global/service-global/environment-wide Basic Auth storage remains session-only, as does SSO — neither has a valid vault key. Fixes a gap where Clear-ServiceCredential only ever cleared in-memory state, allowing Get-ServiceCredential to silently re-resolve a "cleared" credential from the vault. |
| 2.7.0 | 12Aug26 | Added Aria (VMware Aria Automation) as a supported -SSOProvider. REST-native two-step CSP refresh-token / IaaS bearer-token exchange in Invoke-SSOProviderToken — no CLI tool required, unlike GCloud/AzureCLI. Sources its underlying domain-account credential via Get-ServiceCredential -AuthType Basic (label 'ssoidentity'), so the first SSO call for Aria can bootstrap that credential interactively. Domain resolves from a new -SSODomain parameter on Register-CustomService (persisted through Write-ServiceConfig/Read-ServiceConfig), falling back to a domain-joined system's own domain when omitted. |
| 2.6.0 | 31Jul26 | Added QueryParam to -AuthType across Invoke-APIRequest and Get-ServiceCredential, for services (e.g. Synology DSM) whose login endpoint expects credentials as query string parameters rather than an Authorization header. Recurses internally via -AuthType Basic to reuse the full vault/fallback/prompt chain, then decodes the result into a UserName/Password object substituted into {user}/{pass} endpoint placeholders. Vault-backed, so eligible for 403 retry like Basic. Extracted Convert-VaultSecretToCredential from Resolve-VaultCredential to remove duplicated PSCredential normalisation logic between the single-label and multi-label vault lookup paths. |
| 2.5.5 | 28May26 | Removed default service seed from Initialise-ServiceConfig. services.json now initialises as empty registry on first load. All services must be registered explicitly via Register-CustomService -Persistent. |
| 2.5.4 | 17May26 | Fixed Basic Auth vault write in Set-ServiceCredential — credentials now persisted to vault in all Basic paths, not only the Token path. |
| 2.5.3 | 17May26 | Fixed Token vault write in Set-ServiceCredential — token credentials now persisted to vault correctly between sessions. |
| 2.5.2 | 17May26 | Added direct BaseUrl + AuthType None execution path in Invoke-APIRequest. Unauthenticated requests to dynamic or ad-hoc URIs no longer require a registered service or Authorization header. |
| 2.5.1 | 17May26 | Added None to -AuthType ValidateSet across Invoke-APIRequest and Get-ServiceConfig. AuthType None skips all credential resolution — suitable for unauthenticated local services and listeners. |
| 2.5.0 | 17May26 | Replaced -UseToken and -UseSSO switches with unified -AuthType [ValidateSet('Basic','Token','SSO','None')] parameter across all public functions. Added -Label parameter for named vault credential retrieval. Auth mode selection is now explicit and tab-completed. |
| 2.4.4 | 17May26 | Added -SessionOnly and -Endpoint pass-through to Get-ServiceCredential from Get-ServiceConfig. |
| 2.4.3 | 17May26 | Australian/British English spelling applied throughout all functions and documentation. |
| 2.4.2 | 17May26 | Changed -UseSSO to [switch] with provider resolved automatically from service registry. Fixed Bearer vs Basic Auth determination by key presence in stored credential. PowerShell 7 compatibility fixes for -UseToken and -UseSSO parameters. |
| 2.4.1 | 17May26 | Fixed SecretManagement detection to use Get-Module -ListAvailable with explicit import. Fixed -UseToken and -UseSSO [string] default handling. |
| 2.4.0 | 17May26 | Added SecretManagement vault integration for token credential resolution. Vault index initialised on module load when SecretManagement is available. |
| 2.3.0 | 16May26 | Added persistent service registry via services.json. Services survive module reload without re-registration. Added ArgumentCompleter on -Service across all public functions for tab completion from live registry. |
| 2.2.0 | 16May26 | Added SSO OAuth support via -UseSSO parameter. Implemented Invoke-SSOProviderToken for GCloud and AzureCLI providers. |
| 2.1.1 | 28Mar26 | Restored Debug-Error based handled-error reporting with graceful fallback when SysCommon is unavailable. Added centralised Write-ServiceApiHandledError private function. |
| 2.1.0 | 28Mar26 | Added explicit Authorization header override support in Invoke-APIRequest. Updated Get-ServiceConfig to honour registered DefaultHeaders and skip credential lookup when Authorization is already supplied. |
| 2.0.0 | 28Jan26 | Renamed from AtlassianAPI. Refactored to use Get-ServiceConfig and Get-ServiceCredential. Fixed GET Content-Type issue. Universal service support. |
