# ServiceAPI

**Version**: 2.8.0  
**Author**: Matthew Sillett  
**Organisation**:

---

## Overview

ServiceAPI is a PowerShell module that provides a unified REST API framework for interacting with multiple services. It supports Basic Auth, static Token, SSO OAuth, QueryParam (credential delivered via URL query string rather than a header), and None (unauthenticated) authentication modes via a persistent service registry pattern, with optional credential persistence through Microsoft SecretManagement vault integration.

SSO providers currently supported: `GCloud` (Google Cloud SDK), `AzureCLI` (Azure CLI), and `Aria` (VMware Aria Automation — REST-native, no CLI tool required).

Services are registered once with a BaseUrl and stored in a user-scoped `services.json` file. Credentials are resolved automatically from the vault, from in-memory global state, or via interactive prompt — in that order. All public functions share a unified `-AuthType` parameter with tab completion, and the `-Service` parameter tab-completes from the live registry.

ServiceAPI degrades gracefully when optional dependencies (`SysCommon`, `Microsoft.PowerShell.SecretManagement`) are absent.

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

Supported providers: `GCloud`, `AzureCLI`, `Aria`. SSO tokens are cached in `$global:ServiceSSOTokens` with an expiry timestamp and refreshed automatically when within 5 minutes of expiry — never stored in the vault, regardless of provider.

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

For SSO, a cached token is returned if valid. If expired or absent, `Invoke-SSOProviderToken` acquires a new token from the registered provider (`GCloud`, `AzureCLI`, or `Aria`). For `Aria`, refresh additionally resolves the underlying domain-account credential via a nested `Get-ServiceCredential -AuthType Basic -Label ssoidentity` call and the domain via registry `SSODomain` or the local domain-joined system.

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


---

## Module Structure

```text
ServiceAPI/
├── ServiceAPI.psm1
├── ServiceAPI.psd1
└── functions/
    ├── Private/
    │   ├── ConvertSecureStringToPlainText.ps1
    │   ├── ConvertVaultSecretToCredential.ps1
    │   ├── InitializeServiceConfig.ps1
    │   ├── InitializeVaultIndex.ps1
    │   ├── InvokeCredentialPrompt.ps1
    │   ├── InvokeSSOProviderToken.ps1
    │   ├── NewServiceKey.ps1
    │   ├── NewStandardHeaders.ps1
    │   ├── ReadServiceConfig.ps1
    │   ├── ReadVaultIndex.ps1
    │   ├── RemoveVaultIndex.ps1
    │   ├── ResolveVaultCredential.ps1
    │   ├── TestIsTokenValue.ps1
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
| `services.json` | `$env:APPDATA\ServiceAPI\` | Persistent service registry — BaseUrl and SSOProvider per service/environment |
| `credential-index.json` | `$env:LOCALAPPDATA\ServiceAPI\` | Machine-local vault label index — tracks which named credentials exist per service key |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
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
