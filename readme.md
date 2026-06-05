# ServiceAPI

**Version**: 2.5.5  
**Author**: Matthew Sillett  
**Organisation**:

---

## Overview

ServiceAPI is a PowerShell module that provides a unified REST API framework for interacting with multiple services. It supports Basic Auth, Token, and SSO OAuth authentication via a persistent service registry pattern, with optional credential persistence through Microsoft SecretManagement vault integration.

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
| `Set-ServiceCredential` | Store Basic Auth, Token, or SSO credentials in global state and vault |
| `Get-ServiceCredential` | Resolve authentication headers for a service (called internally) |
| `Get-ServiceConfig` | Resolve BaseUrl and merged headers for a service (called internally) |
| `Clear-ServiceCredential` | Remove stored credentials from global state and optionally from vault |


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

### Unauthenticated Service

```powershell
# Register a local service that requires no auth
Register-CustomService -ServiceName localservice -BaseUrl 'http://localhost:8080/api' -Persistent

# Request with no credential resolution
Invoke-APIRequest -Service localservice -Endpoint 'status' -AuthType None

# Ad-hoc request to a dynamic URI — no service registration required
Invoke-APIRequest -BaseUrl 'http://localhost:54235/session/abc123' -Endpoint 'keyboard' -Method Put -Body $effect -AuthType None
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

For SSO, a cached token is returned if valid. If expired or absent, `Invoke-SSOProviderToken` acquires a new token from the registered provider (`GCloud` or `AzureCLI`).

Handled errors use `Debug-Error` when `SysCommon` is available. If `SysCommon` is unavailable, ServiceAPI falls back to native PowerShell error output. `-Silent` suppresses handled-error output while rethrowing exceptions to the caller.

---

## Vault Integration

ServiceAPI integrates with `Microsoft.PowerShell.SecretManagement` for persistent credential storage across sessions. Vault support is optional — the module degrades gracefully when the module is absent.

```powershell
# Register a vault (first time only)
Register-SecretVault -Name 'LocalStore' -ModuleName 'Microsoft.PowerShell.SecretStore' -DefaultVault
Set-SecretStoreConfiguration -Scope CurrentUser -Authentication Password -PasswordTimeout 3600

# Store credentials — written to vault automatically
Set-ServiceCredential -Service myapi -Environment prod -AuthType Basic
Set-ServiceCredential -Service myapi -Environment prod -AuthType Token

# Clear from vault
Clear-ServiceCredential -Service myapi -Environment prod -AuthType Token -FromVault

# Verify vault contents
Get-SecretInfo | Format-Table Name, Type, VaultName
Get-Content "$env:LOCALAPPDATA\ServiceAPI\credential-index.json"
```

Vault labels are tracked in a machine-local `credential-index.json` at `$env:LOCALAPPDATA\ServiceAPI\`. This index is never committed to source control.


---

## Module Structure

```text
ServiceAPI/
├── ServiceAPI.psm1
├── ServiceAPI.psd1
└── functions/
    ├── Private/
    │   ├── ConvertSecureStringToPlainText.ps1
    │   ├── InitializeServiceConfig.ps1
    │   ├── InitializeVaultIndex.ps1
    │   ├── InvokeCredentialPrompt.ps1
    │   ├── InvokeSSOProviderToken.ps1
    │   ├── NewServiceKey.ps1
    │   ├── NewStandardHeaders.ps1
    │   ├── ReadServiceConfig.ps1
    │   ├── ReadVaultIndex.ps1
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
