# ServiceAPI

**Version**: 2.5.2  
**Author**: Matthew Sillett  
**Organisation**: Australian Signals Directorate

---

## Overview

ServiceAPI is a PowerShell REST API framework supporting Basic Auth and Token authentication with a service registry pattern for managing multiple API endpoints.

---

## Installation

```powershell
Import-Module ServiceAPI
```

---

## Quick Start

```powershell
# Set credentials for a service
Set-ServiceCredential -Service opnsense -Environment prod

# Make API request
Invoke-APIRequest -Service opnsense -Endpoint 'core/firmware/status'

# Register custom service
Register-CustomService -ServiceName myapi -BaseUrl 'https://api.example.com'
```

---

## Functions

| Function | Description |
|----------|-------------|
| `Set-ServiceCredential` | Store Basic Auth credentials or tokens |
| `Get-ServiceCredential` | Retrieve authentication headers |
| `Clear-ServiceCredential` | Remove stored credentials |
| `Get-ServiceConfig` | Get service configuration (BaseUrl + headers) |
| `Invoke-APIRequest` | Execute REST API calls |
| `Register-CustomService` | Add custom API services |

---

## Predefined Services

- **OPNsense** (PROD)
- **Cloudflare** (PROD)
- **Google** (PROD — SSO via GCloud)
- **Razer Chroma** (PROD — AuthType None, localhost)

---

## Examples

### Basic Usage
```powershell
# Set credential for service
Set-ServiceCredential -Service jira -Environment prod

# GET request
Invoke-APIRequest -Service jira -Endpoint 'api/2/myself'

# POST request with body
$body = @{ fields = @{ summary = "New issue" } }
Invoke-APIRequest -Service jira -Endpoint 'api/2/issue' -Method POST -Body $body
```

### Custom Service
```powershell
# Register custom API
Register-CustomService -ServiceName github -BaseUrl 'https://api.github.com' -Environment prod

# Use it
Set-ServiceCredential -Service github
Invoke-APIRequest -Service github -Endpoint 'users/octocat'
```

### Token Authentication
```powershell
# Set token from SecureString
$token = Read-Host "Enter API Token" -AsSecureString
Set-ServiceCredential -Service jira -Environment prod -Token $token

# Set token from plain string
Set-ServiceCredential -Service cloudflare -Environment prod -Token 'cfat_xxxxx'

# Set token from a Bearer-prefixed string
Set-ServiceCredential -Service cloudflare -Environment prod -Token 'Bearer cfat_xxxxx'

# Use token-only credential resolution
Invoke-APIRequest -Service cloudflare -Environment prod -Endpoint 'zones?name=smashnet.win' -UseToken
```

---

## Explicit Header Authentication

Callers can bypass service registration and stored credentials by supplying:

- `BaseUrl`
- `Headers` containing `Authorization`
- `Endpoint`

In this mode, no service registration is required, no credential lookup is performed, and the supplied Authorization header is honored as authoritative. Standard headers are still used as a base and caller headers are layered on top.

```powershell
$headers = New-ModifiedHeader -BaseHeaders (New-StandardHeaders) -Override @{
    Authorization = "Bearer $token"
}

Invoke-APIRequest -BaseUrl 'https://api.cloudflare.com/client/v4/' -Headers $headers -Endpoint 'zones?name=smashnet.win'
```

---

## Config-Driven Header Precedence

When requests use registered service configuration, headers are resolved in this order:

1. `New-StandardHeaders`
2. registered `DefaultHeaders`
3. credential-derived headers only when `Authorization` is not already supplied by `DefaultHeaders`
4. `Invoke-APIRequest -Headers` remains the final override layer

If registered `DefaultHeaders` already provides a non-empty `Authorization` header, `Get-ServiceConfig` skips credential lookup and returns the merged headers as-is.

---

## Credential Fallback

4-tier credential resolution:
1. Service-Environment (e.g., `jira-prod`)
2. Service-Global (e.g., `jira-global`)
3. Environment-Wide (any service in `prod`)
4. Global Fallback

Handled errors use `Debug-Error` when `SysCommon` is available. If `SysCommon` is unavailable,
ServiceAPI falls back to basic local PowerShell error output. `Invoke-APIRequest -Silent` still
suppresses handled-error output while rethrowing exceptions to the caller.

---

## Module Structure

```
ServiceAPI/
├── ServiceAPI.psm1
├── ServiceAPI.psd1
└── functions/
    ├── Private/    # 4 helpers
    └── Public/     # 6 functions
```

---

## Version History

| Version | Date    | Changes |
|---------|---------|---------|
| 2.5.2   | 17MAY26 | Added direct BaseUrl + AuthType None execution path in Invoke-APIRequest. Unauthenticated requests to dynamic or ad-hoc URIs no longer require a registered service or Authorization header. Updated Service-required error message accordingly. |
| 2.5.1   | 17MAY26 | Added 'None' to -AuthType ValidateSet across Invoke-APIRequest and Get-ServiceConfig. AuthType None skips all credential resolution — suitable for unauthenticated local services and listeners. $useTokenOrSSO guard updated to include None, preventing 403 retry on unauthenticated calls. |
| 2.5.0   | 17MAY26 | Replaced -UseToken and -UseSSO switches with unified -AuthType [ValidateSet('Basic','Token','SSO')] parameter across all public functions. Added -Label parameter for named vault credential retrieval. Auth mode selection is now explicit and tab-completed. 403 retry block updated to check AuthType. Razer Chroma registered as prod service. |
| 2.4.4   | 17MAY26 | Added -SessionOnly and -Endpoint pass-through to Get-ServiceCredential from Get-ServiceConfig. |
| 2.4.3   | 17MAY26 | Australian/British English spelling applied throughout all functions and documentation. |
| 2.4.0   | 17MAY26 | Added SSO credential resolution pass-through in Get-ServiceConfig and Get-ServiceCredential. |
| 2.3.0   | 16MAY26 | Added [ArgumentCompleter] on -Service across public functions for tab completion from live registry. Added inline unregistered service registration prompt in Invoke-APIRequest. |
| 2.2.0   | 16MAY26 | Added -UseSSO parameter. Changed -UseToken from [switch] to [string]. Explicit auth override mode guarded against -UseToken and -UseSSO. |
| 2.1.1   | 28MAR26 | Restored Debug-Error based handled-error reporting with graceful fallback when SysCommon is unavailable. Added centralised Write-ServiceApiHandledError private function. Preserved -Silent behaviour. |
| 2.1.0   | 28MAR26 | Added explicit Authorization header override support in Invoke-APIRequest. Updated Get-ServiceConfig to honour registered DefaultHeaders and skip credential lookup when Authorization is already supplied. |
| 2.0.0   | 27JAN26 | Renamed from AtlassianAPI. Refactored to use Get-ServiceConfig and Get-ServiceCredential. Fixed GET Content-Type issue. |
