# ServiceAPI

**Version**: 2.1.0  
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

- **Jira** (QA/PROD)
- **Confluence** (QA/PROD)
- **Bitbucket** (QA/PROD)
- **Crowd** (QA/PROD)
- **Assets** (QA/PROD)
- **OPNsense** (PROD)

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

In this mode, no service registration is required, no credential lookup is performed, and the supplied Authorization header is honored as authoritative.

```powershell
$headers = New-ModifiedHeader -BaseHeaders (New-StandardHeaders) -Override @{
    Authorization = "Bearer $token"
}

Invoke-APIRequest -BaseUrl 'https://api.cloudflare.com/client/v4/' -Headers $headers -Endpoint 'zones?name=smashnet.win'
```

---

## Credential Fallback

4-tier credential resolution:
1. Service-Environment (e.g., `jira-prod`)
2. Service-Global (e.g., `jira-global`)
3. Environment-Wide (any service in `prod`)
4. Global Fallback

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
| 2.1.0   | 28MAR26 | Added explicit Authorization header override support in Invoke-APIRequest. Enforced token-only credential resolution when UseToken is specified. Updated Set-ServiceCredential to accept plain string or SecureString tokens and normalize Bearer-prefixed input. |
| 2.0.0   | 27JAN26 | Renamed from AtlassianAPI. Fixed GET Content-Type issue. Streamlined. |
