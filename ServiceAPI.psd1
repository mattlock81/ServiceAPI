@{
    RootModule        = 'ServiceAPI.psm1'
    ModuleVersion     = '2.3.0'
    GUID              = 'a1b2c3d4-e5f6-47a8-b9c0-d1e2f3a4b5c6'
    Author            = 'Matthew Sillett'
    CompanyName       = 'Australian Signals Directorate'
    Copyright         = '© 2026 Matthew Sillett. All rights reserved.'
    Description       = 'REST API framework for PowerShell supporting Basic Auth, static Bearer token, and OAuth SSO authentication. Predefined support for Atlassian Data Center, OPNsense, and Google Workspace APIs. Service registry is driven by a persistent config\services.json file with auto-creation on first load.'
    PowerShellVersion = '5.1'

    FunctionsToExport = '*'
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags = @('API', 'REST', 'Atlassian', 'Jira', 'Confluence', 'OPNsense', 'Google', 'OAuth', 'SSO', 'DevOps', 'Automation')
            ReleaseNotes = @'
2.3.0 | 16MAY26 | Introduced persistent service registry via config\services.json. File is
                  auto-created and seeded with default services on first module load. All
                  hardcoded service definitions removed from ServiceAPI.psm1. Register-CustomService
                  extended with -Persistent switch to write registrations to services.json.
                  Persistent registrations include BaseUrl and SSOProvider where set. Three new
                  private functions added: Initialize-ServiceConfig, Read-ServiceConfig,
                  Write-ServiceConfig. ArgumentCompleter added to -Service parameter across all
                  public functions for live tab completion from the runtime registry. ArgumentCompleter
                  added to -UseSSO in Invoke-APIRequest surfacing known providers with service default
                  first. Inline unregistered service registration prompt added to Invoke-APIRequest
                  with session/permanent choice and SSO provider inference from call parameters.
2.2.0 | 16MAY26 | Added SSO authentication support via -UseSSO across all functions. SSO tokens
                  stored in $global:ServiceSSOTokens with expiry metadata and automatic lazy refresh.
                  Register-CustomService extended with -SSOProvider. -UseToken changed from [switch]
                  to [string] across all functions. Added private Invoke-SSOProviderToken helper.
                  Explicit auth override mode guarded against -UseToken and -UseSSO. 403 retry
                  extended to exclude SSO and token requests.
2.1.1 | 28MAR26 | Restored Debug-Error based handled-error reporting with graceful fallback when
                  SysCommon is unavailable. Added centralised Write-ServiceApiHandledError helper.
2.1.0 | 28MAR26 | Added explicit Authorization header override support in Invoke-APIRequest.
                  Enforced token-only credential resolution for -UseToken. Updated Set-ServiceCredential
                  to accept plain string or SecureString tokens.
2.0.0 | 27JAN26 | Complete module rename to ServiceAPI. Removed backward compatibility aliases.
                  Fixed Content-Type header for GET requests. Fixed credential prompting logic.
'@
        }
    }
}
