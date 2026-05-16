@{
    RootModule        = 'ServiceAPI.psm1'
    ModuleVersion     = '2.2.0'
    GUID              = 'a1b2c3d4-e5f6-47a8-b9c0-d1e2f3a4b5c6'
    Author            = 'Matthew Sillett'
    CompanyName       = 'Australian Signals Directorate'
    Copyright         = '© 2026 Matthew Sillett. All rights reserved.'
    Description       = 'REST API framework for PowerShell supporting Basic Auth, static Bearer token, and OAuth SSO authentication. Predefined support for Atlassian Data Center, OPNsense, and Google Workspace APIs.'
    PowerShellVersion = '5.1'

    FunctionsToExport = '*'
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags = @('API', 'REST', 'Atlassian', 'Jira', 'Confluence', 'OPNsense', 'Google', 'OAuth', 'SSO', 'DevOps', 'Automation')
            ReleaseNotes = @'
2.2.0 | 16MAY26 | Added SSO authentication support via -UseSSO parameter across Invoke-APIRequest,
                  Get-ServiceConfig, Get-ServiceCredential, Set-ServiceCredential, and Clear-ServiceCredential.
                  SSO tokens are short-lived OAuth Bearer tokens obtained via provider dispatch (GCloud, AzureCLI)
                  and stored in $global:ServiceSSOTokens with expiry metadata and automatic lazy refresh.
                  Register-CustomService extended with -SSOProvider to associate a default provider with a
                  service registration. -UseToken changed from [switch] to [string] across all functions to
                  support optional inline token value with interactive prompt fallback. Added private
                  Invoke-SSOProviderToken helper for centralised provider dispatch. Explicit auth override
                  mode in Invoke-APIRequest now guarded against -UseToken and -UseSSO to prevent silent
                  credential bypass. 403 retry extended to exclude SSO and token requests.
2.1.1 | 28MAR26 | Restored Debug-Error based handled-error reporting with graceful fallback when SysCommon
                  is unavailable. Added centralized Write-ServiceApiHandledError helper. Preserved Silent
                  behavior while suppressing handled-error output.
2.1.0 | 28MAR26 | Added explicit Authorization header override support in Invoke-APIRequest. Enforced
                  token-only credential resolution for -UseToken. Updated Set-ServiceCredential to accept
                  plain string or SecureString tokens. Updated Get-ServiceConfig to honor registered
                  DefaultHeaders and skip credential lookup when Authorization is already supplied.
2.0.0 | 27JAN26 | Complete module rename to ServiceAPI. Removed backward compatibility aliases.
                  Fixed Content-Type header for GET requests. Fixed credential prompting logic.
'@
        }
    }
}
