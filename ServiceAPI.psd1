@{
    RootModule        = 'ServiceAPI.psm1'
    ModuleVersion     = '2.1.0'
    GUID              = 'a1b2c3d4-e5f6-47a8-b9c0-d1e2f3a4b5c6'
    Author            = 'Matthew Sillett'
    CompanyName       = 'Australian Signals Directorate'
    Copyright         = '© 2026 Matthew Sillett. All rights reserved.'
    Description       = 'REST API framework for PowerShell supporting Basic Auth and Token authentication. Predefined support for Atlassian Data Center and OPNsense.'
    PowerShellVersion = '5.1'
    
    FunctionsToExport = '*'
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    
    PrivateData = @{
        PSData = @{
            Tags = @('API', 'REST', 'Atlassian', 'Jira', 'Confluence', 'OPNsense', 'DevOps', 'Automation')
            ReleaseNotes = @'
2.1.0 | 28MAR26 | Added explicit Authorization header override support in Invoke-APIRequest. Enforced token-only credential resolution for -UseToken. Updated Set-ServiceCredential to accept plain string or SecureString tokens. Updated Get-ServiceConfig to honor registered DefaultHeaders and skip credential lookup when Authorization is already supplied.
2.0.0 | 27JAN26 | Complete module rename to ServiceAPI. Removed backward compatibility aliases. Fixed Content-Type header for GET requests. Fixed credential prompting logic.
'@
        }
    }
}
