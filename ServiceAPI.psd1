@{
    RootModule        = 'ServiceAPI.psm1'
    ModuleVersion     = '2.5.0'
    GUID              = 'a1b2c3d4-e5f6-47a8-b9c0-d1e2f3a4b5c6'
    Author            = 'Matthew Sillett'
    CompanyName       = 'Australian Signals Directorate'
    Copyright         = '© 2026 Matthew Sillett. All rights reserved.'
    Description       = 'REST API framework for PowerShell supporting Basic Auth, static Bearer token, OAuth SSO, and SecretManagement vault-integrated credential resolution. Predefined support for Atlassian Data Center, OPNsense, and Google Workspace APIs. User configuration stored in AppData and LocalAppData — module updates never overwrite user data.'
    PowerShellVersion = '5.1'

    FunctionsToExport = '*'
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags = @('API', 'REST', 'Atlassian', 'Jira', 'Confluence', 'OPNsense', 'Google', 'OAuth', 'SSO', 'SecretManagement', 'Vault', 'DevOps', 'Automation')
            ReleaseNotes = @'
2.5.0 | 17MAY26 | Unified authentication model — replaced -UseToken and -UseSSO parameters
                  with -AuthType [ValidateSet('Basic','Token','SSO')] across all public
                  functions. Added -Label parameter for named vault credential retrieval,
                  defaulting to 'default'. Auth mode selection is now explicit, tab-completed,
                  and unambiguous. -SessionOnly retained as a modifier for Basic and Token.
                  Moved user configuration out of module directory — services.json to
                  $env:APPDATA\ServiceAPI\, credential-index.json to $env:LOCALAPPDATA\ServiceAPI\.
                  Module updates no longer overwrite user data.
2.4.4 | 17MAY26 | Extended SecretManagement vault integration to Basic Auth. Resolve-VaultCredential
                  extended with -AuthType parameter (Token/Basic). Basic Auth path stores and
                  retrieves PSCredential objects natively. Get-ServiceCredential Priority 2 now
                  attempts vault resolution before the four-tier in-memory fallback when vault
                  is available and -SessionOnly is not set.
2.4.3 | 17MAY26 | British/Australian English spelling applied throughout. Initialize renamed
                  to Initialise in private function names (Initialise-ServiceConfig,
                  Initialise-VaultIndex) and all call sites. American spellings corrected
                  in all inline comments, help text, and changelog entries across all files.
                  Authorization retained in HTTP header references as a proper noun.
2.4.2 | 17MAY26 | Bearer vs Basic Auth determined by key presence in stored vault credential.
                  Test call in Resolve-VaultCredential also uses correct header type.
2.4.1 | 17MAY26 | Fixed -UseToken and -UseSSO parameter types from [object] to [string] with
                  appropriate defaults for PowerShell 7 compatibility. -UseToken defaults to
                  'default' (vault label). -UseSSO defaults to empty string. SecretManagement
                  detection updated to use Get-Module -ListAvailable and explicit Import-Module,
                  mirroring SysCommon detection pattern.
2.4.0 | 17MAY26 | Added optional SecretManagement vault integration. Detected automatically at
                  module import — all vault logic is bypassed silently when the module is absent.
                  When detected, token-mode (-UseToken) requests resolve credentials from the vault
                  via Resolve-VaultCredential: label lookup, interactive prompt with test call
                  validation (2xx/401/403/other handling), and optional vault write-back with
                  credential-index.json tracking. Credentials stored as encoded "key:secret" strings
                  under the naming convention "{service}-{label}-{environment}". Label vs raw token
                  distinguished via Test-IsTokenValue heuristic (vault index match, known prefixes,
                  length, character set). -SessionOnly switch added to Invoke-APIRequest and
                  Get-ServiceCredential to bypass vault for session-only credentials. Four new private
                  functions: Initialise-VaultIndex, Read-VaultIndex, Write-VaultIndex,
                  Resolve-VaultCredential, Test-IsTokenValue. credential-index.json auto-created in
                  config\ on first vault-enabled load. $global:ServiceApiVaultIndex initialised in
                  Phase 4 and populated in Phase 4.5. Vault index added to Phase 6 cleanup.
2.3.0 | 16MAY26 | Introduced persistent service registry via config\services.json. File auto-created
                  and seeded with default services on first load. Hardcoded service definitions
                  removed from psm1. Register-CustomService extended with -Persistent switch.
                  ArgumentCompleter added to -Service across all public functions. ArgumentCompleter
                  added to -UseSSO in Invoke-APIRequest. Inline unregistered service registration
                  prompt added to Invoke-APIRequest.
2.2.0 | 16MAY26 | Added SSO authentication support via -UseSSO across all functions. SSO tokens
                  stored in $global:ServiceSSOTokens with expiry metadata and automatic lazy refresh.
                  Register-CustomService extended with -SSOProvider. -UseToken changed from [switch]
                  to [string] across all functions. Added private Invoke-SSOProviderToken helper.
2.1.1 | 28MAR26 | Restored Debug-Error based handled-error reporting with graceful fallback.
2.1.0 | 28MAR26 | Added explicit Authorization header override support in Invoke-APIRequest.
2.0.0 | 27JAN26 | Complete module rename to ServiceAPI. Removed backward compatibility aliases.
'@
        }
    }
}
