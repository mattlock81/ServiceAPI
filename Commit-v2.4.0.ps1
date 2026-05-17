#Requires -Version 5.1
<#
.SYNOPSIS
    Commits and pushes ServiceAPI v2.4.0 changes to GitHub then removes itself.
.NOTES
    Author : Matthew Sillett
    Run from any PowerShell session on your home machine.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$git  = 'C:\Program Files\Git\bin\git.exe'
$repo = 'F:\Source\mattlock81\ServiceAPI'

Set-Location $repo

Write-Host 'Staging all changes...' -ForegroundColor Cyan
& $git add -A

Write-Host 'Current status:' -ForegroundColor Cyan
& $git status

Write-Host 'Committing...' -ForegroundColor Cyan
& $git commit -m 'feat(vault): SecretManagement vault integration for token credential resolution (v2.4.0)

New private functions:
- Initialize-VaultIndex: creates credential-index.json on first vault-enabled load
- Read-VaultIndex: deserialises credential-index.json to hashtable
- Write-VaultIndex: merges a label entry and writes back to disk
- Resolve-VaultCredential: full vault resolution flow — label lookup, interactive
  prompt, test call validation (2xx/401/403/other), vault write-back
- Test-IsTokenValue: heuristic to distinguish vault labels from raw token strings
  (vault index match, known prefixes, length, character set)

ServiceAPI.psm1:
- Phase 0.5: detect SecretManagement at import, cache as $script:ServiceApiHasSecretManagement
- Phase 4: add $global:ServiceApiVaultIndex initialisation
- Phase 4.5: conditionally run Initialize-VaultIndex and Read-VaultIndex when vault detected
- Phase 6: add ServiceApiVaultIndex to cleanup handler
- Version bumped to 2.4.0

Get-ServiceCredential:
- Token mode (Priority 1) now routes through Resolve-VaultCredential when vault detected
- Non-vault path preserved unchanged for environments without SecretManagement
- -SessionOnly, -Endpoint, -BaseUrl parameters added for vault flow pass-through

Get-ServiceConfig:
- -SessionOnly, -Endpoint pass-through added to Get-ServiceCredential credParams

Invoke-APIRequest:
- -SessionOnly switch added, passed through to Get-ServiceConfig
- Endpoint passed through to Get-ServiceConfig for vault test call validation

ServiceAPI.psd1:
- Version bumped to 2.4.0
- Description and tags updated
- Release notes updated

Vault naming convention: {service}-{label}-{environment}
Credential stored as plain "key:secret" encoded string (":secret" when key is null)
Credential index tracked in config\credential-index.json (gitignored)'

Write-Host 'Pushing to origin master...' -ForegroundColor Cyan
& $git push origin master

Write-Host 'Done.' -ForegroundColor Green

# Self-cleanup — remove this script after successful push
Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force
Write-Host 'Commit script removed.' -ForegroundColor DarkGray
