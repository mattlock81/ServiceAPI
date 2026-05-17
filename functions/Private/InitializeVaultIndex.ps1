function Initialize-VaultIndex {
    <#
    .SYNOPSIS
        Ensures the vault credential index file exists on first load.

    .DESCRIPTION
        Called once at module load when SecretManagement is detected. Checks for the existence
        of credential-index.json in the module config directory. If absent, creates an empty
        index file. Never overwrites an existing index.

        The credential index tracks which named credentials exist in the vault per
        service-environment key. It never stores credential values — only labels.

    .NOTES
        Author      : Matthew Sillett
        Organisation: Australian Signals Directorate
        Version     : 1.0.0
        Date        : 17-MAY-26

        CHANGE LOG
        1.0.0 | 17MAY26 | Initial version. Provides first-load auto-creation of
                          credential-index.json for SecretManagement vault integration.
    #>

    [CmdletBinding()]
    param()

    $configDir  = Join-Path -Path $script:ModuleRoot -ChildPath 'config'
    $indexPath  = Join-Path -Path $configDir -ChildPath 'credential-index.json'

    if (Test-Path -Path $indexPath -PathType Leaf) {
        Write-Verbose "ServiceAPI: credential-index.json found at: $indexPath"
        return
    }

    if (-not (Test-Path -Path $configDir -PathType Container)) {
        New-Item -Path $configDir -ItemType Directory -Force | Out-Null
    }

    try {
        '{}' | Set-Content -LiteralPath $indexPath -Encoding UTF8 -Force
        Write-Verbose "ServiceAPI: Created empty credential-index.json at: $indexPath"
    } catch {
        Write-Warning "ServiceAPI: Failed to create credential-index.json — $_"
    }
}
