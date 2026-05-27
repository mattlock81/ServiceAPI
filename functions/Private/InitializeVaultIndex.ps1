function Initialise-VaultIndex {
    <#
    .SYNOPSIS
        Ensures the vault credential index file exists on first load.

    .DESCRIPTION
        Called once at module load when SecretManagement is detected. Checks for the
        existence of credential-index.json in the user's local AppData directory
        ($env:LOCALAPPDATA\ServiceAPI\). If absent, creates the directory and an empty
        index file. Never overwrites an existing index.

        Storing credential-index.json in LocalAppData ensures it is machine-local and
        consistent with the SecretManagement vault which also stores credentials locally.
        This prevents a roamed index referencing vault entries that do not exist on the
        current machine.

        The credential index tracks which named credentials exist in the vault per
        service-environment key. It never stores credential values — only labels.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.1.0
        Date        : 17-MAY-26

        CHANGE LOG
        1.1.0 | 17MAY26 | Moved credential-index.json from module config\ directory to
                          $env:LOCALAPPDATA\ServiceAPI\ via $script:ServiceApiVaultIndexPath
                          so the index remains machine-local, consistent with the vault store.
        1.0.1 | 17MAY26 | Renamed to Initialise-VaultIndex for British/Australian English.
        1.0.0 | 17MAY26 | Initial version.
    #>

    [CmdletBinding()]
    param()

    $indexDir  = $script:ServiceApiVaultIndexPath
    $indexPath = Join-Path -Path $indexDir -ChildPath 'credential-index.json'

    if (Test-Path -Path $indexPath -PathType Leaf) {
        Write-Verbose "ServiceAPI: credential-index.json found at: $indexPath"
        return
    }

    if (-not (Test-Path -Path $indexDir -PathType Container)) {
        New-Item -Path $indexDir -ItemType Directory -Force | Out-Null
        Write-Verbose "ServiceAPI: Created vault index directory: $indexDir"
    }

    try {
        '{}' | Set-Content -LiteralPath $indexPath -Encoding UTF8 -Force
        Write-Verbose "ServiceAPI: Created empty credential-index.json at: $indexPath"
    } catch {
        Write-Warning "ServiceAPI: Failed to create credential-index.json — $_"
    }
}
