function Write-VaultIndex {
    <#
    .SYNOPSIS
        Adds a credential label to the vault index for a service-environment key.

    .DESCRIPTION
        Reads the current credential-index.json from the user's local AppData directory
        ($env:LOCALAPPDATA\ServiceAPI\), adds the supplied label to the array for the
        specified service-environment key if not already present, then writes the result
        back to disk. Updates $global:ServiceApiVaultIndex in memory.

        Called by Resolve-VaultCredential after a credential is successfully stored
        in the vault.

    .PARAMETER ServiceKey
        The service-environment key (e.g., opnsense-prod) to update in the index.

    .PARAMETER Label
        The credential label to add (e.g., default, matt).

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.1.0
        Date        : 17-MAY-26

        CHANGE LOG
        1.1.0 | 17MAY26 | Updated path from module config\ directory to
                          $env:LOCALAPPDATA\ServiceAPI\ via $script:ServiceApiVaultIndexPath.
        1.0.0 | 17MAY26 | Initial version.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string]$ServiceKey,
        [Parameter(Mandatory)][string]$Label
    )

    $indexDir  = $script:ServiceApiVaultIndexPath
    $indexPath = Join-Path -Path $indexDir -ChildPath 'credential-index.json'

    # Ensure directory exists
    if (-not (Test-Path -Path $indexDir -PathType Container)) {
        New-Item -Path $indexDir -ItemType Directory -Force | Out-Null
    }

    # Read current index
    $current = Read-VaultIndex

    # Add label if not already present
    if (-not $current.ContainsKey($ServiceKey)) {
        $current[$ServiceKey] = @()
    }

    if ($Label -notin $current[$ServiceKey]) {
        $current[$ServiceKey] = @($current[$ServiceKey]) + $Label
    }

    # Write back to disk
    try {
        $current | ConvertTo-Json -Depth 3 |
            Set-Content -LiteralPath $indexPath -Encoding UTF8 -Force
        Write-Verbose "ServiceAPI: Vault index updated: [$ServiceKey] → [$Label]"
    } catch {
        Write-Warning "ServiceAPI: Failed to write credential-index.json — $_"
    }

    # Update in-memory index
    $global:ServiceApiVaultIndex = $current
}
