function Remove-VaultIndex {
    <#
    .SYNOPSIS
        Removes a credential label from the vault index for a service-environment key.

    .DESCRIPTION
        Reads the current credential-index.json from the user's local AppData directory
        ($env:LOCALAPPDATA\ServiceAPI\), removes the supplied label from the array for
        the specified service-environment key. If the array becomes empty, removes the
        key entirely. Writes the result back to disk and updates
        $global:ServiceApiVaultIndex in memory.

        Called by Clear-ServiceCredential after a vault secret is successfully removed.
        Mirrors Write-VaultIndex.

    .PARAMETER ServiceKey
        The service-environment key (e.g., jira-prod) to update in the index.

    .PARAMETER Label
        The credential label to remove (e.g., default, matt).

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.0
        Date        : 17-AUG-26

        CHANGE LOG
        1.0.0 | 17AUG26 | Initial version. Added to support automatic vault cleanup from
                          Clear-ServiceCredential — previously no removal counterpart to
                          Write-VaultIndex existed, leaving the index out of sync whenever
                          a vault secret was removed independently of the index.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string]$ServiceKey,
        [Parameter(Mandatory)][string]$Label
    )

    $indexDir  = $script:ServiceApiVaultIndexPath
    $indexPath = Join-Path -Path $indexDir -ChildPath 'credential-index.json'

    $current = Read-VaultIndex

    if (-not $current.ContainsKey($ServiceKey)) {
        Write-Verbose "ServiceAPI: No vault index entry for [$ServiceKey] — nothing to remove."
        return
    }

    $current[$ServiceKey] = @($current[$ServiceKey] | Where-Object { $_ -ne $Label })

    if ($current[$ServiceKey].Count -eq 0) {
        $current.Remove($ServiceKey)
    }

    # Ensure directory exists (defensive — should already exist if an index entry was found)
    if (-not (Test-Path -Path $indexDir -PathType Container)) {
        New-Item -Path $indexDir -ItemType Directory -Force | Out-Null
    }

    try {
        $current | ConvertTo-Json -Depth 3 |
            Set-Content -LiteralPath $indexPath -Encoding UTF8 -Force
        Write-Verbose "ServiceAPI: Vault index updated: removed [$Label] from [$ServiceKey]"
    } catch {
        Write-Warning "ServiceAPI: Failed to write credential-index.json — $_"
    }

    $global:ServiceApiVaultIndex = $current
}
