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

    .OUTPUTS
        None. Updates credential-index.json and $global:ServiceApiVaultIndex as side effects.

    .EXAMPLE
        Write-VaultIndex -ServiceKey 'jira-prod' -Label 'default'

        Records the label 'default' for jira-prod in credential-index.json and in the in-memory index.

    .EXAMPLE
        Write-VaultIndex -ServiceKey 'jira-prod' -Label 'default'
        Write-VaultIndex -ServiceKey 'jira-prod' -Label 'default'

        Calling it twice with the same key and label records the label once. A label already
        present is not duplicated.

    .EXAMPLE
        Set-Secret -Name 'jira-default-prod' -Secret $cred -Vault LocalStore
        Write-VaultIndex -ServiceKey 'jira-prod' -Label 'default'

        The order Resolve-VaultCredential uses: store the credential in the vault, then record
        its label so a later session can find it without prompting.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.2.0
        Date        : 08-OCT-26

        CHANGE LOG
        1.2.0 | 08OCT26 | Linux support: restrict the file and directory to the owner (700/600) through
                          Set-ServiceApiSecureMode.
        1.1.2 | 06OCT26 | Replaced em dashes with ASCII punctuation and reworded the affected
                          sentences, so the source is plain ASCII and loads on Windows PowerShell 5.1.
        1.1.1 | 06OCT26 | Added the help examples and .OUTPUTS required by the CMF standard.
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
        Set-ServiceApiSecureMode -Path $indexDir
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
        Write-Verbose "ServiceAPI: Vault index updated: [$ServiceKey] -> [$Label]"
        Set-ServiceApiSecureMode -Path $indexPath
    } catch {
        Write-Warning "ServiceAPI: Failed to write credential-index.json: $_"
    }

    # Update in-memory index
    $global:ServiceApiVaultIndex = $current
}
