function Remove-VaultIndex {
    <#
    .SYNOPSIS
        Removes a credential label from the vault index for a service-environment key.

    .DESCRIPTION
        Reads the current credential-index.json from the machine-local data folder and removes
        the supplied label (with its recorded vault) for the specified service-environment key.
        If no labels remain, removes the key entirely. Writes the result back to disk through
        Save-VaultIndex and updates $global:ServiceApiVaultIndex in memory.

        Called by Clear-ServiceCredential after a vault secret is successfully removed.
        Mirrors Write-VaultIndex.

    .PARAMETER ServiceKey
        The service-environment key (e.g., jira-prod) to update in the index.

    .PARAMETER Label
        The credential label to remove (e.g., default, matt).

    .OUTPUTS
        None. Updates credential-index.json and $global:ServiceApiVaultIndex as side effects.

    .EXAMPLE
        Remove-VaultIndex -ServiceKey 'jira-prod' -Label 'default'

        Removes the label 'default' from jira-prod. When it was the last label for that key, the
        key is removed from the index as well.

    .EXAMPLE
        Remove-VaultIndex -ServiceKey 'jira-prod' -Label 'matt' -Verbose

        Shows in the verbose stream that the label was removed. For a key with no index entry the
        verbose output reports that there is nothing to remove, and the function returns.

    .EXAMPLE
        Remove-Secret -Name 'jira-default-prod' -Vault LocalStore
        Remove-VaultIndex -ServiceKey 'jira-prod' -Label 'default'

        The order Clear-ServiceCredential uses: remove the secret from the vault first, then remove
        its label so the index never names a credential that no longer exists.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.2.0
        Date        : 08-OCT-26

        CHANGE LOG
        1.2.0 | 08OCT26 | Vault selection: removes a label from the label-to-vault schema; writes through
                          Save-VaultIndex.
        1.1.0 | 08OCT26 | Linux support: restrict the file and directory to the owner (700/600) through
                          Set-ServiceApiSecureMode.
        1.0.2 | 06OCT26 | Replaced em dashes with ASCII punctuation and reworded the affected
                          sentences, so the source is plain ASCII and loads on Windows PowerShell 5.1.
        1.0.1 | 06OCT26 | Added the help examples and .OUTPUTS required by the CMF standard.
        1.0.0 | 17AUG26 | Initial version. Added to support automatic vault cleanup from
                          Clear-ServiceCredential, because previously no removal counterpart to
                          Write-VaultIndex existed, leaving the index out of sync whenever
                          a vault secret was removed independently of the index.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string]$ServiceKey,
        [Parameter(Mandatory)][string]$Label
    )

    $current = Read-VaultIndex

    if (-not $current.ContainsKey($ServiceKey) -or -not $current[$ServiceKey].ContainsKey($Label)) {
        Write-Verbose "ServiceAPI: No vault index entry for [$ServiceKey] label [$Label]; nothing to remove."
        return
    }

    $current[$ServiceKey].Remove($Label)

    if ($current[$ServiceKey].Count -eq 0) {
        $current.Remove($ServiceKey)
    }

    Save-VaultIndex -Index $current
    Write-Verbose "ServiceAPI: Vault index updated: removed [$Label] from [$ServiceKey]"
}
