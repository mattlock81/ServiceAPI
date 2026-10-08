function Write-VaultIndex {
    <#
    .SYNOPSIS
        Adds a credential label to the vault index for a service-environment key.

    .DESCRIPTION
        Reads the current credential-index.json from the machine-local data folder, records
        the supplied label and the vault that holds it for the specified service-environment
        key (replacing any earlier record for that label), then writes the result back to disk
        through Save-VaultIndex. Updates $global:ServiceApiVaultIndex in memory.

        Called by Resolve-VaultCredential after a credential is successfully stored
        in the vault.

    .PARAMETER ServiceKey
        The service-environment key (e.g., opnsense-prod) to update in the index.

    .PARAMETER Label
        The credential label to add (e.g., default, matt).

    .PARAMETER Vault
        The registered vault name that holds the secret. Only the name is stored, never a path.
        Defaults to an empty string, meaning the vault is decided when the label is next read.

    .OUTPUTS
        None. Updates credential-index.json and $global:ServiceApiVaultIndex as side effects.

    .EXAMPLE
        Write-VaultIndex -ServiceKey 'jira-prod' -Label 'default' -Vault 'LocalStore'

        Records that the label 'default' for jira-prod is held in the vault LocalStore, in
        credential-index.json and in the in-memory index.

    .EXAMPLE
        Write-VaultIndex -ServiceKey 'jira-prod' -Label 'default'
        Write-VaultIndex -ServiceKey 'jira-prod' -Label 'default'

        Calling it twice with the same key and label records the label once. A label already
        present is not duplicated; the vault record is replaced.

    .EXAMPLE
        Set-Secret -Name 'jira-default-prod' -Secret $cred -Vault LocalStore
        Write-VaultIndex -ServiceKey 'jira-prod' -Label 'default' -Vault 'LocalStore'

        The order Resolve-VaultCredential uses: store the credential in the vault, then record
        its label so a later session can find it without prompting.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.3.0
        Date        : 08-OCT-26

        CHANGE LOG
        1.3.0 | 08OCT26 | Vault selection: records the vault that holds each label (-Vault); writes through
                          Save-VaultIndex.
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
        [Parameter(Mandatory)][string]$Label,
        [string]$Vault = ''
    )

    $current = Read-VaultIndex

    if (-not $current.ContainsKey($ServiceKey)) {
        $current[$ServiceKey] = @{}
    }

    # Record the vault that holds the label; an existing record is replaced.
    $current[$ServiceKey][$Label] = $Vault

    Save-VaultIndex -Index $current
    Write-Verbose "ServiceAPI: Vault index updated: [$ServiceKey] -> [$Label] in vault [$Vault]"
}
