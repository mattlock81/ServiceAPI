function Save-VaultIndex {
    <#
    .SYNOPSIS
        Writes the whole vault index to credential-index.json and refreshes the in-memory copy.

    .DESCRIPTION
        The single writer for credential-index.json. The index maps service key to label to
        vault name:

            { "jira-prod": { "default": "LocalStore", "matt": "automation" } }

        Keys are sorted so the file is stable. Only vault names are stored, never paths. On
        Linux the folder and file are restricted to the owner. A write failure is reported
        as a warning and never stops the caller; the in-memory index is still updated.

    .PARAMETER Index
        The index to write: a hashtable of service key to a hashtable of label to vault name.

    .EXAMPLE
        $index = Read-VaultIndex
        $index['jira-prod'] = @{ default = 'LocalStore' }
        Save-VaultIndex -Index $index

        Replaces the index with an updated copy.

    .EXAMPLE
        Save-VaultIndex -Index @{}

        Writes an empty index.

    .EXAMPLE
        & (Get-Module ServiceAPI) { Save-VaultIndex -Index (Read-VaultIndex) }

        Rewrites the index in the current format from outside the module.

    .OUTPUTS
        None.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.0
        Date        : 08-OCT-26

        CHANGE LOG
        1.0.0 | 08OCT26 | Initial version. Vault selection: one writer for the label-to-vault
                          index, replacing the duplicated write blocks in Write-VaultIndex and
                          Remove-VaultIndex.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$Index
    )

    $dir  = $script:ServiceApiVaultIndexPath
    $path = Join-Path -Path $dir -ChildPath 'credential-index.json'

    if (-not (Test-Path -Path $dir -PathType Container)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
        Set-ServiceApiSecureMode -Path $dir
    }

    $ordered = [ordered]@{}
    foreach ($serviceKey in ($Index.Keys | Sort-Object)) {
        $ordered[$serviceKey] = [ordered]@{}
        foreach ($label in ($Index[$serviceKey].Keys | Sort-Object)) {
            $ordered[$serviceKey][$label] = [string]$Index[$serviceKey][$label]
        }
    }

    try {
        $ordered | ConvertTo-Json -Depth 4 |
            Set-Content -LiteralPath $path -Encoding UTF8 -Force
        Set-ServiceApiSecureMode -Path $path
        Write-Verbose "ServiceAPI: Vault index written to: $path"
    } catch {
        Write-Warning "ServiceAPI: Failed to write credential-index.json: $_"
    }

    $global:ServiceApiVaultIndex = $Index
}
