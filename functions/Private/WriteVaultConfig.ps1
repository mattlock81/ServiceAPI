function Write-VaultConfig {
    <#
    .SYNOPSIS
        Saves or clears the default vault in vault-config.json.

    .DESCRIPTION
        Writes the default vault name to vault-config.json in the machine-local data
        folder. An empty name removes the saved default. Only the vault name is stored,
        never a path, because vault registrations are per user and per machine. On Linux
        the file and folder are restricted to the owner.

    .PARAMETER DefaultVault
        The registered vault name to save as the default. An empty string clears it.

    .EXAMPLE
        Write-VaultConfig -DefaultVault 'automation'

        Saves 'automation' as the default vault.

    .EXAMPLE
        Write-VaultConfig -DefaultVault ''

        Clears the saved default vault.

    .EXAMPLE
        & (Get-Module ServiceAPI) { Write-VaultConfig -DefaultVault 'LocalStore' }

        Saves a default vault from outside the module for troubleshooting.

    .OUTPUTS
        None.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.0
        Date        : 08-OCT-26

        CHANGE LOG
        1.0.0 | 08OCT26 | Initial version. Vault selection: saves or clears the default vault.
    #>

    [CmdletBinding()]
    param (
        [AllowEmptyString()]
        [string]$DefaultVault = ''
    )

    $dir  = $script:ServiceApiVaultIndexPath
    $path = Join-Path -Path $dir -ChildPath 'vault-config.json'

    if ([string]::IsNullOrWhiteSpace($DefaultVault)) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            Remove-Item -LiteralPath $path -Force
            Write-Verbose 'ServiceAPI: Cleared the saved default vault.'
        }
        return
    }

    if (-not (Test-Path -Path $dir -PathType Container)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
        Set-ServiceApiSecureMode -Path $dir
    }

    [ordered]@{ DefaultVault = $DefaultVault } | ConvertTo-Json |
        Set-Content -LiteralPath $path -Encoding UTF8 -Force
    Set-ServiceApiSecureMode -Path $path
    Write-Verbose "ServiceAPI: Saved default vault [$DefaultVault]."
}
