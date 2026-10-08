function Get-ServiceVault {
    <#
    .SYNOPSIS
        Lists the registered SecretManagement vaults and shows which one ServiceAPI uses by default.

    .DESCRIPTION
        Returns one object for each vault registered with SecretManagement, with the vault
        type, whether it is the ServiceAPI default (saved by Set-ServiceVault), whether it is
        the SecretManagement default, and how many ServiceAPI credentials the index records
        in it.

        A vault is chosen for a credential in this order. Reading: -Vault, the vault recorded
        for the label, the saved default, then the only registered vault. Writing: -Vault, the
        vault already recorded for the label, the saved default, the only registered vault,
        then a prompt. See Set-ServiceVault to choose the default.

        Returns nothing, with a warning, when SecretManagement is not available.

    .PARAMETER Name
        Limits the output to vaults whose name matches. Wildcards are allowed.

    .EXAMPLE
        Get-ServiceVault

        Lists every registered vault and marks the ServiceAPI default.

    .EXAMPLE
        Get-ServiceVault -Name 'auto*' | Format-Table Name, ModuleName, IsServiceDefault, Credentials

        Shows the vaults whose names start with 'auto' and how many credentials each holds.

    .EXAMPLE
        (Get-ServiceVault | Where-Object IsServiceDefault).Name

        Returns the name of the saved default vault.

    .OUTPUTS
        PSCustomObject with Name, ModuleName, IsServiceDefault, IsSecretManagementDefault
        and Credentials.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.0
        Date        : 08-OCT-26

        CHANGE LOG
        1.0.0 | 08OCT26 | Initial version. Vault selection: lists the registered vaults and the
                          saved default.
    #>

    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [ArgumentCompleter({
            param($cmd, $param, $word, $ast, $fakeBound)
            if (Get-Command -Name Get-SecretVault -ErrorAction SilentlyContinue) {
                Get-SecretVault -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -like "$word*" } |
                    ForEach-Object {
                        [System.Management.Automation.CompletionResult]::new(
                            $_.Name, $_.Name, 'ParameterValue', $_.Name
                        )
                    }
            }
        })]
        [string]$Name = '*'
    )

    if (-not $script:ServiceApiHasSecretManagement) {
        Write-Warning 'Microsoft.PowerShell.SecretManagement is not available, so there are no vaults to list.'
        return
    }

    $saved = (Read-VaultConfig).DefaultVault

    foreach ($registered in @(Get-SecretVault -ErrorAction SilentlyContinue)) {
        if ($registered.Name -notlike $Name) { continue }

        $count = 0
        foreach ($serviceKey in $global:ServiceApiVaultIndex.Keys) {
            foreach ($label in $global:ServiceApiVaultIndex[$serviceKey].Keys) {
                if ([string]$global:ServiceApiVaultIndex[$serviceKey][$label] -ieq $registered.Name) { $count++ }
            }
        }

        [pscustomobject]@{
            Name                     = $registered.Name
            ModuleName               = $registered.ModuleName
            IsServiceDefault         = [bool]($saved -and $registered.Name -ieq $saved)
            IsSecretManagementDefault = [bool]$registered.IsDefault
            Credentials              = $count
        }
    }
}
