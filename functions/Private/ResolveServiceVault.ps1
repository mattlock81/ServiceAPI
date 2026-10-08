function Resolve-ServiceVault {
    <#
    .SYNOPSIS
        Chooses the SecretManagement vault for a credential read or write.

    .DESCRIPTION
        Returns the name of a registered vault, or $null when none can be chosen. The name
        always carries the registered spelling.

        An explicit -Vault wins and must be registered; an unregistered name throws.

        Reads (default):
        1. -Vault.
        2. The vault recorded in the index for the service key and label.
        3. The saved default vault (Set-ServiceVault).
        4. The only registered vault.
        Otherwise $null, with a warning, because an unscoped lookup could return a secret of
        the same name from the wrong vault.

        Writes (-ForWrite):
        1. -Vault.
        2. The vault already recorded for the label, so updating a credential does not move it.
        3. The saved default vault.
        4. The only registered vault.
        5. A prompt when several are registered (offers to save the choice as the default).
        6. When none is registered, the create-a-vault flow (New-ServiceDefaultVault).
        Unattended runs never prompt: they warn and return $null so the caller can fall back
        to the session store.

        A recorded or saved vault that is no longer registered is skipped with a warning.
        Nothing here depends on the vault type.

    .PARAMETER Vault
        An explicit vault name. Must be registered.

    .PARAMETER ServiceKey
        The service key (service-environment) used to find the recorded vault.

    .PARAMETER Label
        The credential label used to find the recorded vault.

    .PARAMETER ForWrite
        Selects the write order and allows prompting or creating a vault.

    .EXAMPLE
        Resolve-ServiceVault -ServiceKey 'jira-prod' -Label 'default'

        Returns the vault that holds the jira-prod 'default' credential.

    .EXAMPLE
        Resolve-ServiceVault -ServiceKey 'jira-prod' -Label 'matt' -ForWrite

        Returns the vault to write the 'matt' credential to, prompting if needed.

    .EXAMPLE
        Resolve-ServiceVault -Vault 'automation'

        Validates that 'automation' is registered and returns its registered spelling.

    .OUTPUTS
        System.String

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.0
        Date        : 08-OCT-26

        CHANGE LOG
        1.0.0 | 08OCT26 | Initial version. Vault selection resolver for reads and writes.
    #>

    [CmdletBinding()]
    [OutputType([string])]
    param (
        [string]$Vault,
        [string]$ServiceKey,
        [string]$Label,
        [switch]$ForWrite
    )

    if (-not $script:ServiceApiHasSecretManagement) { return $null }

    $registered = @(Get-SecretVault -ErrorAction SilentlyContinue)
    $names      = @($registered | ForEach-Object { $_.Name })

    # Returns the registered spelling of a name, or $null when it is not registered.
    $match = { param($candidate)
        if ([string]::IsNullOrWhiteSpace($candidate)) { return $null }
        $names | Where-Object { $_ -ieq $candidate } | Select-Object -First 1
    }

    # 1. Explicit -Vault
    if ($Vault) {
        $found = & $match $Vault
        if (-not $found) {
            $list = if ($names.Count) { $names -join ', ' } else { 'none' }
            throw "Vault [$Vault] is not registered. Registered vaults: $list. Register one with Register-SecretVault."
        }
        return $found
    }

    # 2. Vault recorded in the index for this label
    if ($ServiceKey -and $Label -and $global:ServiceApiVaultIndex -and
        $global:ServiceApiVaultIndex.ContainsKey($ServiceKey) -and
        $global:ServiceApiVaultIndex[$ServiceKey].ContainsKey($Label)) {

        $recorded = [string]$global:ServiceApiVaultIndex[$ServiceKey][$Label]
        if ($recorded) {
            $found = & $match $recorded
            if ($found) { return $found }
            Write-Warning "ServiceAPI: The vault [$recorded] recorded for [$ServiceKey] label [$Label] is not registered. Falling back to the default vault."
        }
    }

    # 3. Saved default vault
    $saved = (Read-VaultConfig).DefaultVault
    if ($saved) {
        $found = & $match $saved
        if ($found) { return $found }
        Write-Warning "ServiceAPI: The saved default vault [$saved] is not registered. Use Set-ServiceVault to choose another."
    }

    # 4. The only registered vault
    if ($names.Count -eq 1) { return $names[0] }

    if (-not $ForWrite) {
        if ($names.Count -gt 1) {
            Write-Warning "ServiceAPI: Cannot tell which vault holds this credential. Pass -Vault or choose a default with Set-ServiceVault."
        }
        return $null
    }

    # 5. Several vaults and no default: ask (interactive only)
    if ($names.Count -gt 1) {
        if (-not (Test-ServiceApiInteractive)) {
            Write-Warning "ServiceAPI: Several vaults are registered and no default is saved. Pass -Vault or run Set-ServiceVault. The credential was not stored in a vault."
            return $null
        }

        Write-Host "`nSelect the vault to store this credential in:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $names.Count; $i++) { Write-Host "  [$($i + 1)] $($names[$i])" }
        $selection = Read-Host "Vault (1-$($names.Count))"
        $parsed    = 0
        if (-not [int]::TryParse($selection, [ref]$parsed) -or $parsed -lt 1 -or $parsed -gt $names.Count) {
            Write-Warning 'ServiceAPI: No valid vault selected. The credential was not stored in a vault.'
            return $null
        }

        $chosen = $names[$parsed - 1]
        $save   = Read-Host "Save [$chosen] as the default vault? (Y/n)"
        if (-not $save -or $save -match '^[Yy]') { Write-VaultConfig -DefaultVault $chosen }
        return $chosen
    }

    # 6. No vault registered: offer to create one (interactive only)
    $created = New-ServiceDefaultVault
    if (-not $created) {
        Write-Warning 'ServiceAPI: No vault is available. The credential was not stored in a vault.'
    }
    return $created
}
