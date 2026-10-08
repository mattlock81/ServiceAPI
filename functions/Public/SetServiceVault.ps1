function Set-ServiceVault {
    <#
    .SYNOPSIS
        Saves the default SecretManagement vault that ServiceAPI uses for credentials.

    .DESCRIPTION
        Saves a registered vault name as the ServiceAPI default, so you are not asked which
        vault to use each time and so a vault other than the SecretManagement default can be
        preferred. The setting is machine-local (vault-config.json beside the vault index)
        and holds the vault name only, never a path, because vault registrations are per user
        and per machine.

        Any registered SecretManagement extension works, including SecretStore and
        SecretManagement.KeePass. SecretStore is one store per user: several SecretStore
        registrations share the same secrets and lock settings, so separate vaults for
        different purposes need different extensions.

        A credential read still uses the vault recorded for its label; the default applies to
        new credentials and to labels without a recorded vault. -Vault on the credential
        functions overrides it for one call.

        Suggested vault names, by purpose: automation, local-systems, online-accounts.

    .PARAMETER Name
        The registered vault name to save as the default. The name must be registered; see
        Get-SecretVault.

    .PARAMETER Clear
        Removes the saved default.

    .EXAMPLE
        Set-ServiceVault -Name 'automation'

        Saves 'automation' as the default vault for new ServiceAPI credentials.

    .EXAMPLE
        Set-ServiceVault -Clear

        Removes the saved default; the only registered vault, or a prompt, is used instead.

    .EXAMPLE
        Set-ServiceVault -Name 'local-systems' -WhatIf

        Shows what would be saved without changing anything.

    .OUTPUTS
        None.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.0
        Date        : 08-OCT-26

        CHANGE LOG
        1.0.0 | 08OCT26 | Initial version. Vault selection: saves or clears the default vault.
    #>

    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Set')]
    param (
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'Set')]
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
        [string]$Name,

        [Parameter(Mandatory, ParameterSetName = 'Clear')]
        [switch]$Clear
    )

    if (-not $script:ServiceApiHasSecretManagement) {
        Write-Warning 'Microsoft.PowerShell.SecretManagement is not available, so no vault can be saved.'
        return
    }

    if ($Clear) {
        if ($PSCmdlet.ShouldProcess('ServiceAPI default vault', 'Clear')) {
            Write-VaultConfig -DefaultVault ''
        }
        return
    }

    # Resolve-ServiceVault throws for an unregistered name and returns the registered spelling.
    $registered = Resolve-ServiceVault -Vault $Name

    if ($PSCmdlet.ShouldProcess("ServiceAPI default vault", "Set to [$registered]")) {
        Write-VaultConfig -DefaultVault $registered
    }
}
