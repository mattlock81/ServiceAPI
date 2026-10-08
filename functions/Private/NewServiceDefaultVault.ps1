function New-ServiceDefaultVault {
    <#
    .SYNOPSIS
        Offers to create a personal SecretStore vault named LocalStore when none is registered.

    .DESCRIPTION
        Runs only in an interactive session. Asks for confirmation, registers a
        Microsoft.PowerShell.SecretStore vault named LocalStore as the SecretManagement
        default, configures the store for the current user with password authentication
        (SecretStore prompts for the new password), and saves LocalStore as the ServiceAPI
        default vault.

        This is the only place in the module that assumes SecretStore. Every other vault
        decision works with any registered SecretManagement extension.

        Returns the vault name, or $null when the session is not interactive, the user
        declines, SecretStore is not installed, or registration fails.

    .EXAMPLE
        $vault = New-ServiceDefaultVault

        Offers to create LocalStore and returns its name, or $null.

    .EXAMPLE
        if (-not (Get-SecretVault)) { New-ServiceDefaultVault | Out-Null }

        Creates the default vault only when no vault is registered.

    .EXAMPLE
        & (Get-Module ServiceAPI) { New-ServiceDefaultVault -Verbose }

        Runs the flow from outside the module with verbose output.

    .OUTPUTS
        System.String

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.0
        Date        : 08-OCT-26

        CHANGE LOG
        1.0.0 | 08OCT26 | Initial version. Vault selection: create-a-vault flow for a first run
                          with no registered vault.
    #>

    [CmdletBinding()]
    [OutputType([string])]
    param()

    if (-not (Test-ServiceApiInteractive)) { return $null }

    Write-Host "`nNo SecretManagement vault is registered." -ForegroundColor Cyan
    $answer = Read-Host "Create a personal SecretStore vault named 'LocalStore' now? (Y/n)"
    if ($answer -and $answer -notmatch '^[Yy]') { return $null }

    if (-not (Get-Module -Name Microsoft.PowerShell.SecretStore -ListAvailable)) {
        Write-Warning "Microsoft.PowerShell.SecretStore is not installed. Install it (Install-PSResource Microsoft.PowerShell.SecretStore) or register another vault with Register-SecretVault, then retry."
        return $null
    }

    try {
        Register-SecretVault -Name 'LocalStore' -ModuleName 'Microsoft.PowerShell.SecretStore' -DefaultVault -ErrorAction Stop
        Set-SecretStoreConfiguration -Scope CurrentUser -Authentication Password -PasswordTimeout 3600 -Confirm:$false -ErrorAction Stop
        Write-VaultConfig -DefaultVault 'LocalStore'
        Write-Host "Vault 'LocalStore' created and saved as the ServiceAPI default." -ForegroundColor Cyan
        return 'LocalStore'
    } catch {
        Write-Warning "Could not create the 'LocalStore' vault: $_"
        return $null
    }
}
