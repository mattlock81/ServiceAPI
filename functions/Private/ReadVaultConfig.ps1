function Read-VaultConfig {
    <#
    .SYNOPSIS
        Reads the saved ServiceAPI vault settings from vault-config.json.

    .DESCRIPTION
        Returns a hashtable with the saved default vault name. The file lives next to
        credential-index.json in the machine-local data folder, because vault
        registrations are per user and per machine. A missing, empty or unreadable file
        returns an empty default without raising an error.

    .OUTPUTS
        System.Collections.Hashtable with the key DefaultVault (an empty string when no
        default is saved).

    .EXAMPLE
        (Read-VaultConfig).DefaultVault

        Returns the saved default vault name, or an empty string.

    .EXAMPLE
        if ((Read-VaultConfig).DefaultVault) { 'A default vault is saved.' }

        Tests whether a default vault has been saved.

    .EXAMPLE
        & (Get-Module ServiceAPI) { Read-VaultConfig }

        Reads the saved settings from outside the module for troubleshooting.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.0
        Date        : 08-OCT-26

        CHANGE LOG
        1.0.0 | 08OCT26 | Initial version. Vault selection: reads the saved default vault.
    #>

    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $result = @{ DefaultVault = '' }
    $path   = Join-Path -Path $script:ServiceApiVaultIndexPath -ChildPath 'vault-config.json'

    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $result }

    try {
        $raw = Get-Content -LiteralPath $path -Raw -Encoding UTF8
        if ([string]::IsNullOrWhiteSpace($raw)) { return $result }

        $parsed = $raw | ConvertFrom-Json
        if ($parsed.PSObject.Properties.Name -contains 'DefaultVault' -and $parsed.DefaultVault) {
            $result['DefaultVault'] = [string]$parsed.DefaultVault
        }
    } catch {
        Write-Warning "ServiceAPI: Failed to read vault-config.json: $_"
    }

    return $result
}
