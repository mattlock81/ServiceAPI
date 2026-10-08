function Read-VaultIndex {
    <#
    .SYNOPSIS
        Reads the vault credential index from credential-index.json.

    .DESCRIPTION
        Reads credential-index.json from the machine-local data folder
        ($env:LOCALAPPDATA\ServiceAPI\ on Windows, ~/.local/share/ServiceAPI on Linux) and
        returns a hashtable mapping service-environment keys to a hashtable of credential label
        to vault name.

        The older format, a bare array of labels per key, is still read. Its labels are assigned
        to the saved default vault or the only registered vault (an empty name when neither
        applies), and $script:ServiceApiVaultIndexLegacy is set so the loader can rewrite the
        file in the current format.

        Returns an empty hashtable if the file is absent or empty. Never throws:
        vault index read failures are non-fatal; the module falls back to interactive
        prompts.

    .OUTPUTS
        System.Collections.Hashtable - service-environment key to a hashtable of label to vault name.
        Empty when the index file is absent, empty or unreadable.

    .EXAMPLE
        $index = Read-VaultIndex
        $index.Keys

        Lists the service-environment keys that have at least one stored credential label.

    .EXAMPLE
        (Read-VaultIndex)['jira-prod']

        Returns the credential labels recorded for jira-prod, or $null when there are none.

    .EXAMPLE
        if ((Read-VaultIndex).ContainsKey('jira-prod')) {
            Write-Verbose 'A vault credential exists for jira-prod; skipping the prompt.'
        }

        Checks whether any credential label exists for a key before deciding to prompt.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.2.0
        Date        : 08-OCT-26

        CHANGE LOG
        1.2.0 | 08OCT26 | Vault selection: reads the label-to-vault schema; the older array-per-key format is
                          read as legacy and its labels assigned to the saved default or the only registered vault.
        1.1.2 | 06OCT26 | Replaced em dashes with ASCII punctuation and reworded the affected
                          sentences, so the source is plain ASCII and loads on Windows PowerShell 5.1.
        1.1.1 | 06OCT26 | Added the help examples and .OUTPUTS required by the CMF standard.
        1.1.0 | 17MAY26 | Updated path from module config\ directory to
                          $env:LOCALAPPDATA\ServiceAPI\ via $script:ServiceApiVaultIndexPath.
        1.0.0 | 17MAY26 | Initial version.
    #>

    [CmdletBinding()]
    param()

    $script:ServiceApiVaultIndexLegacy = $false
    $indexPath = Join-Path -Path $script:ServiceApiVaultIndexPath -ChildPath 'credential-index.json'

    if (-not (Test-Path -Path $indexPath -PathType Leaf)) { return @{} }

    try {
        $raw = Get-Content -LiteralPath $indexPath -Raw -Encoding UTF8
        if ([string]::IsNullOrWhiteSpace($raw) -or $raw.Trim() -eq '{}') { return @{} }

        $parsed = $raw | ConvertFrom-Json
        $result = @{}

        # Legacy entries (a bare array of labels) are assigned to the saved default vault, or
        # to the only registered vault, so they keep resolving. An empty name means undecided.
        $legacyVault = $null

        foreach ($key in $parsed.PSObject.Properties.Name) {
            $value = $parsed.$key
            $entry = @{}

            if ($value -is [System.Array] -or $value -is [string]) {
                $script:ServiceApiVaultIndexLegacy = $true

                if ($null -eq $legacyVault) {
                    $legacyVault = ''
                    $names = @()
                    if ($script:ServiceApiHasSecretManagement) {
                        $names = @(Get-SecretVault -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
                    }
                    $saved = (Read-VaultConfig).DefaultVault
                    if ($saved -and ($names -contains $saved)) {
                        $legacyVault = $saved
                    } elseif ($names.Count -eq 1) {
                        $legacyVault = $names[0]
                    }
                }

                foreach ($label in @($value)) { $entry[[string]$label] = $legacyVault }
            } else {
                foreach ($label in $value.PSObject.Properties.Name) {
                    $entry[$label] = [string]$value.$label
                }
            }

            $result[$key] = $entry
        }

        return $result
    } catch {
        Write-Warning "ServiceAPI: Failed to read credential-index.json: $_"
        return @{}
    }
}
