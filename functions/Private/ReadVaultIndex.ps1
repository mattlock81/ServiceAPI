function Read-VaultIndex {
    <#
    .SYNOPSIS
        Reads the vault credential index from credential-index.json.

    .DESCRIPTION
        Reads credential-index.json from the user's local AppData directory
        ($env:LOCALAPPDATA\ServiceAPI\) and returns a hashtable mapping
        service-environment keys to arrays of stored credential labels.

        Returns an empty hashtable if the file is absent or empty. Never throws:
        vault index read failures are non-fatal; the module falls back to interactive
        prompts.

    .OUTPUTS
        System.Collections.Hashtable - service-environment key to an array of credential labels.
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
        Version     : 1.1.2
        Date        : 06-OCT-26

        CHANGE LOG
        1.1.2 | 06OCT26 | Replaced em dashes with ASCII punctuation and reworded the affected
                          sentences, so the source is plain ASCII and loads on Windows PowerShell 5.1.
        1.1.1 | 06OCT26 | Added the help examples and .OUTPUTS required by the CMF standard.
        1.1.0 | 17MAY26 | Updated path from module config\ directory to
                          $env:LOCALAPPDATA\ServiceAPI\ via $script:ServiceApiVaultIndexPath.
        1.0.0 | 17MAY26 | Initial version.
    #>

    [CmdletBinding()]
    param()

    $indexPath = Join-Path -Path $script:ServiceApiVaultIndexPath -ChildPath 'credential-index.json'

    if (-not (Test-Path -Path $indexPath -PathType Leaf)) { return @{} }

    try {
        $raw = Get-Content -LiteralPath $indexPath -Raw -Encoding UTF8
        if ([string]::IsNullOrWhiteSpace($raw) -or $raw.Trim() -eq '{}') { return @{} }

        $parsed = $raw | ConvertFrom-Json
        $result = @{}

        foreach ($key in $parsed.PSObject.Properties.Name) {
            # Ensure labels are stored as a plain string array
            $result[$key] = @($parsed.$key)
        }

        return $result
    } catch {
        Write-Warning "ServiceAPI: Failed to read credential-index.json: $_"
        return @{}
    }
}
