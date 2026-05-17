function Read-VaultIndex {
    <#
    .SYNOPSIS
        Reads the vault credential index from credential-index.json.

    .DESCRIPTION
        Reads credential-index.json from the user's local AppData directory
        ($env:LOCALAPPDATA\ServiceAPI\) and returns a hashtable mapping
        service-environment keys to arrays of stored credential labels.

        Returns an empty hashtable if the file is absent or empty. Never throws —
        vault index read failures are non-fatal; the module falls back to interactive
        prompts.

    .NOTES
        Author      : Matthew Sillett
        Organisation: Australian Signals Directorate
        Version     : 1.1.0
        Date        : 17-MAY-26

        CHANGE LOG
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
        Write-Warning "ServiceAPI: Failed to read credential-index.json — $_"
        return @{}
    }
}
