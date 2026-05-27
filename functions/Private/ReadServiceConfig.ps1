function Read-ServiceConfig {
    <#
    .SYNOPSIS
        Reads the persisted service configuration from services.json.

    .DESCRIPTION
        Reads services.json from the user's roaming AppData directory
        ($env:APPDATA\ServiceAPI\) and returns a hashtable representing the stored
        service registry. Called internally at module load and by Register-CustomService
        when merging a new persistent entry.

        If the directory or file does not exist, returns an empty hashtable. File creation
        on first load is handled by Initialise-ServiceConfig, not this function.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.1.0
        Date        : 17-MAY-26

        CHANGE LOG
        1.1.0 | 17MAY26 | Updated path from module config\ directory to
                          $env:APPDATA\ServiceAPI\ via $script:ServiceApiConfigPath.
        1.0.0 | 16MAY26 | Initial version. Centralises services.json read access for module
                          load and persistent registration write-merge operations.
    #>

    [CmdletBinding()]
    param()

    $configPath = Join-Path -Path $script:ServiceApiConfigPath -ChildPath 'services.json'

    if (-not (Test-Path -Path $configPath -PathType Leaf)) {
        return @{}
    }

    try {
        $raw = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8
        if ([string]::IsNullOrWhiteSpace($raw)) { return @{} }

        # ConvertFrom-Json returns a PSCustomObject — convert to nested hashtable for consistency
        $parsed = $raw | ConvertFrom-Json
        $result = @{}

        foreach ($serviceName in $parsed.PSObject.Properties.Name) {
            $result[$serviceName] = @{}
            foreach ($env in $parsed.$serviceName.PSObject.Properties.Name) {
                $envEntry = @{}
                $src      = $parsed.$serviceName.$env

                if ($src.PSObject.Properties['BaseUrl'])     { $envEntry['BaseUrl']     = $src.BaseUrl }
                if ($src.PSObject.Properties['SSOProvider']) { $envEntry['SSOProvider'] = $src.SSOProvider }

                $result[$serviceName][$env] = $envEntry
            }
        }

        return $result
    } catch {
        Write-Warning "ServiceAPI: Failed to read services.json — $_"
        return @{}
    }
}
