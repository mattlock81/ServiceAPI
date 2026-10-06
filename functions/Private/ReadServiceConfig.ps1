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

    .OUTPUTS
        Hashtable of service name to environment to entry. Each entry carries the whitelisted
        fields BaseUrl, SSOProvider, SSODomain, SSOTenant and ProbeEndpoint when present.

    .EXAMPLE
        $config = Read-ServiceConfig
        $config.Keys

        Lists the service names persisted in services.json (empty when the file is absent).

    .EXAMPLE
        $config = Read-ServiceConfig
        $config['aihc']['prod'].ProbeEndpoint

        Reads one persisted field for a service and environment.

    .EXAMPLE
        $current = Read-ServiceConfig
        if (-not $current.ContainsKey('jira')) { $current['jira'] = @{} }

        Shows the merge-write pattern used by Write-ServiceConfig: read, add an entry, write back.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.4.1
        Date        : 06-OCT-26

        CHANGE LOG
        1.4.1 | 06OCT26 | Replaced em dashes with ASCII punctuation and reworded the affected
                          sentences, so the source is plain ASCII and loads on Windows PowerShell 5.1.
        1.4.0 | 06OCT26 | Added ProbeEndpoint to the parsed field whitelist so it survives the
                          read round-trip. Added the three help examples required by the CMF
                          standard.
        1.3.0 | 01OCT26 | Added SSOTenant to the parsed field whitelist so it survives the
                          read round-trip after being written by Write-ServiceConfig.
        1.2.0 | 12AUG26 | Added SSODomain to the parsed field whitelist so it survives
                          the read round-trip after being written by Write-ServiceConfig.
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

        # ConvertFrom-Json returns a PSCustomObject, so convert it to a nested hashtable for consistency
        $parsed = $raw | ConvertFrom-Json
        $result = @{}

        foreach ($serviceName in $parsed.PSObject.Properties.Name) {
            $result[$serviceName] = @{}
            foreach ($env in $parsed.$serviceName.PSObject.Properties.Name) {
                $envEntry = @{}
                $src      = $parsed.$serviceName.$env

                if ($src.PSObject.Properties['BaseUrl'])     { $envEntry['BaseUrl']     = $src.BaseUrl }
                if ($src.PSObject.Properties['SSOProvider']) { $envEntry['SSOProvider'] = $src.SSOProvider }
                if ($src.PSObject.Properties['SSODomain'])   { $envEntry['SSODomain']   = $src.SSODomain }
                if ($src.PSObject.Properties['SSOTenant'])   { $envEntry['SSOTenant']   = $src.SSOTenant }
                if ($src.PSObject.Properties['ProbeEndpoint']) { $envEntry['ProbeEndpoint'] = $src.ProbeEndpoint }

                $result[$serviceName][$env] = $envEntry
            }
        }

        return $result
    } catch {
        Write-Warning "ServiceAPI: Failed to read services.json: $_"
        return @{}
    }
}
