function Write-ServiceConfig {
    <#
    .SYNOPSIS
        Merges a service entry into services.json and writes the result to disk.

    .DESCRIPTION
        Reads the current services.json from the user's roaming AppData directory
        ($env:APPDATA\ServiceAPI\), merges the supplied service name, environment,
        BaseUrl, and optional SSOProvider into the existing data, then writes the result
        back to disk as formatted JSON. Creates the directory if absent.

        Called by Register-CustomService when -Persistent is specified. Does not affect
        in-memory registry state; that is managed by Register-CustomService directly.

    .PARAMETER ServiceName
        The service name key to write (e.g., google, jira).

    .PARAMETER Environment
        The environment key to write under the service (e.g., prod, qa).

    .PARAMETER BaseUrl
        The base URL to persist for this service/environment.

    .PARAMETER SSOProvider
        Optional. The SSO provider string to persist (e.g., GCloud, AzureCLI, Aria, AriaOidc).

    .PARAMETER SSODomain
        Optional. The domain string to persist for the Aria SSO provider.

    .PARAMETER SSOTenant
        Optional. The tenant name string to persist for the AriaOidc SSO provider.

    .PARAMETER ProbeEndpoint
        Optional. The relative probe endpoint string to persist, used to test whether a bearer
        is valid for the service (see Get-ServiceProbeEndpoint).

    .EXAMPLE
        Write-ServiceConfig -ServiceName jira -Environment prod -BaseUrl 'https://jira.example.com'

        Persists a plain service entry with no SSO settings.

    .EXAMPLE
        Write-ServiceConfig -ServiceName aria -Environment prod -BaseUrl 'https://aria.example.com' `
            -SSOProvider AriaOidc -SSOTenant 'my-tenant'

        Persists an AriaOidc service together with its tenant.

    .EXAMPLE
        Write-ServiceConfig -ServiceName aria -Environment prod -BaseUrl 'https://aria.example.com' `
            -SSOProvider AriaOidc -SSOTenant 'my-tenant' -ProbeEndpoint 'iaas/api/projects?$top=1'

        Persists a probe endpoint alongside the SSO settings. An entry for the same service and
        environment is replaced; other environments and services in the file are preserved.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.5.1
        Date        : 08-OCT-26

        CHANGE LOG
        1.5.1 | 08OCT26 | Help examples: the example service name aihc is replaced with aria. No code change.
        1.5.0 | 08OCT26 | Linux support: restrict the file and directory to the owner (700/600) through
                          Set-ServiceApiSecureMode.
        1.4.1 | 06OCT26 | Replaced em dashes with ASCII punctuation and reworded the affected
                          sentences, so the source is plain ASCII and loads on Windows PowerShell 5.1.
        1.4.0 | 06OCT26 | Added optional -ProbeEndpoint parameter, persisted to the services.json
                          entry when supplied. Added the three help examples required by the
                          CMF standard.
        1.3.0 | 01OCT26 | Added optional -SSOTenant parameter, persisted to the services.json
                          entry alongside SSOProvider and SSODomain when supplied. Used by the
                          AriaOidc SSO provider.
        1.2.0 | 12AUG26 | Added optional -SSODomain parameter, persisted to the
                          services.json entry alongside SSOProvider when supplied.
        1.1.0 | 17MAY26 | Updated path from module config\ directory to
                          $env:APPDATA\ServiceAPI\ via $script:ServiceApiConfigPath.
        1.0.0 | 16MAY26 | Initial version. Handles merge-write to services.json for
                          persistent service registration via Register-CustomService.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string]$ServiceName,
        [Parameter(Mandatory)][string]$Environment,
        [Parameter(Mandatory)][string]$BaseUrl,
        [string]$SSOProvider,
        [string]$SSODomain,
        [string]$SSOTenant,
        [string]$ProbeEndpoint
    )

    $configDir  = $script:ServiceApiConfigPath
    $configPath = Join-Path -Path $configDir -ChildPath 'services.json'

    # Ensure config directory exists
    if (-not (Test-Path -Path $configDir -PathType Container)) {
        New-Item -Path $configDir -ItemType Directory -Force | Out-Null
        Write-Verbose "ServiceAPI: Created config directory: $configDir"
        Set-ServiceApiSecureMode -Path $configDir
    }

    # Read current file content or start with empty hashtable
    $current = Read-ServiceConfig

    # Ensure service key exists
    if (-not $current.ContainsKey($ServiceName)) {
        $current[$ServiceName] = @{}
    }

    # Build the environment entry
    $entry = @{ BaseUrl = $BaseUrl.TrimEnd('/') }
    if (-not [string]::IsNullOrWhiteSpace($SSOProvider)) {
        $entry['SSOProvider'] = $SSOProvider
    }
    if (-not [string]::IsNullOrWhiteSpace($SSODomain)) {
        $entry['SSODomain'] = $SSODomain
    }
    if (-not [string]::IsNullOrWhiteSpace($SSOTenant)) {
        $entry['SSOTenant'] = $SSOTenant
    }
    if (-not [string]::IsNullOrWhiteSpace($ProbeEndpoint)) {
        $entry['ProbeEndpoint'] = $ProbeEndpoint
    }

    $current[$ServiceName][$Environment] = $entry

    # Write merged result as formatted JSON
    try {
        $current | ConvertTo-Json -Depth 5 |
            Set-Content -LiteralPath $configPath -Encoding UTF8 -Force
        Write-Verbose "ServiceAPI: Persisted service [$ServiceName-$Environment] to: $configPath"
        Set-ServiceApiSecureMode -Path $configPath
    } catch {
        throw "ServiceAPI: Failed to write services.json: $_"
    }
}
