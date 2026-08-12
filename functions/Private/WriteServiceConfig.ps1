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
        in-memory registry state — that is managed by Register-CustomService directly.

    .PARAMETER ServiceName
        The service name key to write (e.g., google, jira).

    .PARAMETER Environment
        The environment key to write under the service (e.g., prod, qa).

    .PARAMETER BaseUrl
        The base URL to persist for this service/environment.

    .PARAMETER SSOProvider
        Optional. The SSO provider string to persist (e.g., GCloud, AzureCLI, Aria).

    .PARAMETER SSODomain
        Optional. The domain string to persist for the Aria SSO provider.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.2.0
        Date        : 12-AUG-26

        CHANGE LOG
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
        [string]$SSODomain
    )

    $configDir  = $script:ServiceApiConfigPath
    $configPath = Join-Path -Path $configDir -ChildPath 'services.json'

    # Ensure config directory exists
    if (-not (Test-Path -Path $configDir -PathType Container)) {
        New-Item -Path $configDir -ItemType Directory -Force | Out-Null
        Write-Verbose "ServiceAPI: Created config directory: $configDir"
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

    $current[$ServiceName][$Environment] = $entry

    # Write merged result as formatted JSON
    try {
        $current | ConvertTo-Json -Depth 5 |
            Set-Content -LiteralPath $configPath -Encoding UTF8 -Force
        Write-Verbose "ServiceAPI: Persisted service [$ServiceName-$Environment] to: $configPath"
    } catch {
        throw "ServiceAPI: Failed to write services.json — $_"
    }
}
