function Initialise-ServiceConfig {
    <#
    .SYNOPSIS
        Ensures services.json exists on first load with an empty service registry.

    .DESCRIPTION
        Called once at module load. Checks for the existence of services.json in the
        user's roaming AppData directory ($env:APPDATA\ServiceAPI\). If the file is not
        found, creates the directory if absent and writes an empty services.json.

        No default services are seeded. All services must be registered by the caller
        using Register-CustomService -Persistent, or by manually editing services.json.

        Storing services.json in AppData ensures it survives module updates and roams
        with the user's Windows profile across machines where the module is installed.

        If the file already exists, this function returns without modification — it never
        overwrites an existing config.

    .NOTES
        Author  : Matthew Sillett
        Version : 1.2.0
        Date    : 18-MAY-26

        CHANGE LOG
        1.2.0 | 18MAY26 | Removed default service seed. services.json is now initialised
                          as an empty registry. All services must be registered via
                          Register-CustomService or manual JSON editing. Removed
                          organisation field from header.
        1.1.0 | 17MAY26 | Moved services.json from module config\ directory to
                          $env:APPDATA\ServiceAPI\ so module updates do not overwrite
                          user configuration. Path now sourced from $script:ServiceApiConfigPath.
        1.0.1 | 17MAY26 | Renamed from Initialize-ServiceConfig to Initialise-ServiceConfig
                          to conform to Australian/British English spelling conventions.
        1.0.0 | 16MAY26 | Initial version. Provides first-load auto-creation of services.json
                          seeded with predefined services, replacing hardcoded registry in psm1.
    #>

    [CmdletBinding()]
    param()

    $configDir  = $script:ServiceApiConfigPath
    $configPath = Join-Path -Path $configDir -ChildPath 'services.json'

    # File already exists — nothing to do
    if (Test-Path -Path $configPath -PathType Leaf) {
        Write-Verbose "ServiceAPI: services.json found at: $configPath"
        return
    }

    # Create config directory if absent
    if (-not (Test-Path -Path $configDir -PathType Container)) {
        New-Item -Path $configDir -ItemType Directory -Force | Out-Null
        Write-Verbose "ServiceAPI: Created config directory: $configDir"
    }

    # Empty registry — no default services seeded. Register services via
    # Register-CustomService -Persistent or by editing services.json directly.
    $empty = [ordered]@{}

    try {
        $empty | ConvertTo-Json -Depth 5 |
            Set-Content -LiteralPath $configPath -Encoding UTF8 -Force
        Write-Verbose "ServiceAPI: Created empty services.json at: $configPath"
    } catch {
        Write-Warning "ServiceAPI: Failed to create services.json — $_"
    }
}
