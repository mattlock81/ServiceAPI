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

        If the file already exists, this function returns without modification; it never
        overwrites an existing config.

    .OUTPUTS
        None. Creates services.json as a side effect when it is absent.

    .EXAMPLE
        & (Get-Module ServiceAPI) { Initialise-ServiceConfig }

        Creates an empty services.json in $env:APPDATA\ServiceAPI\ when none exists, and returns
        without change when one does. The function is private, so it is run from module scope.

    .EXAMPLE
        & (Get-Module ServiceAPI) { Initialise-ServiceConfig -Verbose }

        Shows in the verbose stream whether the directory and file were created or already present.

    .EXAMPLE
        Test-Path (Join-Path $env:APPDATA 'ServiceAPI\services.json')

        Confirms the registry file exists after the module has loaded. Expected result: True.

    .NOTES
        Author  : Matthew Sillett
        Version : 1.3.0
        Date    : 08-OCT-26

        CHANGE LOG
        1.3.0 | 08OCT26 | Linux support: restrict the file and directory to the owner (700/600) through
                          Set-ServiceApiSecureMode.
        1.2.3 | 07OCT26 | File renamed from InitializeServiceConfig.ps1 to InitialiseServiceConfig.ps1
                          so the file name matches the function name and the Australian/British
                          spelling convention. No code change.
        1.2.2 | 06OCT26 | Replaced em dashes with ASCII punctuation and reworded the affected
                          sentences, so the source is plain ASCII and loads on Windows PowerShell 5.1.
        1.2.1 | 06OCT26 | Added the help examples and .OUTPUTS required by the CMF standard.
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

    # File already exists; nothing to do
    if (Test-Path -Path $configPath -PathType Leaf) {
        Write-Verbose "ServiceAPI: services.json found at: $configPath"
        return
    }

    # Create config directory if absent
    if (-not (Test-Path -Path $configDir -PathType Container)) {
        New-Item -Path $configDir -ItemType Directory -Force | Out-Null
        Write-Verbose "ServiceAPI: Created config directory: $configDir"
        Set-ServiceApiSecureMode -Path $configDir
    }

    # Empty registry: no default services seeded. Register services via
    # Register-CustomService -Persistent or by editing services.json directly.
    $empty = [ordered]@{}

    try {
        $empty | ConvertTo-Json -Depth 5 |
            Set-Content -LiteralPath $configPath -Encoding UTF8 -Force
        Write-Verbose "ServiceAPI: Created empty services.json at: $configPath"
        Set-ServiceApiSecureMode -Path $configPath
    } catch {
        Write-Warning "ServiceAPI: Failed to create services.json: $_"
    }
}
