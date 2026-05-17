function Initialise-ServiceConfig {
    <#
    .SYNOPSIS
        Ensures services.json exists and is seeded with default services on first load.

    .DESCRIPTION
        Called once at module load. Checks for the existence of services.json in the
        user's roaming AppData directory ($env:APPDATA\ServiceAPI\). If the file is not
        found, creates the directory if absent and writes a default services.json seeded
        with the predefined Atlassian and OPNsense service entries.

        Storing services.json in AppData ensures it survives module updates and roams
        with the user's Windows profile across machines where the module is installed.

        If the file already exists, this function returns without modification — it never
        overwrites an existing config.

    .NOTES
        Author      : Matthew Sillett
        Organisation: Australian Signals Directorate
        Version     : 1.1.0
        Date        : 17-MAY-26

        CHANGE LOG
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

    # Default seed — predefined services only. User-registered services are added
    # via Register-CustomService -Persistent and stored in the same file.
    $defaults = [ordered]@{
        jira = [ordered]@{
            qa   = [ordered]@{ BaseUrl = 'https://jira.qa.atlassian.therealworld.info/rest' }
            prod = [ordered]@{ BaseUrl = 'https://jira.atlassian.therealworld.info/rest' }
        }
        confluence = [ordered]@{
            qa   = [ordered]@{ BaseUrl = 'https://confluence.qa.atlassian.therealworld.info' }
            prod = [ordered]@{ BaseUrl = 'https://confluence.atlassian.therealworld.info' }
        }
        bitbucket = [ordered]@{
            qa   = [ordered]@{ BaseUrl = 'https://bitbucket.qa.atlassian.therealworld.info' }
            prod = [ordered]@{ BaseUrl = 'https://bitbucket.atlassian.therealworld.info' }
        }
        crowd = [ordered]@{
            qa   = [ordered]@{ BaseUrl = 'https://crowd.qa.atlassian.therealworld.info' }
            prod = [ordered]@{ BaseUrl = 'https://crowd.atlassian.therealworld.info' }
        }
        assets = [ordered]@{
            qa   = [ordered]@{ BaseUrl = 'https://jira.qa.atlassian.therealworld.info' }
            prod = [ordered]@{ BaseUrl = 'https://jira.atlassian.therealworld.info' }
        }
        opnsense = [ordered]@{
            prod = [ordered]@{ BaseUrl = 'https://firewall.smashnet.win/api' }
        }
    }

    try {
        $defaults | ConvertTo-Json -Depth 5 |
            Set-Content -LiteralPath $configPath -Encoding UTF8 -Force
        Write-Verbose "ServiceAPI: Created default services.json at: $configPath"
    } catch {
        Write-Warning "ServiceAPI: Failed to create default services.json — $_"
    }
}
