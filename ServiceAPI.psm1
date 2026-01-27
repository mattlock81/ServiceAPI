# ServiceAPI.psm1

# ==============================
# ServiceAPI PowerShell Module
# ==============================
# Version: 2.0.0
# Author: Matthew Sillett
# Organisation: Australian Signals Directorate
# Date: 2026-01-27

# ==============================
# Phase 0: Dependency Import
# ==============================
try {
    if (-not (Get-Module -Name SYSCommon)) {
        Import-Module SYSCommon -DisableNameChecking -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        if (-not (Get-Module -Name SYSCommon)) {
            Write-Warning "SYSCommon module not available. Debug-Error functionality will be limited."
        }
    }
} catch {
    Write-Warning "SYSCommon module not available. Debug-Error functionality will be limited."
}

# ==============================
# Phase 1: Define Module Paths
# ==============================
$script:ModuleRoot = $PSScriptRoot
$script:FunctionsPath = Join-Path -Path $script:ModuleRoot -ChildPath "Functions"
$script:PrivateFunctionsPath = Join-Path -Path $script:FunctionsPath -ChildPath "Private"
$script:PublicFunctionsPath = Join-Path -Path $script:FunctionsPath -ChildPath "Public"

if (-not (Test-Path -Path $script:FunctionsPath -PathType Container)) {
    Write-Error "Functions directory not found: $script:FunctionsPath"
    return
}

# ==============================
# Phase 2: Load Private Functions
# ==============================
if (Test-Path -Path $script:PrivateFunctionsPath -PathType Container) {
    Get-ChildItem -Path $script:PrivateFunctionsPath -Filter "*.ps1" -File | ForEach-Object {
        . $_.FullName
        Write-Verbose "Loaded: $($_.BaseName)"
    }
}

# ==============================
# Phase 3: Load Public Functions
# ==============================
if (Test-Path -Path $script:PublicFunctionsPath -PathType Container) {
    Get-ChildItem -Path $script:PublicFunctionsPath -Filter "*.ps1" -File | ForEach-Object {
        . $_.FullName
        Write-Verbose "Loaded: $($_.BaseName)"
    }
}

# ==============================
# Phase 4: Global Variables
# ==============================
$global:ServiceCredentials = @{}
$global:ServiceTokens = @{}
$global:ServiceSSOTokens = @{}

# Service registry with predefined services
$global:ServiceRegistry = @{
    jira = @{
        qa = @{ BaseUrl = 'https://jira.qa.atlassian.therealworld.info/rest' }
        prod = @{ BaseUrl = 'https://jira.atlassian.therealworld.info/rest' }
    }
    confluence = @{
        qa = @{ BaseUrl = 'https://confluence.qa.atlassian.therealworld.info' }
        prod = @{ BaseUrl = 'https://confluence.atlassian.therealworld.info' }
    }
    bitbucket = @{
        qa = @{ BaseUrl = 'https://bitbucket.qa.atlassian.therealworld.info' }
        prod = @{ BaseUrl = 'https://bitbucket.atlassian.therealworld.info' }
    }
    crowd = @{
        qa = @{ BaseUrl = 'https://crowd.qa.atlassian.therealworld.info' }
        prod = @{ BaseUrl = 'https://crowd.atlassian.therealworld.info' }
    }
    assets = @{
        qa = @{ BaseUrl = 'https://jira.qa.atlassian.therealworld.info' }
        prod = @{ BaseUrl = 'https://jira.atlassian.therealworld.info' }
    }
    opnsense = @{
        prod = @{ BaseUrl = 'https://firewall.smashnet.win/api' }
    }
}

$global:RegisteredServices = @('jira', 'confluence', 'bitbucket', 'crowd', 'assets', 'opnsense')

# ==============================
# Phase 5: Cleanup on Exit
# ==============================
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    Remove-Variable -Name ServiceCredentials, ServiceTokens, ServiceSSOTokens, ServiceRegistry, RegisteredServices -Scope Global -ErrorAction SilentlyContinue
} -SupportEvent

Write-Verbose "ServiceAPI module loaded (v2.0.0)"
