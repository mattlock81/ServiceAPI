# ServiceAPI.psm1

# ==============================
# ServiceAPI PowerShell Module
# ==============================
# Version: 2.1.1
# Author: Matthew Sillett
# Organisation: Australian Signals Directorate
# Date: 2026-01-27

# ==============================
# Phase 0: Dependency Import
# ==============================
# Detect SysCommon / Debug-Error once at import time and cache the result for later handled-error reporting.
$script:ServiceApiHasDebugError = $false
$serviceApiDebugErrorWarning = "SysCommon / Debug-Error was not found. ServiceAPI will fall back to basic local error handling."

try {
    if (-not (Get-Module -Name SysCommon -ErrorAction SilentlyContinue)) {
        Import-Module SysCommon -DisableNameChecking -Force -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
    }
} catch {
    # Continue loading without SysCommon; handled-error reporting will use local fallback.
}

$script:ServiceApiHasDebugError = $null -ne (Get-Command -Name Debug-Error -ErrorAction SilentlyContinue)
if (-not $script:ServiceApiHasDebugError) {
    Write-Warning $serviceApiDebugErrorWarning
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

# Export only public functions after all module functions have been dot-sourced.
$publicFunctions = if (Test-Path -Path $script:PublicFunctionsPath -PathType Container) {
    Get-ChildItem -Path $script:PublicFunctionsPath -Filter "*.ps1" -File | ForEach-Object {
        $content = Get-Content -LiteralPath $_.FullName -Raw
        if ($content -match 'function\s+([A-Za-z0-9\-_]+)\s*\{') {
            $matches[1]
        }
    }
} else {
    @()
}
Export-ModuleMember -Function $publicFunctions

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

Write-Verbose "ServiceAPI module loaded (v2.1.1)"
