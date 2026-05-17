# ServiceAPI.psm1

# ==============================
# ServiceAPI PowerShell Module
# ==============================
# Version: 2.3.0
# Author: Matthew Sillett
# Organisation: Australian Signals Directorate
# Date: 2026-05-16

# ==============================
# Phase 0: Dependency Import
# ==============================
# Detect SysCommon / Debug-Error once at import time and cache the result.
$script:ServiceApiHasDebugError  = $false
$serviceApiDebugErrorWarning     = "SysCommon / Debug-Error was not found. ServiceAPI will fall back to basic local error handling."

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
# Phase 0.5: Detect and Import SecretManagement
# ==============================
# Mirrors the SysCommon detection pattern. Uses ListAvailable to confirm the module
# is installed before attempting import. Flag is only set on confirmed successful import.
# All vault logic is bypassed silently when the module is not available.
$script:ServiceApiHasSecretManagement = $false

if (Get-Module -Name Microsoft.PowerShell.SecretManagement -ListAvailable) {
    try {
        if (-not (Get-Module -Name Microsoft.PowerShell.SecretManagement)) {
            Import-Module Microsoft.PowerShell.SecretManagement -DisableNameChecking -Force -ErrorAction Stop | Out-Null
        }
        $script:ServiceApiHasSecretManagement = $true
        Write-Verbose "ServiceAPI: SecretManagement detected and imported — vault credential resolution enabled."
    } catch {
        Write-Verbose "ServiceAPI: SecretManagement available but failed to import — vault credential resolution disabled."
    }
} else {
    Write-Verbose "ServiceAPI: SecretManagement not available — vault credential resolution disabled."
}

# ==============================
# Phase 1: Define Module Paths
# ==============================
$script:ModuleRoot          = $PSScriptRoot
$script:FunctionsPath       = Join-Path -Path $script:ModuleRoot -ChildPath 'Functions'
$script:PrivateFunctionsPath = Join-Path -Path $script:FunctionsPath -ChildPath 'Private'
$script:PublicFunctionsPath  = Join-Path -Path $script:FunctionsPath -ChildPath 'Public'

if (-not (Test-Path -Path $script:FunctionsPath -PathType Container)) {
    Write-Error "Functions directory not found: $script:FunctionsPath"
    return
}

# ==============================
# Phase 2: Load Private Functions
# ==============================
if (Test-Path -Path $script:PrivateFunctionsPath -PathType Container) {
    Get-ChildItem -Path $script:PrivateFunctionsPath -Filter '*.ps1' -File | ForEach-Object {
        . $_.FullName
        Write-Verbose "Loaded private: $($_.BaseName)"
    }
}

# ==============================
# Phase 3: Load Public Functions
# ==============================
if (Test-Path -Path $script:PublicFunctionsPath -PathType Container) {
    Get-ChildItem -Path $script:PublicFunctionsPath -Filter '*.ps1' -File | ForEach-Object {
        . $_.FullName
        Write-Verbose "Loaded public: $($_.BaseName)"
    }
}

# Export only public functions after all module functions have been dot-sourced.
$publicFunctions = if (Test-Path -Path $script:PublicFunctionsPath -PathType Container) {
    Get-ChildItem -Path $script:PublicFunctionsPath -Filter '*.ps1' -File | ForEach-Object {
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
# Phase 4: Initialise Global State
# ==============================
# Credential and token stores — always start empty for security.
# Services are populated in Phase 5 from services.json, not hardcoded here.
$global:ServiceCredentials  = @{}
$global:ServiceTokens       = @{}
$global:ServiceSSOTokens    = @{}
$global:ServiceRegistry     = @{}
$global:RegisteredServices  = @()
$global:ServiceApiVaultIndex = @{}

# ==============================
# Phase 4.5: Initialise Vault Index
# ==============================
# Only runs when SecretManagement is detected. Creates credential-index.json if absent
# and loads the index into $global:ServiceApiVaultIndex for use during credential resolution.
if ($script:ServiceApiHasSecretManagement) {
    Initialise-VaultIndex
    $global:ServiceApiVaultIndex = Read-VaultIndex
    Write-Verbose "ServiceAPI: Vault index loaded ($($global:ServiceApiVaultIndex.Count) service key(s))."
}

# ==============================
# Phase 5: Load Service Registry from Config
# ==============================
# Ensures services.json exists (creates and seeds defaults on first load),
# then reads all entries and registers them into the global service registry.
# This replaces the previously hardcoded $global:ServiceRegistry hashtable.

Initialise-ServiceConfig

$persistedServices = Read-ServiceConfig

foreach ($serviceName in $persistedServices.Keys) {
    foreach ($env in $persistedServices[$serviceName].Keys) {
        $entry = $persistedServices[$serviceName][$env]

        $regParams = @{
            ServiceName = $serviceName
            BaseUrl     = $entry.BaseUrl
            Environment = $env
            Force       = $true
        }

        if ($entry.ContainsKey('SSOProvider') -and -not [string]::IsNullOrWhiteSpace($entry.SSOProvider)) {
            $regParams['SSOProvider'] = $entry.SSOProvider
        }

        Register-CustomService @regParams
        Write-Verbose "Loaded service [$serviceName-$env] from services.json."
    }
}

Write-Verbose "ServiceAPI: Loaded $($global:RegisteredServices.Count) service(s) from registry."

# ==============================
# Phase 6: Cleanup on Exit
# ==============================
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    Remove-Variable -Name ServiceCredentials, ServiceTokens, ServiceSSOTokens, `
                         ServiceRegistry, RegisteredServices, ServiceApiVaultIndex `
                    -Scope Global -ErrorAction SilentlyContinue
} -SupportEvent

Write-Verbose "ServiceAPI module loaded (v2.4.0)"
