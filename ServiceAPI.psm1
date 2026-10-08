# ServiceAPI.psm1

# ==============================
# ServiceAPI PowerShell Module
# ==============================
# Version: 3.0.0
# Author: Matthew Sillett
# Date: 2026-10-08

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
        Write-Verbose "ServiceAPI: SecretManagement detected and imported; vault credential resolution enabled."
    } catch {
        Write-Verbose "ServiceAPI: SecretManagement available but failed to import; vault credential resolution disabled."
    }
} else {
    Write-Verbose "ServiceAPI: SecretManagement not available; vault credential resolution disabled."
}

# ==============================
# Phase 0.6: Detect Platform
# ==============================
# $IsWindows, $IsLinux and $IsMacOS do not exist in Windows PowerShell 5.1, which runs on
# Windows only, so an absent $IsWindows means Windows. Supported platforms are Windows and
# Linux. RHEL-family Linux (RHEL, AlmaLinux, Rocky, Fedora, CentOS, Oracle Linux) is the
# tested target; other Linux distributions load with a warning. Anything else is refused.
$script:ServiceApiIsWindows = if (Test-Path -Path Variable:\IsWindows) { [bool]$IsWindows } else { $true }
$script:ServiceApiIsLinux   = (-not $script:ServiceApiIsWindows) -and
                              (Test-Path -Path Variable:\IsLinux) -and [bool]$IsLinux
$script:ServiceApiOsId      = ''
$script:ServiceApiOsIdLike  = ''
$script:ServiceApiIsRhelFamily = $false

if ($script:ServiceApiIsWindows) {
    $script:ServiceApiPlatform = 'Windows'
} elseif ($script:ServiceApiIsLinux) {
    $script:ServiceApiPlatform = 'Linux'
    $serviceApiOsRelease = '/etc/os-release'
    if (Test-Path -LiteralPath $serviceApiOsRelease -PathType Leaf) {
        foreach ($serviceApiLine in (Get-Content -LiteralPath $serviceApiOsRelease -ErrorAction SilentlyContinue)) {
            if ($serviceApiLine -match '^\s*(ID|ID_LIKE)\s*=\s*"?([^"]*)"?\s*$') {
                if ($Matches[1] -eq 'ID')      { $script:ServiceApiOsId     = $Matches[2].Trim().ToLowerInvariant() }
                if ($Matches[1] -eq 'ID_LIKE') { $script:ServiceApiOsIdLike = $Matches[2].Trim().ToLowerInvariant() }
            }
        }
    }
    $serviceApiRhelIds = @('rhel', 'fedora', 'centos', 'almalinux', 'rocky', 'ol')
    $serviceApiOsTokens = @($script:ServiceApiOsId) + @($script:ServiceApiOsIdLike -split '\s+') |
        Where-Object { $_ }
    $script:ServiceApiIsRhelFamily = [bool]($serviceApiOsTokens | Where-Object { $serviceApiRhelIds -contains $_ })
    if (-not $script:ServiceApiIsRhelFamily) {
        Write-Warning ("ServiceAPI is tested on RHEL-family Linux. Detected '{0}'; loading anyway." -f
            $(if ($script:ServiceApiOsId) { $script:ServiceApiOsId } else { 'unknown distribution' }))
    }
} else {
    throw 'ServiceAPI supports Windows and Linux only. This platform is not supported.'
}
Write-Verbose "ServiceAPI: platform $script:ServiceApiPlatform (id '$script:ServiceApiOsId', RHEL family: $script:ServiceApiIsRhelFamily)."

# ==============================
# Phase 1: Define Module Paths
# ==============================
$script:ModuleRoot           = $PSScriptRoot
# Folder names are case-sensitive on Linux: match the on-disk names exactly.
$script:FunctionsPath        = Join-Path -Path $script:ModuleRoot -ChildPath 'functions'
$script:PrivateFunctionsPath = Join-Path -Path $script:FunctionsPath -ChildPath 'Private'
$script:PublicFunctionsPath  = Join-Path -Path $script:FunctionsPath -ChildPath 'Public'

# User data paths: outside the module directory so updates never overwrite user config.
# Windows: services.json roams with the user profile; the vault index is machine-local.
# Linux: XDG base directories (config for services.json, data for the vault index).
if ($script:ServiceApiIsWindows) {
    $serviceApiConfigRoot = $env:APPDATA
    $serviceApiDataRoot   = $env:LOCALAPPDATA
} else {
    $serviceApiHome = if ($env:HOME) { $env:HOME } else { [Environment]::GetFolderPath('UserProfile') }
    $serviceApiConfigRoot = if ($env:XDG_CONFIG_HOME) { $env:XDG_CONFIG_HOME } else { Join-Path -Path $serviceApiHome -ChildPath '.config' }
    $serviceApiDataRoot   = if ($env:XDG_DATA_HOME)   { $env:XDG_DATA_HOME }   else { Join-Path -Path $serviceApiHome -ChildPath '.local/share' }
}
$script:ServiceApiConfigPath     = Join-Path -Path $serviceApiConfigRoot -ChildPath 'ServiceAPI'
# credential-index.json is machine-local, consistent with the SecretManagement vault store
$script:ServiceApiVaultIndexPath = Join-Path -Path $serviceApiDataRoot -ChildPath 'ServiceAPI'

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
# Credential and token stores: always start empty for security.
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

        if ($entry.ContainsKey('SSODomain') -and -not [string]::IsNullOrWhiteSpace($entry.SSODomain)) {
            $regParams['SSODomain'] = $entry.SSODomain
        }

        if ($entry.ContainsKey('SSOTenant') -and -not [string]::IsNullOrWhiteSpace($entry.SSOTenant)) {
            $regParams['SSOTenant'] = $entry.SSOTenant
        }

        if ($entry.ContainsKey('ProbeEndpoint') -and -not [string]::IsNullOrWhiteSpace($entry.ProbeEndpoint)) {
            $regParams['ProbeEndpoint'] = $entry.ProbeEndpoint
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

Write-Verbose "ServiceAPI module loaded (v2.10.4)"
