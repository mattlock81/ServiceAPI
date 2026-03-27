function Get-ServiceConfig {
    <#
    .SYNOPSIS
        Resolves BaseUrl and headers for a service/environment.

    .DESCRIPTION
        Resolves the BaseUrl and headers to be used with REST API requests.
        BaseUrl may come from the supplied BaseUrl parameter or the registered service configuration.

        Headers are built in layers:
        1. New-StandardHeaders
        2. registered DefaultHeaders
        3. credential-derived headers only when Authorization is not already present

        Registered DefaultHeaders are authoritative for overlapping keys. If DefaultHeaders contains
        a non-empty Authorization header, Get-ServiceCredential is skipped. Otherwise, credential-derived
        headers are resolved and only fill missing values.

    .PARAMETER Service
        Service name to resolve.

    .PARAMETER Environment
        Environment to resolve. Defaults to prod.

    .PARAMETER BaseUrl
        Optional direct BaseUrl override. Required if the service/environment is not registered.

    .PARAMETER UseToken
        Used only if credential resolution is needed and Authorization is not already provided by DefaultHeaders.

    .EXAMPLE
        Get-ServiceConfig -Service jira -Environment prod
        Returns resolved configuration for jira in prod.

    .EXAMPLE
        Get-ServiceConfig -Service cloudflare -Environment prod -UseToken
        Returns resolved configuration using token credential resolution when no Authorization header is already registered.

    .EXAMPLE
        Get-ServiceConfig -Service cloudflare -Environment prod -BaseUrl 'https://api.cloudflare.com/client/v4/'
        Returns resolved configuration using the supplied BaseUrl override.

    .NOTES
        Author      : Matthew Sillett
        Organisation: Australian Signals Directorate
        Version     : 2.1.0
        Date        : 28-MAR-26

        CHANGE LOG
        2.1.0 | 28MAR26 | Added registered DefaultHeaders precedence and skipped credential lookup when Authorization is already supplied.
        2.0.0 | 27JAN26 | Refactored from Get-AtlassianConfig to support generalised API services with service registry.
        1.2.0 | 22AUG25 | Added support for custom service with -BaseUrl. Updated validation and examples.
        1.1.5 | 23JUN25 | Added inline comments and enforced early fail for unimplemented -UseSSO flag.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Service,

        [string]$Environment = 'prod',
        [string]$BaseUrl,
        [switch]$UseToken
    )

    try {
        $serviceConfig = $null

        # === Determine the BaseUrl ===
        if ($BaseUrl) {
            # User-provided BaseUrl takes precedence
            Write-Verbose "Using custom BaseUrl: $BaseUrl"
        } elseif ($global:ServiceRegistry.ContainsKey($Service) -and 
                  $global:ServiceRegistry[$Service].ContainsKey($Environment)) {
            # Lookup from service registry
            $serviceConfig = $global:ServiceRegistry[$Service][$Environment]
            $BaseUrl = $serviceConfig.BaseUrl
            Write-Verbose "Resolved BaseUrl from registry: $BaseUrl"
        } else {
            throw "BaseUrl not defined for [$Service] in [$Environment] environment. Provide -BaseUrl or register the service first."
        }

        # === Start with standard headers ===
        $Headers = New-StandardHeaders -Service $Service

        # === Merge registered default headers if present ===
        if ($serviceConfig -and $null -ne $serviceConfig.DefaultHeaders) {
            if ($serviceConfig.DefaultHeaders -isnot [System.Collections.IDictionary]) {
                throw "DefaultHeaders for [$Service] in [$Environment] must be a hashtable or dictionary-compatible object."
            }

            foreach ($key in $serviceConfig.DefaultHeaders.Keys) {
                $Headers[$key] = $serviceConfig.DefaultHeaders[$key]
            }
        }

        # A registered Authorization header suppresses credential lookup for this config-driven request.
        $hasAuthorizationHeader = $false
        foreach ($key in $Headers.Keys) {
            if ([string]::Equals([string]$key, 'Authorization', [System.StringComparison]::OrdinalIgnoreCase) -and
                -not [string]::IsNullOrWhiteSpace([string]$Headers[$key])) {
                $hasAuthorizationHeader = $true
                break
            }
        }

        # === Resolve credential-derived headers and fill any missing values ===
        if (-not $hasAuthorizationHeader) {
            # Credential-derived headers are applied only to keys not already defined by standard/default headers.
            $credentialHeaders = Get-ServiceCredential -Service $Service -Environment $Environment -UseToken:$UseToken

            foreach ($key in $credentialHeaders.Keys) {
                $headerExists = $false

                foreach ($existingKey in $Headers.Keys) {
                    if ([string]::Equals([string]$existingKey, [string]$key, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $headerExists = $true
                        break
                    }
                }

                if (-not $headerExists) {
                    $Headers[$key] = $credentialHeaders[$key]
                }
            }
        } else {
            # DefaultHeaders already provides auth, so credential resolution is skipped.
            Write-Verbose "Using Authorization header from DefaultHeaders; skipping credential resolution."
        }

        # === Return a hashtable with resolved API config ===
        return @{
            Service     = $Service
            Environment = $Environment
            BaseUrl     = $BaseUrl
            Headers     = $Headers
        }
    } catch {
        # Use Debug-Error if available, else fallback to null return
        if (Get-Command -Name Debug-Error -ErrorAction SilentlyContinue) {
            Debug-Error -ErrorRecord $_ -Severity 'Critical'
        } else {
            Write-Error $_
        }
        return $null
    }
}
