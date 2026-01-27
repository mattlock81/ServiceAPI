function Register-CustomService {
    <#
    .SYNOPSIS
        Registers a custom API service in the service registry for use with Invoke-APIRequest.

    .DESCRIPTION
        Allows registration of custom API services that are not predefined in the module.
        Once registered, the service can be used with all module functions without requiring -BaseUrl each time.
        Supports multiple environments per service.

    .PARAMETER ServiceName
        The name to identify the service (e.g., custom-api, github, gitlab).

    .PARAMETER BaseUrl
        The base URL for the API endpoint.

    .PARAMETER Environment
        The environment name: qa, prod, dev, or custom. Defaults to prod.

    .PARAMETER DefaultHeaders
        Optional hashtable of default headers to include with requests to this service.

    .PARAMETER Force
        Overwrite existing service registration without confirmation.

    .EXAMPLE
        Register-CustomService -ServiceName github -BaseUrl "https://api.github.com"
        # Registers GitHub API for prod environment

    .EXAMPLE
        Register-CustomService -ServiceName internal-api -BaseUrl "https://api.internal.com/v2" -Environment dev
        # Registers internal API for dev environment

    .EXAMPLE
        $headers = @{ "X-Custom-Auth" = "Bearer token123" }
        Register-CustomService -ServiceName custom-api -BaseUrl "https://custom.com/api" -DefaultHeaders $headers
        # Registers with custom default headers

    .NOTES
        Author      : Matthew Sillett
        Organisation: Australian Signals Directorate
        Version     : 1.0.0
        Date        : 27-JAN-26

        CHANGE LOG
        1.0.0 | 27JAN26 | Initial version to support custom service registration in service registry.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$ServiceName,
        
        [Parameter(Mandatory)]
        [string]$BaseUrl,
        
        [string]$Environment = 'prod',
        
        [hashtable]$DefaultHeaders = @{
            "Accept"       = "application/json"
            "Content-Type" = "application/json"
        },

        [switch]$Force
    )

    # Validate BaseUrl format
    if ($BaseUrl -notmatch '^https?://') {
        throw "BaseUrl must start with http:// or https://"
    }

    # Check if service already exists
    if ($global:ServiceRegistry.ContainsKey($ServiceName)) {
        if ($global:ServiceRegistry[$ServiceName].ContainsKey($Environment)) {
            if (-not $Force) {
                $confirm = Read-Host "Service [$ServiceName] in [$Environment] already exists. Overwrite? (Y/N)"
                if ($confirm -ne 'Y') { return }
            }
        }
    } else {
        # Create new service entry
        $global:ServiceRegistry[$ServiceName] = @{}
    }

    # Register the service with environment
    $global:ServiceRegistry[$ServiceName][$Environment] = @{
        BaseUrl        = $BaseUrl.TrimEnd('/')
        DefaultHeaders = $DefaultHeaders
    }

    # Add to registered services list if not already present
    if ($ServiceName -notin $global:RegisteredServices) {
        $global:RegisteredServices += $ServiceName
    }

    Write-Verbose "Registered service [$ServiceName] for [$Environment] environment with BaseUrl: $BaseUrl"
}
