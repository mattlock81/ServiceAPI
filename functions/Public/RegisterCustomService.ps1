function Register-CustomService {
    <#
    .SYNOPSIS
        Registers a custom API service in the service registry for use with Invoke-APIRequest.

    .DESCRIPTION
        Allows registration of custom API services that are not predefined in the module.
        Once registered, the service can be used with all module functions without requiring
        -BaseUrl each time. Supports multiple environments per service.

        An optional -SSOProvider parameter associates a default SSO provider with the service
        registration. When present, Invoke-APIRequest called with -UseSSO will use this provider
        for automatic token acquisition and refresh without requiring the caller to specify
        the provider on every request.

        Supported SSO providers: GCloud, AzureCLI.

    .PARAMETER ServiceName
        The name to identify the service (e.g., custom-api, github, googleapi).

    .PARAMETER BaseUrl
        The base URL for the API endpoint.

    .PARAMETER Environment
        The environment name: qa, prod, dev, or custom. Defaults to prod.

    .PARAMETER DefaultHeaders
        Optional hashtable of default headers to include with requests to this service.

    .PARAMETER SSOProvider
        Optional. Associates a default SSO provider with this service registration.
        When specified, -UseSSO calls against this service will use this provider for
        token acquisition and refresh without requiring the provider to be named on each call.
        Accepted values: GCloud, AzureCLI.

    .PARAMETER Force
        Overwrite existing service registration without confirmation.

    .EXAMPLE
        Register-CustomService -ServiceName github -BaseUrl 'https://api.github.com'
        Registers GitHub API for prod environment with no SSO provider.

    .EXAMPLE
        Register-CustomService -ServiceName googleapi -BaseUrl 'https://gmail.googleapis.com' -SSOProvider GCloud
        Registers the Google API for prod environment with GCloud as the default SSO provider.

    .EXAMPLE
        Register-CustomService -ServiceName azuredevops -BaseUrl 'https://dev.azure.com' -Environment prod -SSOProvider AzureCLI
        Registers Azure DevOps for prod environment with AzureCLI as the default SSO provider.

    .EXAMPLE
        Register-CustomService -ServiceName internal-api -BaseUrl 'https://api.internal.com/v2' -Environment dev
        Registers an internal API for dev environment with no SSO provider.

    .NOTES
        Author      : Matthew Sillett
        Organisation: Australian Signals Directorate
        Version     : 2.2.0
        Date        : 16-MAY-26

        CHANGE LOG
        2.2.0 | 16MAY26 | Added -SSOProvider parameter to associate a default SSO provider with a
                          service registration, enabling automatic token resolution via -UseSSO.
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
            'Accept'       = 'application/json'
            'Content-Type' = 'application/json'
        },

        [ValidateSet('GCloud', 'AzureCLI')]
        [string]$SSOProvider,

        [switch]$Force
    )

    # Validate BaseUrl format
    if ($BaseUrl -notmatch '^https?://') {
        throw "BaseUrl must start with http:// or https://"
    }

    # Check for existing registration and confirm overwrite unless -Force is specified
    if ($global:ServiceRegistry.ContainsKey($ServiceName)) {
        if ($global:ServiceRegistry[$ServiceName].ContainsKey($Environment)) {
            if (-not $Force) {
                $confirm = Read-Host "Service [$ServiceName] in [$Environment] already exists. Overwrite? (Y/N)"
                if ($confirm -ne 'Y') { return }
            }
        }
    } else {
        # Initialise new service entry
        $global:ServiceRegistry[$ServiceName] = @{}
    }

    # Build the service environment registration entry
    $entry = @{
        BaseUrl        = $BaseUrl.TrimEnd('/')
        DefaultHeaders = $DefaultHeaders
    }

    # Store the SSO provider if supplied — used by Get-ServiceCredential for automatic token dispatch
    if ($SSOProvider) {
        $entry.SSOProvider = $SSOProvider
        Write-Verbose "SSO provider [$SSOProvider] registered for [$ServiceName] in [$Environment]."
    }

    $global:ServiceRegistry[$ServiceName][$Environment] = $entry

    # Add to registered services list if not already present
    if ($ServiceName -notin $global:RegisteredServices) {
        $global:RegisteredServices += $ServiceName
    }

    Write-Verbose "Registered service [$ServiceName] for [$Environment] environment with BaseUrl: $($entry.BaseUrl)"
}
