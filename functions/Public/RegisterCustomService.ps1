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

        When -Persistent is specified, the registration is written to config\services.json in
        the module directory. Persistent registrations are loaded automatically on next module
        import and reflected immediately in tab completion for -Service parameters across all
        module functions.

        When -Persistent is not specified, the registration is session-only and lost on module
        reload.

        Supported SSO providers: GCloud, AzureCLI, Aria.

    .PARAMETER ServiceName
        The name to identify the service (e.g., custom-api, github, googleapi).
        Supports tab completion from currently registered services.

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
        Accepted values: GCloud, AzureCLI, Aria.

    .PARAMETER SSODomain
        Optional. Only meaningful when -SSOProvider is 'Aria'. The domain to submit
        alongside the username during the Aria CSP token exchange. When omitted, the
        domain of a domain-joined system is used automatically at request time — set this
        explicitly for non-domain-joined systems (e.g. a personal dev machine).

    .PARAMETER Persistent
        When specified, writes the registration to config\services.json so it is restored
        on next module import. When omitted, the registration is session-only.

    .PARAMETER Force
        Overwrite existing service registration without confirmation.

    .EXAMPLE
        Register-CustomService -ServiceName github -BaseUrl 'https://api.github.com'
        Registers GitHub API for prod (session-only).

    .EXAMPLE
        Register-CustomService -ServiceName googleapi -BaseUrl 'https://gmail.googleapis.com' -SSOProvider GCloud -Persistent
        Registers the Google API for prod with GCloud SSO provider and persists to services.json.

    .EXAMPLE
        Register-CustomService -ServiceName azuredevops -BaseUrl 'https://dev.azure.com' -SSOProvider AzureCLI -Persistent
        Registers Azure DevOps for prod with AzureCLI SSO provider and persists to services.json.

    .EXAMPLE
        Register-CustomService -ServiceName internal-api -BaseUrl 'https://api.internal.com/v2' -Environment dev
        Registers an internal API for dev environment (session-only, no SSO provider).

    .NOTES
        Author      : Matthew Sillett
        Version     : 2.4.0
        Date        : 12-AUG-26

        CHANGE LOG
        2.4.0 | 12AUG26 | Added 'Aria' to the -SSOProvider ValidateSet. Added optional
                          -SSODomain parameter, stored in the in-memory registry entry
                          and persisted to services.json via Write-ServiceConfig when
                          -Persistent is specified.
        2.3.0 | 16MAY26 | Added -Persistent switch to write registrations to config\services.json.
                          Added [ArgumentCompleter] on -ServiceName for tab completion from live
                          registry. Persistent registrations are loaded on next module import.
        2.2.0 | 16MAY26 | Added -SSOProvider parameter to associate a default SSO provider with
                          a service registration.
        1.0.0 | 27JAN26 | Initial version.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ArgumentCompleter({
            param($cmd, $param, $word, $ast, $fakeBound)
            if ($global:RegisteredServices) {
                $global:RegisteredServices |
                    Where-Object { $_ -like "$word*" } |
                    ForEach-Object {
                        [System.Management.Automation.CompletionResult]::new(
                            $_, $_, 'ParameterValue', $_
                        )
                    }
            }
        })]
        [string]$ServiceName,

        [Parameter(Mandatory)]
        [string]$BaseUrl,

        [string]$Environment = 'prod',

        [hashtable]$DefaultHeaders = @{
            'Accept'       = 'application/json'
            'Content-Type' = 'application/json'
        },

        [ValidateSet('GCloud', 'AzureCLI', 'Aria')]
        [string]$SSOProvider,

        [string]$SSODomain,

        [switch]$Persistent,
        [switch]$Force
    )

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
        $global:ServiceRegistry[$ServiceName] = @{}
    }

    # Build the in-memory registry entry
    $entry = @{
        BaseUrl        = $BaseUrl.TrimEnd('/')
        DefaultHeaders = $DefaultHeaders
    }

    if ($SSOProvider) {
        $entry['SSOProvider'] = $SSOProvider
        Write-Verbose "SSO provider [$SSOProvider] registered for [$ServiceName-$Environment]."
    }

    if ($SSODomain) {
        if ($SSOProvider -ne 'Aria') {
            Write-Warning "-SSODomain is only used by the Aria SSO provider and will be stored but ignored for provider [$SSOProvider]."
        }
        $entry['SSODomain'] = $SSODomain
        Write-Verbose "SSO domain [$SSODomain] registered for [$ServiceName-$Environment]."
    }

    $global:ServiceRegistry[$ServiceName][$Environment] = $entry

    if ($ServiceName -notin $global:RegisteredServices) {
        $global:RegisteredServices += $ServiceName
    }

    Write-Verbose "Registered service [$ServiceName] for [$Environment] with BaseUrl: $($entry.BaseUrl)"

    # Write to services.json when -Persistent is specified
    if ($Persistent) {
        $writeParams = @{
            ServiceName = $ServiceName
            Environment = $Environment
            BaseUrl     = $entry.BaseUrl
        }
        if ($SSOProvider) { $writeParams['SSOProvider'] = $SSOProvider }
        if ($SSODomain)   { $writeParams['SSODomain']   = $SSODomain }

        Write-ServiceConfig @writeParams
        Write-Verbose "Persisted [$ServiceName-$Environment] to services.json."
    }
}
