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

        Supported SSO providers: GCloud, AzureCLI, Aria, AriaOidc.

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
        Accepted values: GCloud, AzureCLI, Aria, AriaOidc.

    .PARAMETER SSODomain
        Optional. Only meaningful when -SSOProvider is 'Aria'. The domain to submit
        alongside the username during the Aria CSP token exchange. When omitted, the
        domain of a domain-joined system is used automatically at request time; set this
        explicitly for non-domain-joined systems (e.g. a personal dev machine).

    .PARAMETER SSOTenant
        Optional. Only meaningful when -SSOProvider is 'AriaOidc'. The Aria tenant name, as it
        appears after 'service=tenant:' in the portal login redirect. Required by the AriaOidc
        provider to open the correct tenant portal during browser login.

    .PARAMETER ProbeEndpoint
        Optional. A relative endpoint (for example 'iaas/api/projects?$top=1') that returns 2xx
        for any valid bearer the identity may use at all. The module sends a bearer here to tell
        a stale token from an authorisation denial when a request returns HTTP 403, and to choose
        which candidate bearer to use at AriaOidc login. A leading '/' is trimmed. The AriaOidc
        provider defaults to 'iaas/api/projects?$top=1' when this is omitted; other providers
        have no default, and the 403 retry then falls back to refreshing the token.

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

    .EXAMPLE
        Register-CustomService -ServiceName aria -BaseUrl 'https://aria.example.com' -SSOProvider AriaOidc -SSOTenant 'my-tenant' -ProbeEndpoint 'iaas/api/projects?$top=1' -Persistent
        Registers an Aria service and names the cheap read-only endpoint used to test whether its
        bearer is valid. An AriaOidc service defaults to this value when -ProbeEndpoint is omitted.

    .NOTES
        Author      : Matthew Sillett
        Version     : 2.6.2
        Date        : 08-OCT-26

        CHANGE LOG
        2.6.2 | 08OCT26 | Help examples now use the example service name aria. No code change.
        2.6.1 | 06OCT26 | Replaced em dashes with ASCII punctuation and reworded the affected
                          sentences, so the source is plain ASCII and loads on Windows PowerShell 5.1.
        2.6.0 | 06OCT26 | Added -ProbeEndpoint. The relative endpoint used to test whether a
                          bearer is valid for the service, stored in the in-memory registry
                          entry and persisted via Write-ServiceConfig when -Persistent is
                          specified. A leading '/' is trimmed. Used by the SSO 403 retry and the
                          AriaOidc bearer selection (see Get-ServiceProbeEndpoint).
        2.5.0 | 01OCT26 | Added 'AriaOidc' to the -SSOProvider ValidateSet. Added optional
                          -SSOTenant parameter, stored in the in-memory registry entry and
                          persisted to services.json via Write-ServiceConfig when -Persistent
                          is specified. Used only by the AriaOidc provider.
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

        [ValidateSet('GCloud', 'AzureCLI', 'Aria', 'AriaOidc')]
        [string]$SSOProvider,

        [string]$SSODomain,

        [string]$SSOTenant,

        [string]$ProbeEndpoint,

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

    if ($SSOTenant) {
        if ($SSOProvider -ne 'AriaOidc') {
            Write-Warning "-SSOTenant is only used by the AriaOidc SSO provider and will be stored but ignored for provider [$SSOProvider]."
        }
        $entry['SSOTenant'] = $SSOTenant
        Write-Verbose "SSO tenant [$SSOTenant] registered for [$ServiceName-$Environment]."
    }

    if ($ProbeEndpoint) {
        $entry['ProbeEndpoint'] = $ProbeEndpoint.TrimStart('/')
        Write-Verbose "Probe endpoint [$($entry['ProbeEndpoint'])] registered for [$ServiceName-$Environment]."
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
        if ($SSOTenant)   { $writeParams['SSOTenant']   = $SSOTenant }
        if ($ProbeEndpoint) { $writeParams['ProbeEndpoint'] = $entry['ProbeEndpoint'] }

        Write-ServiceConfig @writeParams
        Write-Verbose "Persisted [$ServiceName-$Environment] to services.json."
    }
}
