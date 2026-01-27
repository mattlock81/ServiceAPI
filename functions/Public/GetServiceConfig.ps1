function Get-ServiceConfig {
    <#
    .SYNOPSIS
        Retrieves configuration settings for an API service in the specified environment.

    .DESCRIPTION
        Resolves the BaseUrl and authentication headers to be used with REST API requests.
        Internally calls Get-ServiceCredential to apply the appropriate headers based on the service/environment/credential configuration.
        Supports both predefined services (from service registry) and custom services with user-provided BaseUrl.

    .PARAMETER Service
        The API service name (e.g., jira, confluence, custom-api).

    .PARAMETER Environment
        The environment to target: qa, prod, dev. Defaults to prod.

    .PARAMETER BaseUrl
        Required if Service is not in the predefined registry. Specifies the base URL to use for custom service endpoints.

    .PARAMETER UseToken
        Use token-based authentication.

    .EXAMPLE
        Get-ServiceConfig -Service jira
        # Returns config for jira prod

    .EXAMPLE
        Get-ServiceConfig -Service confluence -Environment qa
        # Returns config for confluence qa

    .EXAMPLE
        Get-ServiceConfig -Service custom-api -BaseUrl 'https://api.example.com/v1'
        # Returns config for custom API service

    .EXAMPLE
        Get-ServiceConfig -Service bitbucket -UseToken
        # Returns config with token-based auth

    .NOTES
        Author      : Matthew Sillett
        Organisation: Australian Signals Directorate
        Version     : 2.0.0
        Date        : 27-JAN-26

        CHANGE LOG
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
        # === Determine the BaseUrl ===
        if ($BaseUrl) {
            # User-provided BaseUrl takes precedence
            Write-Verbose "Using custom BaseUrl: $BaseUrl"
        } elseif ($global:ServiceRegistry.ContainsKey($Service) -and 
                  $global:ServiceRegistry[$Service].ContainsKey($Environment)) {
            # Lookup from service registry
            $BaseUrl = $global:ServiceRegistry[$Service][$Environment].BaseUrl
            Write-Verbose "Resolved BaseUrl from registry: $BaseUrl"
        } else {
            throw "BaseUrl not defined for [$Service] in [$Environment] environment. Provide -BaseUrl or register the service first."
        }

        # === Resolve appropriate headers (Token or Basic) ===
        $Headers = Get-ServiceCredential -Service $Service -Environment $Environment -UseToken:$UseToken

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
