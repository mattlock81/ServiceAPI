function Invoke-APIRequest {
    <#
    .SYNOPSIS
        Executes a REST API request using either registered service configuration or explicit header-based authentication.

    .DESCRIPTION
        Invoke-APIRequest supports two request modes.

        In service/config-driven mode, the function resolves BaseUrl and authentication headers from
        registered service configuration and stored credentials. When -UseToken is specified, token-only
        credential resolution is used. When -UseToken is not specified, the normal Basic authentication
        path is used.

        In explicit header override mode, the function sends the request directly when -BaseUrl,
        -Endpoint, and -Headers.Authorization are supplied. In this mode, -Service is not required,
        Get-ServiceConfig is not called, Get-ServiceCredential is not called, stored credentials are
        not required, credential refresh is not attempted on 403, New-StandardHeaders are used as
        a base and caller-supplied headers are overlaid, and the supplied Authorization header is
        treated as authoritative.

        Service/config-driven requests retain the existing 403 retry behavior for Basic authentication.
        Explicit override requests do not attempt credential refresh. Handled exceptions are reported
        through Debug-Error when available. When SysCommon / Debug-Error is unavailable, ServiceAPI
        falls back to basic local PowerShell error output. -Silent suppresses handled-error output
        and rethrows to the caller.

    .PARAMETER Method
        The HTTP method (GET, POST, PUT, DELETE, PATCH). Defaults to GET if not supplied.

    .PARAMETER Service
        The API service name (e.g., jira, confluence, custom-api).
        Optional only when -BaseUrl and -Headers.Authorization are supplied for explicit header override.
        Otherwise required for config-driven requests.

    .PARAMETER Endpoint
        The relative path to append to the service BaseUrl.

    .PARAMETER Environment
        (Optional) The environment to target: qa, prod, dev. Defaults to prod.

    .PARAMETER Body
        Optional body payload. Automatically serialised to JSON if supplied.

    .PARAMETER Headers
        Custom headers to include with the request.
        If Headers contains Authorization and BaseUrl + Endpoint are supplied, the request runs in
        explicit auth override mode and skips service/config/credential resolution.

    .PARAMETER BaseUrl
        Optional custom BaseUrl for requests that do not use a registered service configuration.
        May be supplied directly for explicit header-based requests.

    .PARAMETER UseToken
        Applies to config-driven credential resolution only.
        Uses token-only credential lookup and does not allow Basic fallback.

    .PARAMETER Silent
        Suppresses module-generated handled-error output/noise while still rethrowing exceptions to the caller.

        Useful when interacting with APIs that return noisy or non-critical error responses
        (such as Atlassian APIs), allowing the caller to handle failures without additional
        console output.

    .EXAMPLE
        Invoke-APIRequest -Service jira -Environment prod -Endpoint 'api/2/myself'
        Sends a service-based request using the normal Basic authentication path.

    .EXAMPLE
        Invoke-APIRequest -Service cloudflare -Environment prod -Endpoint 'zones?name=smashnet.win' -UseToken
        Sends a service-based request using token-only credential resolution.

    .EXAMPLE
        $headers = New-ModifiedHeader -BaseHeaders (New-StandardHeaders) -Override @{
            Authorization = "Bearer $token"
        }

        Invoke-APIRequest -BaseUrl 'https://api.cloudflare.com/client/v4/' -Headers $headers -Endpoint 'zones?name=smashnet.win'
        Sends a stateless request using the supplied Authorization header without credential lookup.

    .NOTES
        Author      : Matthew Sillett
        Organisation: Australian Signals Directorate
        Version     : 2.1.1
        Date        : 28-MAR-26

        CHANGE LOG
        2.1.1 | 28MAR26 | Restored Debug-Error based handled-error reporting with graceful fallback and retained Silent rethrow behavior.
        2.1.0 | 28MAR26 | Added explicit Authorization header override support and token-only config-driven auth selection.
        2.0.0 | 27JAN26 | Refactored to use Get-ServiceConfig and Get-ServiceCredential. Changed -UsePT to -UseToken.
        1.2.6 | 22SEP25 | Fixed authentication: now automatically calls Set-ServiceCredential if no credential is found globally.
        1.2.5 | 22SEP25 | Changed 403 retry logic: retry only if cached credential exists. Prevented unwanted prompts.
        1.2.4 | 22SEP25 | Added -Silent switch to allow callers to bypass Debug-Error logging and handle exceptions locally.
    #>

    [CmdletBinding()]
    param (
        [ValidateSet("GET","POST","PUT","DELETE","PATCH")]
        [string]$Method = 'GET',

        [string]$Service,
        [Parameter(Mandatory)][string]$Endpoint,

        [string]$Environment = 'prod',
        [object]$Body,
        [object]$Headers,
        [string]$BaseUrl,
        [switch]$UseToken,
        [switch]$Silent
    )

    try {
        $isExplicitAuthOverride = $false
        $overrideHeaders = $null
        $authorizationValue = $null

        # A caller-supplied Authorization header switches the request into explicit auth override mode.
        if (-not [string]::IsNullOrWhiteSpace($BaseUrl) -and
            -not [string]::IsNullOrWhiteSpace($Endpoint) -and
            $null -ne $Headers) {
            if ($Headers -is [System.Collections.IDictionary]) {
                $overrideHeaders = @{}

                foreach ($key in $Headers.Keys) {
                    $overrideHeaders[$key] = $Headers[$key]

                    if ([string]::Equals([string]$key, 'Authorization', [System.StringComparison]::OrdinalIgnoreCase)) {
                        $authorizationValue = $Headers[$key]
                    }
                }

                if (-not [string]::IsNullOrWhiteSpace([string]$authorizationValue)) {
                    $isExplicitAuthOverride = $true
                }
            }
        }

        if ($isExplicitAuthOverride) {
            # Keep standard request headers, then let caller-supplied headers override them.
            $resolvedBaseUrl = $BaseUrl
            $mergedHeaders = New-StandardHeaders
            $overrideHeaders.Keys | ForEach-Object { $mergedHeaders[$_] = $overrideHeaders[$_] }
        } else {
            # Resolve service configuration and credentials only when explicit auth override is not used.
            if ([string]::IsNullOrWhiteSpace($Service)) {
                throw "Service is required unless you supply BaseUrl and Headers.Authorization for explicit auth override."
            }

            # Resolve config object: BaseUrl and authentication headers
            $configParams = @{
                Service     = $Service
                Environment = $Environment
                UseToken    = $UseToken
            }
            if ($BaseUrl) { $configParams.BaseUrl = $BaseUrl }

            $config = Get-ServiceConfig @configParams
            if (-not $config) {
                throw "Failed to resolve service configuration for [$Service] in [$Environment]."
            }

            $resolvedBaseUrl = $config.BaseUrl

            # Merge resolved headers with any custom ones passed in
            $mergedHeaders = @{}
            $config.Headers.Keys | ForEach-Object { $mergedHeaders[$_] = $config.Headers[$_] }

            if ($Headers) {
                if ($Headers -isnot [System.Collections.IDictionary]) {
                    throw "Headers must be a hashtable or dictionary-compatible object."
                }

                $Headers.Keys | ForEach-Object { $mergedHeaders[$_] = $Headers[$_] }
            }
        }

        # Remove Content-Type header for GET requests without a body (OPNsense compatibility)
        if ($Method -eq 'GET' -and -not $Body) {
            $mergedHeaders.Remove('Content-Type')
        }

        # Convert body to JSON if supplied
        if ($Body) {
            $json = $Body | ConvertTo-Json -Depth 10 -Compress
        }

        # Construct final REST URI
        $uri = "$($resolvedBaseUrl.TrimEnd('/'))/$($Endpoint.TrimStart('/'))"

        # Build Invoke-RestMethod parameters
        $params = @{ Method = $Method; Uri = $uri; Headers = $mergedHeaders }
        if ($Body) { $params.Body = $json }

        # Perform request
        return Invoke-RestMethod @params

    } catch {
        if ($Silent) { throw } # Silent suppresses Debug-Error/local fallback handled-error noise but still rethrows to the caller.

        # Handle 403 Forbidden with credential refresh retry
        if (-not $isExplicitAuthOverride -and $_.Exception.Response.StatusCode.value__ -eq 403) {
            Write-Warning "Received 403 Forbidden. Checking cached credentials..."

            if ($UseToken) {
                throw "Token-based requests cannot be refreshed automatically. Please run Set-ServiceCredential manually for this service/environment."
            }

            try {
                # Always attempt to ensure a credential exists globally
                $key = New-ServiceKey -Service $Service -Environment $Environment
                if (-not ($global:ServiceCredentials.ContainsKey($key))) {
                    Write-Verbose "No cached credential found. Prompting via Set-ServiceCredential..."
                    Set-ServiceCredential -Service $Service -Environment $Environment -Verbose
                } else {
                    Write-Verbose "Refreshing cached credential..."
                    Set-ServiceCredential -Service $Service -Environment $Environment -Verbose
                }

                # Retry after refresh
                Write-Verbose "Retrying request after refreshing credentials..."
                return Invoke-APIRequest -Service $Service `
                                         -Environment $Environment `
                                         -Method $Method `
                                         -Endpoint $Endpoint `
                                         -Body $Body `
                                         -Headers $Headers `
                                         -BaseUrl $BaseUrl `
                                         -UseToken:$UseToken `
                                         -Verbose:$VerbosePreference
            } catch {
                Write-ServiceApiHandledError -ErrorRecord $_ -Severity 'Critical' -Message 'Credential refresh failed after 403.'
                return
            }
        }

        # Route handled errors through Debug-Error when available, otherwise use local fallback output.
        Write-ServiceApiHandledError -ErrorRecord $_ -Severity 'Critical'
    }
}
