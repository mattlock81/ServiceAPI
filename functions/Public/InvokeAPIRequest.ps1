function Invoke-APIRequest {
    <#
    .SYNOPSIS
        Sends a REST API request to a configured service and environment.

    .DESCRIPTION
        Issues an HTTP request to the specified API service using configured authentication headers
        and environment-specific BaseUrl. Automatically resolves the service endpoint using Get-ServiceConfig.
        Falls back to the global Basic Auth credential if no specific match is found.
        Supports automatic credential refresh on 403 Forbidden responses.

    .PARAMETER Method
        The HTTP method (GET, POST, PUT, DELETE). Defaults to GET if not supplied.

    .PARAMETER Service
        The API service name (e.g., jira, confluence, custom-api).

    .PARAMETER Endpoint
        The relative path to append to the service BaseUrl.

    .PARAMETER Environment
        (Optional) The environment to target: qa, prod, dev. Defaults to prod.

    .PARAMETER Body
        Optional body payload. Automatically serialised to JSON if supplied.

    .PARAMETER Headers
        Optional additional headers to merge with default authentication headers.

    .PARAMETER BaseUrl
        Optional custom BaseUrl for services not in the registry.

    .PARAMETER UseToken
        Use token-based authentication instead of Basic Auth.

    .PARAMETER Silent
        If set, prevents Debug-Error from logging exceptions. Exceptions are rethrown to be handled by the caller.

    .EXAMPLE
        Invoke-APIRequest -Service jira -Endpoint "issue/PROJECT-123"
        # GET request to jira prod

    .EXAMPLE
        Invoke-APIRequest -Service confluence -Endpoint "rest/api/content" -Method POST -Body @{title="New Page"}
        # POST request with body

    .EXAMPLE
        Invoke-APIRequest -Service custom-api -BaseUrl "https://api.example.com" -Endpoint "v1/users"
        # Request to custom service

    .NOTES
        Author      : Matthew Sillett
        Organisation: Australian Signals Directorate
        Version     : 2.0.0
        Date        : 27-JAN-26

        CHANGE LOG
        2.0.0 | 27JAN26 | Refactored to use Get-ServiceConfig and Get-ServiceCredential. Changed -UsePT to -UseToken.
        1.2.6 | 22SEP25 | Fixed authentication: now automatically calls Set-ServiceCredential if no credential is found globally.
        1.2.5 | 22SEP25 | Changed 403 retry logic: retry only if cached credential exists. Prevented unwanted prompts.
        1.2.4 | 22SEP25 | Added -Silent switch to allow callers to bypass Debug-Error logging and handle exceptions locally.
    #>

    [CmdletBinding()]
    param (
        [ValidateSet("GET","POST","PUT","DELETE","PATCH")]
        [string]$Method = 'GET',

        [Parameter(Mandatory)][string]$Service,
        [Parameter(Mandatory)][string]$Endpoint,

        [string]$Environment = 'prod',
        [object]$Body,
        [hashtable]$Headers,
        [string]$BaseUrl,
        [switch]$UseToken,
        [switch]$Silent
    )

    try {
        # Resolve config object: BaseUrl and authentication headers
        $configParams = @{
            Service     = $Service
            Environment = $Environment
            UseToken    = $UseToken
        }
        if ($BaseUrl) { $configParams.BaseUrl = $BaseUrl }

        $config = Get-ServiceConfig @configParams

        # Merge resolved headers with any custom ones passed in
        $mergedHeaders = @{}
        $config.Headers.Keys | ForEach-Object { $mergedHeaders[$_] = $config.Headers[$_] }
        if ($Headers) { $Headers.Keys | ForEach-Object { $mergedHeaders[$_] = $Headers[$_] } }

        # Remove Content-Type header for GET requests without a body (OPNsense compatibility)
        if ($Method -eq 'GET' -and -not $Body) {
            $mergedHeaders.Remove('Content-Type')
        }

        # Convert body to JSON if supplied
        if ($Body) { $json = $Body | ConvertTo-Json -Depth 10 -Compress }

        # Construct final REST URI
        $uri = "$($config.BaseUrl.TrimEnd('/'))/$($Endpoint.TrimStart('/'))"

        # Build Invoke-RestMethod parameters
        $params = @{ Method = $Method; Uri = $uri; Headers = $mergedHeaders }
        if ($Body) { $params.Body = $json }

        # Perform request
        return Invoke-RestMethod @params

    } catch {
        if ($Silent) { throw } # let caller handle locally

        # Handle 403 Forbidden with credential refresh retry
        if ($_.Exception.Response.StatusCode.value__ -eq 403) {
            Write-Warning "Received 403 Forbidden. Checking cached credentials..."

            if ($UseToken) {
                throw "Token-based requests cannot be refreshed automatically. Please run Set-ServiceCredential manually for this service/environment."
            }

            try {
                # Always attempt to ensure a credential exists globally
                $key = New-ServiceKey -Service $Service -Environment $Environment
                if (-not ($global:ServiceCredentials.ContainsKey($key))) {
                    Write-Host "No cached credential found. Prompting via Set-ServiceCredential..." -ForegroundColor Cyan
                    Set-ServiceCredential -Service $Service -Environment $Environment -Verbose
                } else {
                    Write-Host "Refreshing cached credential..." -ForegroundColor Cyan
                    Set-ServiceCredential -Service $Service -Environment $Environment -Verbose
                }

                # Retry after refresh
                Write-Host "Retry request after refreshing credentials..." -ForegroundColor Cyan
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
                if (Get-Command -Name Debug-Error -ErrorAction SilentlyContinue) {
                    Debug-Error -ErrorRecord $_ -Severity 'Critical'
                } else {
                    Write-Error "Credential refresh failed after 403. Error: $($_.Exception.Message)"
                }
                return
            }
        }

        # Fallback error output for non-403 exceptions
        if (Get-Command -Name Debug-Error -ErrorAction SilentlyContinue) {
            Debug-Error -ErrorRecord $_ -Severity 'Critical'
        } else {
            Write-Error $_
        }
    }
}
