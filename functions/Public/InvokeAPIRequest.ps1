function Invoke-APIRequest {
    <#
    .SYNOPSIS
        Executes a REST API request using either registered service configuration or explicit header-based authentication.

    .DESCRIPTION
        Invoke-APIRequest supports two request modes.

        In service/config-driven mode, the function resolves BaseUrl and authentication headers from
        registered service configuration and stored credentials. Three credential modes are available:

        - Default (no auth switch): Basic Auth via four-tier credential fallback.
        - -UseToken: Static long-lived Bearer token from $global:ServiceTokens. Accepts an optional
          inline token value; prompts and stores if absent.
        - -UseSSO: Short-lived OAuth Bearer token from $global:ServiceSSOTokens with automatic lazy
          refresh via the registered SSO provider. Accepts an optional inline provider name.

        When an unregistered service name is supplied, the function prompts to register it inline.
        The caller is asked for a BaseUrl and whether to persist the registration to services.json
        (permanent) or keep it for the current session only. The auth mode inferred from the current
        call determines what is stored: Basic Auth by default, or the SSO provider if -UseSSO was
        specified with a provider value.

        In explicit header override mode, the function sends the request directly when -BaseUrl,
        -Endpoint, and -Headers.Authorization are supplied without -UseToken or -UseSSO. In this
        mode service/config/credential resolution is bypassed entirely.

        Service/config-driven Basic Auth requests retain 403 retry with credential refresh.
        Token and SSO requests do not retry on 403.
        -Silent suppresses all handled-error output while still rethrowing to the caller.

    .PARAMETER Method
        The HTTP method (GET, POST, PUT, DELETE, PATCH). Defaults to GET.

    .PARAMETER Service
        The API service name. Supports tab completion from the live service registry.
        If the supplied name is not registered, the function prompts to register it inline.

    .PARAMETER Endpoint
        The relative path to append to the service BaseUrl.

    .PARAMETER Environment
        The environment to target: qa, prod, dev. Defaults to prod.

    .PARAMETER Body
        Optional body payload. Automatically serialised to JSON if supplied.

    .PARAMETER Headers
        Custom headers to merge with resolved service headers. If Headers contains Authorization
        and BaseUrl and Endpoint are supplied without -UseToken or -UseSSO, the request runs in
        explicit auth override mode and skips service/config/credential resolution.

    .PARAMETER BaseUrl
        Optional custom BaseUrl override. May be supplied for explicit header override requests
        or to override the registered BaseUrl for a config-driven request.

    .PARAMETER UseToken
        Switches to static token credential resolution. Accepts an optional inline token value.
        If absent, prompts and stores. No Basic fallback.

    .PARAMETER UseSSO
        Switches to SSO credential resolution with automatic token refresh. Accepts an optional
        inline provider name. Resolves provider from registry if not supplied. No Basic fallback.

    .PARAMETER Silent
        Suppresses module-generated handled-error output while still rethrowing exceptions to the
        caller. Use when the caller owns error handling.

    .EXAMPLE
        Invoke-APIRequest -Service jira -Endpoint 'api/2/myself'
        Basic Auth request using the four-tier credential fallback.

    .EXAMPLE
        Invoke-APIRequest -Service cloudflare -Endpoint 'zones' -UseToken
        Token-based request. Prompts and stores if no token exists for cloudflare-prod.

    .EXAMPLE
        Invoke-APIRequest -Service cloudflare -Endpoint 'zones' -UseToken 'cfat_xxxxx'
        Token-based request. Stores the supplied token for cloudflare-prod and proceeds.

    .EXAMPLE
        Invoke-APIRequest -Service googleapi -Endpoint 'gmail/v1/users/me/profile' -UseSSO
        SSO request using the registered GCloud provider for googleapi-prod.

    .EXAMPLE
        Invoke-APIRequest -Service googleapi -Endpoint 'gmail/v1/users/me/profile' -UseSSO GCloud
        SSO request specifying the GCloud provider explicitly.

    .EXAMPLE
        Invoke-APIRequest -Service newapi -Endpoint 'resource'
        Service not registered — prompts for BaseUrl and session/permanent choice before proceeding.

    .EXAMPLE
        $headers = @{ Authorization = "Bearer $token" }
        Invoke-APIRequest -BaseUrl 'https://api.example.com' -Headers $headers -Endpoint 'resource'
        Explicit header override mode — bypasses all credential resolution.

    .NOTES
        Author      : Matthew Sillett
        Organisation: Australian Signals Directorate
        Version     : 2.3.0
        Date        : 16-MAY-26

        CHANGE LOG
        2.3.0 | 16MAY26 | Added [ArgumentCompleter] on -Service for live tab completion from registry.
                          Added [ArgumentCompleter] on -UseSSO for provider name completion.
                          Added inline unregistered service registration prompt with session/permanent
                          choice. Auth mode (Basic, Token, SSO) inferred from call parameters for
                          inline registration — SSOProvider stored when -UseSSO is specified.
        2.2.0 | 16MAY26 | Added -UseSSO parameter for SSO credential resolution pass-through.
                          Changed -UseToken from [switch] to [string]. Explicit auth override mode
                          guarded against -UseToken and -UseSSO. 403 retry extended to exclude SSO.
        2.1.1 | 28MAR26 | Restored Debug-Error based handled-error reporting with graceful fallback.
        2.1.0 | 28MAR26 | Added explicit Authorization header override support and token-only auth.
        2.0.0 | 27JAN26 | Refactored to use Get-ServiceConfig and Get-ServiceCredential.
        1.2.6 | 22SEP25 | Fixed authentication: auto-calls Set-ServiceCredential if no credential found.
        1.2.5 | 22SEP25 | Changed 403 retry logic: retry only if cached credential exists.
        1.2.4 | 22SEP25 | Added -Silent switch.
    #>

    [CmdletBinding()]
    param (
        [ValidateSet('GET', 'POST', 'PUT', 'DELETE', 'PATCH')]
        [string]$Method = 'GET',

        # Tab completion reads live $global:RegisteredServices at press time.
        # Unregistered values are allowed — handled by inline registration prompt below.
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
        [string]$Service,

        [Parameter(Mandatory)]
        [string]$Endpoint,

        [string]$Environment = 'prod',
        [object]$Body,
        [object]$Headers,
        [string]$BaseUrl,

        # -UseToken accepts an optional inline token value. Presence activates token mode.
        [AllowNull()][AllowEmptyString()]
        [object]$UseToken,

        # -UseSSO accepts an optional inline provider name. Presence activates SSO mode.
        # Tab completion offers known providers, with the service default surfaced first.
        [ArgumentCompleter({
            param($cmd, $param, $word, $ast, $fakeBound)
            $providers = @('GCloud', 'AzureCLI')

            # Surface registered default provider for the current -Service value first
            $svc = $fakeBound['Service']
            $env = if ($fakeBound['Environment']) { $fakeBound['Environment'] } else { 'prod' }
            if ($svc -and $global:ServiceRegistry -and
                $global:ServiceRegistry.ContainsKey($svc) -and
                $global:ServiceRegistry[$svc].ContainsKey($env) -and
                $global:ServiceRegistry[$svc][$env].SSOProvider) {
                $default  = $global:ServiceRegistry[$svc][$env].SSOProvider
                $providers = @($default) + ($providers | Where-Object { $_ -ne $default })
            }

            $providers |
                Where-Object { $_ -like "$word*" } |
                ForEach-Object {
                    [System.Management.Automation.CompletionResult]::new(
                        $_, $_, 'ParameterValue', $_
                    )
                }
        })]
        [AllowNull()][AllowEmptyString()]
        [object]$UseSSO,

        [switch]$Silent
    )

    $useTokenMode = $PSBoundParameters.ContainsKey('UseToken')
    $useSSOMode   = $PSBoundParameters.ContainsKey('UseSSO')

    try {
        $isExplicitAuthOverride = $false
        $overrideHeaders        = $null
        $authorizationValue     = $null

        # === Inline service registration — fires when service is not in the registry ===
        # Only applies to config-driven mode (i.e. -Service is provided and not empty).
        if (-not [string]::IsNullOrWhiteSpace($Service) -and
            -not $global:ServiceRegistry.ContainsKey($Service)) {

            Write-Warning "Service [$Service] is not registered."
            $register = Read-Host "Would you like to register it now? (Y/N)"

            if ($register -ne 'Y') {
                throw "Service [$Service] is not registered and registration was declined."
            }

            # Prompt for BaseUrl
            $newBaseUrl = Read-Host "BaseUrl for [$Service]"
            if ([string]::IsNullOrWhiteSpace($newBaseUrl)) {
                throw "BaseUrl cannot be empty. Service [$Service] was not registered."
            }

            # Prompt for session or permanent storage
            $persistence = Read-Host "Register as permanent or session only? (P/S)"

            # Infer SSOProvider from the current call if -UseSSO was supplied with a provider value
            $inferredProvider = $null
            if ($useSSOMode -and -not [string]::IsNullOrWhiteSpace([string]$UseSSO)) {
                $inferredProvider = [string]$UseSSO
            }

            $regParams = @{
                ServiceName = $Service
                BaseUrl     = $newBaseUrl
                Environment = $Environment
                Force       = $true
            }
            if ($inferredProvider) { $regParams['SSOProvider'] = $inferredProvider }
            if ($persistence -eq 'P') { $regParams['Persistent'] = $true }

            Register-CustomService @regParams

            Write-Verbose "Service [$Service] registered for [$Environment]$(if ($persistence -eq 'P') { ' permanently' } else { ' for this session' })."
        }

        # === Explicit auth override detection ===
        # Only fires when neither -UseToken nor -UseSSO is specified — prevents a caller-supplied
        # Authorization header from silently bypassing SSO or token credential resolution.
        if (-not $useTokenMode -and -not $useSSOMode -and
            -not [string]::IsNullOrWhiteSpace($BaseUrl) -and
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
            # Explicit override — use standard headers as base and overlay caller-supplied headers
            $resolvedBaseUrl = $BaseUrl
            $mergedHeaders   = New-StandardHeaders
            $overrideHeaders.Keys | ForEach-Object { $mergedHeaders[$_] = $overrideHeaders[$_] }

        } else {
            # Config-driven mode — resolve service configuration and credentials
            if ([string]::IsNullOrWhiteSpace($Service)) {
                throw "Service is required unless you supply BaseUrl and Headers.Authorization for explicit auth override."
            }

            # Build Get-ServiceConfig parameter set
            $configParams = @{
                Service     = $Service
                Environment = $Environment
            }

            if ($BaseUrl) { $configParams['BaseUrl'] = $BaseUrl }

            # Pass auth mode parameters through to Get-ServiceConfig
            if ($useSSOMode) {
                $configParams['UseSSO'] = if (-not [string]::IsNullOrWhiteSpace([string]$UseSSO)) {
                    [string]$UseSSO
                } else { $null }
            } elseif ($useTokenMode) {
                $configParams['UseToken'] = if (-not [string]::IsNullOrWhiteSpace([string]$UseToken)) {
                    [string]$UseToken
                } else { $null }
            }

            $config = Get-ServiceConfig @configParams
            if (-not $config) {
                throw "Failed to resolve service configuration for [$Service] in [$Environment]."
            }

            $resolvedBaseUrl = $config.BaseUrl

            # Merge resolved config headers with any additional caller-supplied headers
            $mergedHeaders = @{}
            $config.Headers.Keys | ForEach-Object { $mergedHeaders[$_] = $config.Headers[$_] }

            if ($Headers) {
                if ($Headers -isnot [System.Collections.IDictionary]) {
                    throw "Headers must be a hashtable or dictionary-compatible object."
                }
                $Headers.Keys | ForEach-Object { $mergedHeaders[$_] = $Headers[$_] }
            }
        }

        # Remove Content-Type for GET requests without a body (OPNsense compatibility)
        if ($Method -eq 'GET' -and -not $Body) {
            $mergedHeaders.Remove('Content-Type')
        }

        # Serialise body to JSON if supplied
        if ($Body) {
            $json = $Body | ConvertTo-Json -Depth 10 -Compress
        }

        # Construct the final request URI
        $uri = "$($resolvedBaseUrl.TrimEnd('/'))/$($Endpoint.TrimStart('/'))"

        $params = @{ Method = $Method; Uri = $uri; Headers = $mergedHeaders }
        if ($Body) { $params['Body'] = $json }

        return Invoke-RestMethod @params

    } catch {
        # -Silent suppresses all handled-error output but still rethrows to the caller
        if ($Silent) { throw }

        # === 403 retry — Basic Auth only ===
        # Token and SSO requests do not retry on 403.
        if (-not $isExplicitAuthOverride -and $_.Exception.Response.StatusCode.value__ -eq 403) {
            Write-Warning "Received 403 Forbidden. Checking cached credentials..."

            if ($useTokenMode -or $useSSOMode) {
                throw "Token and SSO-based requests cannot be refreshed automatically via 403 retry. Re-authenticate and retry."
            }

            try {
                $key = New-ServiceKey -Service $Service -Environment $Environment
                if (-not $global:ServiceCredentials.ContainsKey($key)) {
                    Write-Verbose "No cached Basic credential found for [$key]. Prompting via Set-ServiceCredential."
                } else {
                    Write-Verbose "Refreshing cached Basic credential for [$key]."
                }

                Set-ServiceCredential -Service $Service -Environment $Environment

                Write-Verbose "Retrying request after credential refresh."
                return Invoke-APIRequest -Service $Service `
                                         -Environment $Environment `
                                         -Method $Method `
                                         -Endpoint $Endpoint `
                                         -Body $Body `
                                         -Headers $Headers `
                                         -BaseUrl $BaseUrl `
                                         -Verbose:$VerbosePreference
            } catch {
                Write-ServiceApiHandledError -ErrorRecord $_ -Severity 'Critical' -Message 'Credential refresh failed after 403.'
                return
            }
        }

        Write-ServiceApiHandledError -ErrorRecord $_ -Severity 'Critical'
    }
}
