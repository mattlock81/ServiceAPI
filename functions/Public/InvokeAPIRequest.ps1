function Invoke-APIRequest {
    <#
    .SYNOPSIS
        Executes a REST API request using either registered service configuration or explicit header-based authentication.

    .DESCRIPTION
        Invoke-APIRequest supports two request modes.

        In service/config-driven mode, the function resolves BaseUrl and authentication
        headers from registered service configuration and stored credentials. The
        authentication type is specified via -AuthType (Basic, Token, or SSO).

        - Basic (default): PSCredential from vault or four-tier in-memory fallback.
        - Token: Static long-lived token from vault by label. Key presence determines
          whether a Bearer or Basic header is built.
        - SSO: Short-lived OAuth Bearer token via provider dispatch. Provider resolved
          from service registry. Auto-refreshed when stale. Never stored in vault.

        -Label specifies the vault credential label for Basic and Token auth types.
        Defaults to 'default'. Multiple credentials per service are supported by
        registering them under different labels.

        -SessionOnly bypasses vault lookup and storage for Basic and Token auth types.
        Ignored for SSO.

        When an unregistered service name is supplied, the function prompts to register
        it inline with a BaseUrl and session/permanent choice.

        In explicit header override mode, the function sends the request directly when
        -BaseUrl, -Endpoint, and -Headers.Authorization are supplied without -AuthType
        Token or SSO. Service/config/credential resolution is bypassed entirely.

        Basic Auth requests retain 403 retry with credential refresh.
        Token and SSO requests do not retry on 403.
        -Silent suppresses all handled-error output while still rethrowing to the caller.

    .PARAMETER Method
        The HTTP method (GET, POST, PUT, DELETE, PATCH). Defaults to GET.

    .PARAMETER Service
        The API service name. Supports tab completion from the live service registry.
        If the supplied name is not registered, the function prompts to register it inline.

    .PARAMETER Endpoint
        The relative path to append to the service BaseUrl.

    .PARAMETER AuthType
        The authentication type. Accepted values: Basic, Token, SSO. Defaults to Basic.
        Tab-completed. Determines the credential resolution path.

    .PARAMETER Label
        The vault credential label to retrieve for Basic and Token auth types.
        Defaults to 'default'. Ignored for SSO.

    .PARAMETER Environment
        The environment to target: qa, prod, dev. Defaults to prod.

    .PARAMETER Body
        Optional body payload. Automatically serialised to JSON if supplied.

    .PARAMETER Headers
        Custom headers to merge with resolved service headers. If Headers contains
        Authorization and BaseUrl and Endpoint are supplied without -AuthType Token or
        SSO, the request runs in explicit auth override mode.

    .PARAMETER BaseUrl
        Optional custom BaseUrl override.

    .PARAMETER SessionOnly
        Bypasses vault lookup and storage for Basic and Token auth types. Ignored for SSO.

    .PARAMETER Silent
        Suppresses module-generated handled-error output while still rethrowing exceptions.

    .EXAMPLE
        Invoke-APIRequest -Service jira -Endpoint 'api/2/myself'
        Basic Auth request using vault or four-tier credential fallback.

    .EXAMPLE
        Invoke-APIRequest -Service cloudflare -Endpoint 'zones' -AuthType Token
        Token request using the 'default' vault label for cloudflare-prod.

    .EXAMPLE
        Invoke-APIRequest -Service cloudflare -Endpoint 'zones' -AuthType Token -Label work
        Token request using the 'work' vault label for cloudflare-prod.

    .EXAMPLE
        Invoke-APIRequest -Service opnsense -Endpoint 'core/firmware/status' -AuthType Token -Label matt
        Token request using the 'matt' vault label for opnsense-prod.

    .EXAMPLE
        Invoke-APIRequest -Service google -Endpoint 'gmail/v1/users/me/profile' -AuthType SSO
        SSO request using the registered GCloud provider for google-prod.

    .EXAMPLE
        Invoke-APIRequest -Service jira -Endpoint 'api/2/myself' -AuthType Basic -SessionOnly
        Basic Auth request bypassing vault — prompts interactively, session store only.

    .EXAMPLE
        Invoke-APIRequest -Service newapi -Endpoint 'resource'
        Unregistered service — prompts for BaseUrl and session/permanent choice.

    .EXAMPLE
        $headers = @{ Authorization = "Bearer $token" }
        Invoke-APIRequest -BaseUrl 'https://api.example.com' -Headers $headers -Endpoint 'resource'
        Explicit header override mode — bypasses all credential resolution.

    .NOTES
        Author      : Matthew Sillett
        Version     : 2.5.2
        Date        : 17-MAY-26

        CHANGE LOG
        2.5.2 | 17MAY26 | Added direct BaseUrl + AuthType None execution path. Allows
                          unauthenticated requests to dynamic or ad-hoc URIs without a
                          registered service or Authorization header requirement.
                          Updated Service-required error message accordingly.
        2.5.1 | 17MAY26 | Added 'None' to -AuthType ValidateSet. AuthType None skips all
                          credential resolution — suitable for unauthenticated local services.
                          $useTokenOrSSO guard updated to include None, preventing 403 retry.
        2.5.0 | 17MAY26 | Replaced -UseToken and -UseSSO with -AuthType [ValidateSet] and
                          -Label parameters. Auth mode selection is now explicit and tab-completed.
                          Explicit auth override mode guarded against AuthType Token and SSO.
                          403 retry block updated to check AuthType rather than former switches.
        2.4.3 | 17MAY26 | Australian/British English spelling applied throughout.
        2.3.0 | 16MAY26 | Added [ArgumentCompleter] on -Service. Added inline unregistered
                          service registration prompt. Added [ArgumentCompleter] on -UseSSO.
        2.2.0 | 16MAY26 | Added -UseSSO parameter. Changed -UseToken from [switch] to [string].
                          Explicit auth override mode guarded against -UseToken and -UseSSO.
        2.1.1 | 28MAR26 | Restored Debug-Error based handled-error reporting.
        2.1.0 | 28MAR26 | Added explicit Authorization header override support.
        2.0.0 | 27JAN26 | Refactored to use Get-ServiceConfig and Get-ServiceCredential.
        1.2.6 | 22SEP25 | Fixed authentication: auto-calls Set-ServiceCredential if no credential found.
        1.2.5 | 22SEP25 | Changed 403 retry logic.
        1.2.4 | 22SEP25 | Added -Silent switch.
    #>

    [CmdletBinding()]
    param (
        [ValidateSet('GET', 'POST', 'PUT', 'DELETE', 'PATCH')]
        [string]$Method = 'GET',

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

        # Authentication type — tab-completed, explicit, unambiguous.
        [ValidateSet('Basic', 'Token', 'SSO', 'None')]
        [string]$AuthType = 'Basic',

        # Vault credential label — applies to Basic and Token. Defaults to 'default'.
        [string]$Label = 'default',

        [string]$Environment = 'prod',
        [object]$Body,
        [object]$Headers,
        [string]$BaseUrl,

        # Bypasses vault lookup and storage for Basic and Token. Ignored for SSO.
        [switch]$SessionOnly,

        [switch]$Silent
    )

    $useTokenOrSSO = $AuthType -in @('Token', 'SSO', 'None')

    try {
        $isExplicitAuthOverride = $false
        $overrideHeaders        = $null
        $authorizationValue     = $null

        # === Inline service registration — fires when service is not in the registry ===
        if (-not [string]::IsNullOrWhiteSpace($Service) -and
            -not $global:ServiceRegistry.ContainsKey($Service)) {

            Write-Warning "Service [$Service] is not registered."
            $register = Read-Host "Would you like to register it now? (Y/N)"

            if ($register -ne 'Y') {
                throw "Service [$Service] is not registered and registration was declined."
            }

            $newBaseUrl = Read-Host "BaseUrl for [$Service]"
            if ([string]::IsNullOrWhiteSpace($newBaseUrl)) {
                throw "BaseUrl cannot be empty. Service [$Service] was not registered."
            }

            $persistence = Read-Host "Register as permanent or session only? (P/S)"

            # Infer SSOProvider from registry if AuthType is SSO
            $inferredProvider = $null
            if ($AuthType -eq 'SSO' -and
                $global:ServiceRegistry.ContainsKey($Service) -and
                $global:ServiceRegistry[$Service].ContainsKey($Environment) -and
                $global:ServiceRegistry[$Service][$Environment].SSOProvider) {
                $inferredProvider = $global:ServiceRegistry[$Service][$Environment].SSOProvider
            }

            $regParams = @{
                ServiceName = $Service
                BaseUrl     = $newBaseUrl
                Environment = $Environment
                Force       = $true
            }
            if ($inferredProvider)      { $regParams['SSOProvider'] = $inferredProvider }
            if ($persistence -eq 'P')   { $regParams['Persistent']  = $true }

            Register-CustomService @regParams
            Write-Verbose "Service [$Service] registered for [$Environment]$(if ($persistence -eq 'P') { ' permanently' } else { ' for this session' })."
        }

        # === Explicit auth override detection ===
        # Only fires for Basic auth without explicit AuthType specification — prevents
        # a caller-supplied Authorization header from bypassing Token or SSO resolution.
        if ($AuthType -eq 'Basic' -and
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

        } elseif ($AuthType -eq 'None' -and -not [string]::IsNullOrWhiteSpace($BaseUrl)) {
            # AuthType None with direct BaseUrl — no service registration or credential resolution required
            $resolvedBaseUrl = $BaseUrl
            $mergedHeaders   = New-StandardHeaders
            if ($Headers -and $Headers -is [System.Collections.IDictionary]) {
                $Headers.Keys | ForEach-Object { $mergedHeaders[$_] = $Headers[$_] }
            }

        } else {
            # Config-driven mode
            if ([string]::IsNullOrWhiteSpace($Service)) {
                throw "Service is required unless you supply BaseUrl and Headers.Authorization for explicit auth override, or BaseUrl with -AuthType None."
            }

            $configParams = @{
                Service     = $Service
                Environment = $Environment
                AuthType    = $AuthType
                Label       = $Label
            }

            if ($BaseUrl)                              { $configParams['BaseUrl']     = $BaseUrl }
            if ($Endpoint)                             { $configParams['Endpoint']    = $Endpoint }
            if ($SessionOnly -and $AuthType -ne 'SSO') { $configParams['SessionOnly'] = $true }

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
        if ($Silent) { throw }

        # === 403 retry — Basic Auth only ===
        if (-not $isExplicitAuthOverride -and $_.Exception.Response.StatusCode.value__ -eq 403) {
            Write-Warning "Received 403 Forbidden. Checking cached credentials..."

            if ($useTokenOrSSO) {
                throw "Token and SSO-based requests cannot be refreshed automatically via 403 retry. Re-authenticate and retry."
            }

            try {
                $key = New-ServiceKey -Service $Service -Environment $Environment
                if (-not $global:ServiceCredentials.ContainsKey($key)) {
                    Write-Verbose "No cached Basic Auth credential found for [$key]. Prompting via Set-ServiceCredential."
                } else {
                    Write-Verbose "Refreshing cached Basic Auth credential for [$key]."
                }

                Set-ServiceCredential -Service $Service -Environment $Environment -AuthType Basic

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
