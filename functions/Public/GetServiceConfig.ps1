function Get-ServiceConfig {
    <#
    .SYNOPSIS
        Resolves BaseUrl and headers for a service/environment.

    .DESCRIPTION
        Resolves the BaseUrl and headers to be used with REST API requests.
        BaseUrl may come from the supplied -BaseUrl parameter or the registered service configuration.

        Headers are built in layers:
        1. New-StandardHeaders provides the base set.
        2. Registered DefaultHeaders are overlaid — they take precedence over standard headers.
        3. Credential-derived headers are resolved via Get-ServiceCredential only when Authorization
           is not already provided by DefaultHeaders.

        Three credential resolution modes are supported, controlled by -UseToken and -UseSSO:
        - Default (neither specified): Basic Auth via four-tier fallback.
        - -UseToken: Static Bearer token from $global:ServiceTokens.
        - -UseSSO: Short-lived OAuth Bearer token from $global:ServiceSSOTokens with lazy refresh.

        When DefaultHeaders already contains a non-empty Authorization value, credential resolution
        is skipped entirely regardless of -UseToken or -UseSSO.

    .PARAMETER Service
        Service name to resolve.

    .PARAMETER Environment
        Environment to resolve. Defaults to prod.

    .PARAMETER BaseUrl
        Optional direct BaseUrl override. Required if the service/environment is not registered.

    .PARAMETER UseToken
        Passes token-mode resolution to Get-ServiceCredential. Accepts an optional inline token value.

    .PARAMETER UseSSO
        Passes SSO-mode resolution to Get-ServiceCredential. Accepts an optional inline provider name.

    .EXAMPLE
        Get-ServiceConfig -Service jira -Environment prod
        Returns resolved configuration for jira in prod using Basic Auth.

    .EXAMPLE
        Get-ServiceConfig -Service cloudflare -Environment prod -UseToken
        Returns resolved configuration using token credential resolution.

    .EXAMPLE
        Get-ServiceConfig -Service googleapi -Environment prod -UseSSO
        Returns resolved configuration using SSO credential resolution via the registered provider.

    .EXAMPLE
        Get-ServiceConfig -Service cloudflare -Environment prod -BaseUrl 'https://api.cloudflare.com/client/v4/'
        Returns resolved configuration using the supplied BaseUrl override.

    .NOTES
        Author      : Matthew Sillett
        Organisation: Australian Signals Directorate
        Version     : 2.4.0
        Date        : 17-MAY-26

        CHANGE LOG
        2.4.0 | 17MAY26 | Added -SessionOnly pass-through. Added Endpoint and BaseUrl pass-through
                          to Get-ServiceCredential for vault test call validation.
        2.3.0 | 16MAY26 | Added [ArgumentCompleter] on -Service for tab completion from live registry.
        2.2.0 | 16MAY26 | Added -UseSSO parameter for SSO credential resolution pass-through to
                          Get-ServiceCredential. Removed early-fail stub for -UseSSO. Both -UseToken
                          and -UseSSO accept optional inline values consistent with Get-ServiceCredential.
        2.1.1 | 28MAR26 | Documentation refresh for centralized handled-error reporting and version consistency.
        2.1.0 | 28MAR26 | Added registered DefaultHeaders precedence and skipped credential lookup
                          when Authorization is already supplied.
        2.0.0 | 27JAN26 | Refactored from Get-AtlassianConfig to support generalised API services.
        1.2.0 | 22AUG25 | Added support for custom service with -BaseUrl.
        1.1.5 | 23JUN25 | Added inline comments and enforced early fail for unimplemented -UseSSO flag.
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
        [string]$Service,

        [string]$Environment = 'prod',
        [string]$BaseUrl,

        # -UseToken accepts an optional inline token value. Presence activates token mode.
        [AllowNull()][AllowEmptyString()]
        [object]$UseToken,

        # -UseSSO accepts an optional inline provider name. Presence activates SSO mode.
        [AllowNull()][AllowEmptyString()]
        [object]$UseSSO,

        # -SessionOnly bypasses vault lookup and storage — passed through to Get-ServiceCredential.
        [switch]$SessionOnly,

        # Passed through to Get-ServiceCredential for vault test call validation.
        [string]$Endpoint
    )

    $useTokenMode = $PSBoundParameters.ContainsKey('UseToken')
    $useSSOMode   = $PSBoundParameters.ContainsKey('UseSSO')

    try {
        $serviceConfig = $null

        # === Determine the BaseUrl ===
        if ($BaseUrl) {
            Write-Verbose "Using custom BaseUrl: $BaseUrl"
        } elseif ($global:ServiceRegistry.ContainsKey($Service) -and
                  $global:ServiceRegistry[$Service].ContainsKey($Environment)) {
            $serviceConfig = $global:ServiceRegistry[$Service][$Environment]
            $BaseUrl = $serviceConfig.BaseUrl
            Write-Verbose "Resolved BaseUrl from registry: $BaseUrl"
        } else {
            throw "BaseUrl not defined for [$Service] in [$Environment] environment. Provide -BaseUrl or register the service first."
        }

        # === Start with standard headers ===
        $Headers = New-StandardHeaders -Service $Service

        # === Overlay registered DefaultHeaders — they take precedence over standard headers ===
        if ($serviceConfig -and $null -ne $serviceConfig.DefaultHeaders) {
            if ($serviceConfig.DefaultHeaders -isnot [System.Collections.IDictionary]) {
                throw "DefaultHeaders for [$Service] in [$Environment] must be a hashtable or dictionary-compatible object."
            }

            foreach ($key in $serviceConfig.DefaultHeaders.Keys) {
                $Headers[$key] = $serviceConfig.DefaultHeaders[$key]
            }
        }

        # === Check whether DefaultHeaders already provides a non-empty Authorization value ===
        $hasAuthorizationHeader = $false
        foreach ($key in $Headers.Keys) {
            if ([string]::Equals([string]$key, 'Authorization', [System.StringComparison]::OrdinalIgnoreCase) -and
                -not [string]::IsNullOrWhiteSpace([string]$Headers[$key])) {
                $hasAuthorizationHeader = $true
                break
            }
        }

        # === Resolve credential-derived headers when Authorization is not already present ===
        if (-not $hasAuthorizationHeader) {

            # Build Get-ServiceCredential parameter set based on active auth mode
            $credParams = @{
                Service     = $Service
                Environment = $Environment
            }

            if ($useSSOMode) {
                # Pass UseSSO — with inline provider value if supplied
                if (-not [string]::IsNullOrWhiteSpace([string]$UseSSO)) {
                    $credParams['UseSSO'] = [string]$UseSSO
                } else {
                    $credParams['UseSSO'] = $null
                }
            } elseif ($useTokenMode) {
                # Pass UseToken — with inline token value if supplied
                if (-not [string]::IsNullOrWhiteSpace([string]$UseToken)) {
                    $credParams['UseToken'] = [string]$UseToken
                } else {
                    $credParams['UseToken'] = $null
                }
                # Pass vault-related parameters for test call validation and session-only override
                if ($SessionOnly) { $credParams['SessionOnly'] = $true }
                if ($Endpoint)    { $credParams['Endpoint']    = $Endpoint }
                if ($BaseUrl)     { $credParams['BaseUrl']     = $BaseUrl }
            }
            # No else needed — default omits both, Get-ServiceCredential defaults to Basic Auth

            $credentialHeaders = Get-ServiceCredential @credParams

            # Apply credential-derived headers only to keys not already defined
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
            Write-Verbose "Using Authorization header from DefaultHeaders; skipping credential resolution."
        }

        return @{
            Service     = $Service
            Environment = $Environment
            BaseUrl     = $BaseUrl
            Headers     = $Headers
        }

    } catch {
        Write-ServiceApiHandledError -ErrorRecord $_ -Severity 'Critical'
        return $null
    }
}
