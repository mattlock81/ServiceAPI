function Get-ServiceCredential {
    <#
    .SYNOPSIS
        Resolves authentication headers for a registered service.

    .DESCRIPTION
        Resolves authentication headers for a registered service using one of three modes.

        Basic Auth is the default. When neither -UseToken nor -UseSSO is specified, the function
        resolves a PSCredential from the Basic Auth credential store using a four-tier fallback:
        service+environment, service-global, any service matching the environment, global. If no
        credential is found, the function prompts interactively and stores the result.

        Token mode (-UseToken) resolves a static Bearer token from $global:ServiceTokens for the
        specified service and environment. No Basic fallback is attempted. If no token is found,
        the function prompts interactively and stores the result for future use.

        SSO mode (-UseSSO) resolves a short-lived OAuth Bearer token from $global:ServiceSSOTokens.
        If the token is present and fresh, it is used directly. If stale (within 5 minutes of expiry
        or already expired), it is refreshed automatically via the stored provider. If no SSO token
        is found, Set-ServiceCredential is called internally to obtain and store one. An optional
        inline provider name may be passed to override registry lookup.

    .PARAMETER Service
        The API service name (e.g., jira, confluence, googleapi).

    .PARAMETER Environment
        The environment to target: qa, prod, dev. Defaults to prod.

    .PARAMETER UseToken
        Switches to token-only credential resolution. Accepts an optional inline token value.
        No Basic fallback. If no stored token exists and no inline value is supplied, prompts
        interactively.

    .PARAMETER UseSSO
        Switches to SSO credential resolution. Accepts an optional inline provider name.
        Performs lazy refresh when the stored token is stale. No Basic or token fallback.

    .EXAMPLE
        Get-ServiceCredential -Service jira -Environment prod
        Resolves Basic Auth headers for jira in prod using the four-tier fallback.

    .EXAMPLE
        Get-ServiceCredential -Service cloudflare -Environment prod -UseToken
        Resolves Bearer token headers for cloudflare in prod. Prompts if not stored.

    .EXAMPLE
        Get-ServiceCredential -Service cloudflare -Environment prod -UseToken 'cfat_xxxxx'
        Stores the supplied token for cloudflare in prod and resolves Bearer headers.

    .EXAMPLE
        Get-ServiceCredential -Service googleapi -Environment prod -UseSSO
        Resolves SSO Bearer headers for googleapi in prod using the registered GCloud provider.

    .EXAMPLE
        Get-ServiceCredential -Service googleapi -Environment prod -UseSSO GCloud
        Resolves SSO Bearer headers using the GCloud provider explicitly.

    .NOTES
        Author      : Matthew Sillett
        Organisation: Australian Signals Directorate
        Version     : 2.2.0
        Date        : 16-MAY-26

        CHANGE LOG
        2.2.0 | 16MAY26 | Added -UseSSO parameter for SSO-based credential resolution with lazy
                          refresh via provider dispatch. -UseToken changed from [switch] to [string]
                          to support optional inline token value with interactive prompt fallback.
                          SSO resolution added as priority 0 before token and Basic Auth paths.
        2.1.1 | 28MAR26 | Documentation refresh for centralised handled-error reporting and fallback behavior.
        2.1.0 | 28MAR26 | Enforced token-only credential resolution with no Basic fallback when -UseToken is specified.
        2.0.0 | 27JAN26 | Refactored from Get-AtlassianCredential to support generalised API services.
        1.2.4 | 24JUN25 | Fixed premature prompt bug; clarified global fallback behaviour.
        1.2.3 | 04JUN25 | Removed deprecated global variable check; unified fallback re-prompt via Set-ServiceCredential.
    #>

    [CmdletBinding()]
    param (
        [string]$Service,
        [string]$Environment = 'prod',

        # -UseToken accepts an optional inline token value. Presence alone activates token mode.
        [AllowNull()][AllowEmptyString()]
        [object]$UseToken,

        # -UseSSO accepts an optional inline provider name. Presence alone activates SSO mode.
        [AllowNull()][AllowEmptyString()]
        [object]$UseSSO
    )

    $useTokenMode = $PSBoundParameters.ContainsKey('UseToken')
    $useSSOMode   = $PSBoundParameters.ContainsKey('UseSSO')

    # Initialise standard headers
    $headers = New-StandardHeaders -Service $Service

    # =========================================================================
    # PRIORITY 0 — SSO mode: short-lived OAuth Bearer token with lazy refresh
    # =========================================================================
    if ($useSSOMode) {

        if ([string]::IsNullOrWhiteSpace($Service) -or [string]::IsNullOrWhiteSpace($Environment)) {
            throw "SSO credential resolution requires both -Service and -Environment."
        }

        $key = New-ServiceKey -Service $Service -Environment $Environment

        # Check whether a stored SSO token exists for this service-environment key
        if ($global:ServiceSSOTokens.ContainsKey($key)) {
            $entry = $global:ServiceSSOTokens[$key]

            # Refresh if within 5 minutes of expiry or already expired
            if ([DateTime]::UtcNow -ge $entry.ExpiresAt.AddMinutes(-5)) {
                Write-Verbose "SSO token for [$key] is stale. Refreshing via provider [$($entry.Provider)]."

                # Obtain a fresh token via provider dispatch
                $freshToken = Invoke-SSOProviderToken -Provider $entry.Provider

                # Update the SSO token store with the refreshed token and new expiry
                $global:ServiceSSOTokens[$key] = @{
                    Token     = (ConvertTo-SecureString -String $freshToken -AsPlainText -Force)
                    ExpiresAt = [DateTime]::UtcNow.AddMinutes(55)
                    Provider  = $entry.Provider
                }

                $entry = $global:ServiceSSOTokens[$key]
                Write-Verbose "SSO token refreshed for [$key]. New expiry: [$($entry.ExpiresAt)] UTC."
            }

            # Inject Bearer header using the stored (or just-refreshed) token
            $token = ConvertSecureStringToPlainText -SecureString $entry.Token
            $headers['Authorization'] = "Bearer $token"
            return $headers
        }

        # No stored SSO token — delegate to Set-ServiceCredential to obtain and store one.
        # Pass inline provider string if supplied, otherwise let Set-ServiceCredential
        # resolve from the registry or prompt interactively.
        Write-Verbose "No SSO token found for [$key]. Delegating to Set-ServiceCredential."

        if (-not [string]::IsNullOrWhiteSpace([string]$UseSSO)) {
            Set-ServiceCredential -Service $Service -Environment $Environment -UseSSO ([string]$UseSSO) -Force
        } else {
            Set-ServiceCredential -Service $Service -Environment $Environment -UseSSO -Force
        }

        # Retrieve the now-stored SSO token
        if (-not $global:ServiceSSOTokens.ContainsKey($key)) {
            throw "SSO token was not stored for [$key] after acquisition. Aborting request."
        }

        $token = ConvertSecureStringToPlainText -SecureString $global:ServiceSSOTokens[$key].Token
        $headers['Authorization'] = "Bearer $token"
        return $headers
    }

    # =========================================================================
    # PRIORITY 1 — Token mode: static long-lived Bearer token
    # =========================================================================
    if ($useTokenMode) {

        if ([string]::IsNullOrWhiteSpace($Service) -or [string]::IsNullOrWhiteSpace($Environment)) {
            throw "Token credential resolution requires both -Service and -Environment."
        }

        $key = New-ServiceKey -Service $Service -Environment $Environment

        # If an inline token value was supplied, store it first
        if (-not [string]::IsNullOrWhiteSpace([string]$UseToken)) {
            Set-ServiceCredential -Service $Service -Environment $Environment -UseToken ([string]$UseToken) -Force
        }

        # Check the token store
        if ($global:ServiceTokens.ContainsKey($key)) {
            $token = ConvertSecureStringToPlainText -SecureString $global:ServiceTokens[$key]
            $headers['Authorization'] = "Bearer $token"
            return $headers
        }

        # Token not found and no inline value supplied — prompt interactively
        Write-Verbose "No token found for [$key]. Prompting interactively."
        Set-ServiceCredential -Service $Service -Environment $Environment -UseToken

        if (-not $global:ServiceTokens.ContainsKey($key)) {
            throw "Token was not stored for [$key] after prompt. Aborting request."
        }

        $token = ConvertSecureStringToPlainText -SecureString $global:ServiceTokens[$key]
        $headers['Authorization'] = "Bearer $token"
        return $headers
    }

    # =========================================================================
    # PRIORITY 2 — Basic Auth: default four-tier fallback
    # =========================================================================
    $cred = $null

    # Tier 1: Exact service + environment match
    $key = New-ServiceKey -Service $Service -Environment $Environment
    if ($Service -and $Environment -and $global:ServiceCredentials.ContainsKey($key)) {
        $cred = $global:ServiceCredentials[$key]

    # Tier 2: Service-global fallback
    } elseif ($Service) {
        $key = New-ServiceKey -Service $Service
        if ($global:ServiceCredentials.ContainsKey($key)) {
            $cred = $global:ServiceCredentials[$key]
        }
    }

    # Tier 3: Any registered service matching the environment
    if (-not $cred -and $Environment) {
        foreach ($svc in $global:RegisteredServices) {
            $key = New-ServiceKey -Service $svc -Environment $Environment
            if ($global:ServiceCredentials.ContainsKey($key)) {
                $cred = $global:ServiceCredentials[$key]
                break
            }
        }
    }

    # Tier 4: Global fallback
    if (-not $cred) {
        $key = New-ServiceKey -Global
        if ($global:ServiceCredentials.ContainsKey($key)) {
            Write-Verbose "Using global credential fallback."
            $cred = $global:ServiceCredentials[$key]
        }
    }

    # No credential resolved — prompt and store for future use
    if (-not $cred) {
        Write-Verbose "No stored Basic credential for [$Service-$Environment]. Prompting."
        try {
            Set-ServiceCredential -Service $Service -Environment $Environment
        } catch {
            throw "Interactive credential prompt failed: $_"
        }

        $key = New-ServiceKey -Service $Service -Environment $Environment
        if ($global:ServiceCredentials.ContainsKey($key)) {
            $cred = $global:ServiceCredentials[$key]
        } else {
            throw "Credential was not set for [$Service-$Environment]. Aborting request."
        }
    }

    # Build Basic Auth header from resolved credential
    $encoded = [Convert]::ToBase64String(
        [Text.Encoding]::ASCII.GetBytes(
            "$($cred.UserName):$($cred.GetNetworkCredential().Password)"
        )
    )
    $headers['Authorization'] = "Basic $encoded"
    return $headers
}
