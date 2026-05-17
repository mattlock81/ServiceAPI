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

        Token mode (-UseToken) resolves a credential using the following priority chain:
        1. When SecretManagement is available, Resolve-VaultCredential handles the full flow:
           vault label lookup, interactive prompt with test call validation, and optional vault
           write-back. The -UseToken value is interpreted as a credential label or raw token via
           heuristic. -SessionOnly bypasses vault entirely for session-only credentials.
        2. When SecretManagement is not available, the existing $global:ServiceTokens store is
           used with interactive prompt fallback as before.

        SSO mode (-UseSSO) resolves a short-lived OAuth Bearer token from $global:ServiceSSOTokens.
        If the token is present and fresh, it is used directly. If stale (within 5 minutes of expiry
        or already expired), it is refreshed automatically via the stored provider. If no SSO token
        is found, Set-ServiceCredential is called internally to obtain and store one.

    .PARAMETER Service
        The API service name (e.g., jira, confluence, opnsense).

    .PARAMETER Environment
        The environment to target: qa, prod, dev. Defaults to prod.

    .PARAMETER UseToken
        Switches to token-based credential resolution. When SecretManagement is available,
        accepts a credential label or raw token value. When unavailable, accepts an inline
        token string. Prompts interactively if no value is supplied or label not found.

    .PARAMETER UseSSO
        Switches to SSO credential resolution. Accepts an optional inline provider name.
        Performs lazy refresh when the stored token is stale. No Basic or token fallback.

    .PARAMETER SessionOnly
        Bypasses vault lookup and storage when SecretManagement is available. Prompts
        interactively and stores the result in the session token store only.

    .PARAMETER Endpoint
        Passed through to Resolve-VaultCredential for test call validation.

    .PARAMETER BaseUrl
        Passed through to Resolve-VaultCredential for test call validation.

    .EXAMPLE
        Get-ServiceCredential -Service jira -Environment prod
        Resolves Basic Auth headers for jira in prod using the four-tier fallback.

    .EXAMPLE
        Get-ServiceCredential -Service opnsense -Environment prod -UseToken
        Vault-enabled: prompts for credentials, test calls, offers vault storage.

    .EXAMPLE
        Get-ServiceCredential -Service opnsense -Environment prod -UseToken 'matt'
        Vault-enabled: retrieves the 'matt' labelled credential from the vault.

    .EXAMPLE
        Get-ServiceCredential -Service cloudflare -Environment prod -UseToken 'cfat_xxxxx'
        Raw token — stored directly, no vault label lookup.

    .EXAMPLE
        Get-ServiceCredential -Service googleapi -Environment prod -UseSSO
        Resolves SSO Bearer headers using the registered GCloud provider.

    .EXAMPLE
        Get-ServiceCredential -Service opnsense -Environment prod -UseToken -SessionOnly
        Prompts interactively, stores in session only — vault bypassed.

    .NOTES
        Author      : Matthew Sillett
        Organisation: Australian Signals Directorate
        Version     : 2.4.0
        Date        : 17-MAY-26

        CHANGE LOG
        2.4.0 | 17MAY26 | Added SecretManagement vault resolution tier into Priority 1 (token mode).
                          When vault is detected, Resolve-VaultCredential handles label lookup,
                          interactive prompt, test call validation, and vault write-back.
                          -SessionOnly and -Endpoint and -BaseUrl parameters added for vault flow.
        2.3.0 | 16MAY26 | Added [ArgumentCompleter] on -Service for tab completion from live registry.
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

        # -UseToken accepts a vault label or raw token value.
        # Defaults to 'default' when specified without a value — resolves the default vault label.
        [AllowEmptyString()]
        [string]$UseToken = 'default',

        # -UseSSO accepts an optional inline provider name. Presence alone activates SSO mode.
        [AllowEmptyString()]
        [string]$UseSSO = '',

        # -SessionOnly bypasses vault lookup and storage — session token store only.
        [switch]$SessionOnly,

        # Passed through to Resolve-VaultCredential for test call validation.
        [string]$Endpoint,
        [string]$BaseUrl
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

        if ($global:ServiceSSOTokens.ContainsKey($key)) {
            $entry = $global:ServiceSSOTokens[$key]

            # Refresh if within 5 minutes of expiry or already expired
            if ([DateTime]::UtcNow -ge $entry.ExpiresAt.AddMinutes(-5)) {
                Write-Verbose "SSO token for [$key] is stale. Refreshing via provider [$($entry.Provider)]."
                $freshToken = Invoke-SSOProviderToken -Provider $entry.Provider
                $global:ServiceSSOTokens[$key] = @{
                    Token     = (ConvertTo-SecureString -String $freshToken -AsPlainText -Force)
                    ExpiresAt = [DateTime]::UtcNow.AddMinutes(55)
                    Provider  = $entry.Provider
                }
                $entry = $global:ServiceSSOTokens[$key]
                Write-Verbose "SSO token refreshed for [$key]. New expiry: [$($entry.ExpiresAt)] UTC."
            }

            $token = ConvertSecureStringToPlainText -SecureString $entry.Token
            $headers['Authorization'] = "Bearer $token"
            return $headers
        }

        # No stored SSO token — delegate to Set-ServiceCredential
        Write-Verbose "No SSO token found for [$key]. Delegating to Set-ServiceCredential."

        if (-not [string]::IsNullOrWhiteSpace([string]$UseSSO)) {
            Set-ServiceCredential -Service $Service -Environment $Environment -UseSSO ([string]$UseSSO) -Force
        } else {
            Set-ServiceCredential -Service $Service -Environment $Environment -UseSSO -Force
        }

        if (-not $global:ServiceSSOTokens.ContainsKey($key)) {
            throw "SSO token was not stored for [$key] after acquisition. Aborting request."
        }

        $token = ConvertSecureStringToPlainText -SecureString $global:ServiceSSOTokens[$key].Token
        $headers['Authorization'] = "Bearer $token"
        return $headers
    }

    # =========================================================================
    # PRIORITY 1 — Token mode
    # =========================================================================
    if ($useTokenMode) {

        if ([string]::IsNullOrWhiteSpace($Service) -or [string]::IsNullOrWhiteSpace($Environment)) {
            throw "Token credential resolution requires both -Service and -Environment."
        }

        $key         = New-ServiceKey -Service $Service -Environment $Environment
        $labelOrToken = if ([string]::IsNullOrWhiteSpace([string]$UseToken)) { 'default' } else { [string]$UseToken }

        # =====================================================================
        # VAULT PATH — when SecretManagement is available and not -SessionOnly
        # =====================================================================
        if ($script:ServiceApiHasSecretManagement -and -not $SessionOnly) {

            $vaultParams = @{
                Service     = $Service
                Environment = $Environment
                Label       = $labelOrToken
            }
            if ($Endpoint) { $vaultParams['Endpoint'] = $Endpoint }
            if ($BaseUrl)  { $vaultParams['BaseUrl']  = $BaseUrl  }

            $resolved = Resolve-VaultCredential @vaultParams

            if ($null -eq $resolved) {
                throw "Credential resolution cancelled for [$key]."
            }

            # Split resolved "key:secret" string on first colon only
            $colonIndex = $resolved.IndexOf(':')
            $credKey    = if ($colonIndex -gt 0) { $resolved.Substring(0, $colonIndex) } else { '' }
            $credSecret = $resolved.Substring($colonIndex + 1)

            if ([string]::IsNullOrWhiteSpace($credKey)) {
                # No key component — Bearer token
                $headers['Authorization'] = "Bearer ${credSecret}"
            } else {
                # Key and secret present — Basic Auth
                $b64 = [Convert]::ToBase64String(
                    [Text.Encoding]::ASCII.GetBytes("${credKey}:${credSecret}")
                )
                $headers['Authorization'] = "Basic $b64"
            }
            return $headers
        }

        # =====================================================================
        # NON-VAULT PATH — SecretManagement unavailable or -SessionOnly
        # =====================================================================

        # If an inline raw token value was supplied, store it first
        if (-not [string]::IsNullOrWhiteSpace([string]$UseToken)) {
            Set-ServiceCredential -Service $Service -Environment $Environment -UseToken ([string]$UseToken) -Force
        }

        if ($global:ServiceTokens.ContainsKey($key)) {
            $token = ConvertSecureStringToPlainText -SecureString $global:ServiceTokens[$key]
            $headers['Authorization'] = "Bearer $token"
            return $headers
        }

        # Token not found — prompt interactively
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
