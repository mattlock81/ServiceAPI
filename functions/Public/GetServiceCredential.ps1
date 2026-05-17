function Get-ServiceCredential {
    <#
    .SYNOPSIS
        Resolves authentication headers for a registered service.

    .DESCRIPTION
        Resolves authentication headers for a registered service. The authentication type
        is specified via -AuthType (Basic, Token, or SSO). Defaults to Basic.

        Basic Auth (-AuthType Basic):
        When SecretManagement is available and -SessionOnly is not set, attempts vault
        resolution first using the specified -Label. Falls through to the four-tier
        in-memory fallback on vault miss, then interactive prompt.

        Token (-AuthType Token):
        When SecretManagement is available and -SessionOnly is not set, resolves a token
        from the vault using the specified -Label via Resolve-VaultCredential. The token
        value determines the header format — no key component produces a Bearer header,
        key:secret produces a Basic header. When vault is unavailable or -SessionOnly is
        set, falls back to $global:ServiceTokens with interactive prompt.

        SSO (-AuthType SSO):
        Resolves a short-lived OAuth Bearer token from $global:ServiceSSOTokens. Provider
        is resolved from the service registry. Refreshes automatically when stale. SSO
        tokens are never stored in the vault. -Label and -SessionOnly are ignored for SSO.

    .PARAMETER Service
        The API service name (e.g., jira, confluence, google).

    .PARAMETER AuthType
        The authentication type to resolve. Accepted values: Basic, Token, SSO.
        Defaults to Basic.

    .PARAMETER Label
        The vault label to retrieve. Defaults to 'default'.
        Applies to Basic and Token auth types.

    .PARAMETER Environment
        The environment to target: qa, prod, dev. Defaults to prod.

    .PARAMETER SessionOnly
        Bypasses vault lookup and storage. Prompts interactively and stores the result
        in the session store only. Applies to Basic and Token — ignored for SSO.

    .PARAMETER Endpoint
        Passed through to Resolve-VaultCredential for test call validation.

    .PARAMETER BaseUrl
        Passed through to Resolve-VaultCredential for test call validation.

    .EXAMPLE
        Get-ServiceCredential -Service jira -Environment prod
        Resolves Basic Auth headers for jira in prod — vault first, then fallback chain.

    .EXAMPLE
        Get-ServiceCredential -Service jira -Environment prod -AuthType Basic -Label matt
        Resolves the 'matt' labelled Basic Auth credential from the vault.

    .EXAMPLE
        Get-ServiceCredential -Service cloudflare -Environment prod -AuthType Token
        Resolves the default token credential from the vault for cloudflare in prod.

    .EXAMPLE
        Get-ServiceCredential -Service cloudflare -Environment prod -AuthType Token -Label work
        Resolves the 'work' labelled token credential from the vault.

    .EXAMPLE
        Get-ServiceCredential -Service google -Environment prod -AuthType SSO
        Resolves SSO Bearer headers using the registered GCloud provider.

    .EXAMPLE
        Get-ServiceCredential -Service jira -Environment prod -SessionOnly
        Prompts interactively for Basic Auth — vault bypassed, session store only.

    .NOTES
        Author      : Matthew Sillett
        Organisation: Australian Signals Directorate
        Version     : 2.5.0
        Date        : 17-MAY-26

        CHANGE LOG
        2.5.0 | 17MAY26 | Replaced -UseToken and -UseSSO with -AuthType [ValidateSet] parameter.
                          Added -Label parameter for named vault credential retrieval. Auth mode
                          selection is now explicit and tab-completed. Resolution logic updated
                          to branch on $AuthType value throughout.
        2.4.4 | 17MAY26 | Extended vault resolution to Basic Auth (Priority 2).
        2.4.3 | 17MAY26 | Australian/British English spelling applied throughout.
        2.4.0 | 17MAY26 | Added SecretManagement vault resolution tier into Priority 1 (token mode).
        2.3.0 | 16MAY26 | Added [ArgumentCompleter] on -Service for tab completion from live registry.
        2.2.0 | 16MAY26 | Added -UseSSO parameter for SSO-based credential resolution.
        2.1.0 | 28MAR26 | Enforced token-only credential resolution with no Basic fallback.
        2.0.0 | 27JAN26 | Refactored from Get-AtlassianCredential to support generalised API services.
        1.2.4 | 24JUN25 | Fixed premature prompt bug; clarified global fallback behaviour.
        1.2.3 | 04JUN25 | Removed deprecated global variable check.
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

        [ValidateSet('Basic', 'Token', 'SSO')]
        [string]$AuthType = 'Basic',

        # Vault label — applies to Basic and Token auth types. Defaults to 'default'.
        [string]$Label = 'default',

        [string]$Environment = 'prod',

        # Bypasses vault lookup and storage — session store only. Ignored for SSO.
        [switch]$SessionOnly,

        # Passed through to Resolve-VaultCredential for test call validation.
        [string]$Endpoint,
        [string]$BaseUrl
    )

    # Initialise standard headers
    $headers = New-StandardHeaders -Service $Service

    # =========================================================================
    # SSO MODE — short-lived OAuth Bearer token with lazy refresh
    # =========================================================================
    if ($AuthType -eq 'SSO') {

        if ([string]::IsNullOrWhiteSpace($Service) -or [string]::IsNullOrWhiteSpace($Environment)) {
            throw "SSO credential resolution requires both -Service and -Environment."
        }

        $key = New-ServiceKey -Service $Service -Environment $Environment

        # Resolve provider from service registry — never supplied by caller
        $ssoProvider = $null
        if ($global:ServiceRegistry.ContainsKey($Service) -and
            $global:ServiceRegistry[$Service].ContainsKey($Environment) -and
            $global:ServiceRegistry[$Service][$Environment].SSOProvider) {
            $ssoProvider = $global:ServiceRegistry[$Service][$Environment].SSOProvider
        }

        if (-not $ssoProvider) {
            throw "No SSO provider registered for [$Service-$Environment]. Register one via Register-CustomService -SSOProvider."
        }

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
            $headers['Authorization'] = "Bearer ${token}"
            return $headers
        }

        # No stored SSO token — delegate to Set-ServiceCredential
        Write-Verbose "No SSO token found for [$key]. Delegating to Set-ServiceCredential."
        Set-ServiceCredential -Service $Service -Environment $Environment -AuthType SSO -Force

        if (-not $global:ServiceSSOTokens.ContainsKey($key)) {
            throw "SSO token was not stored for [$key] after acquisition. Aborting request."
        }

        $token = ConvertSecureStringToPlainText -SecureString $global:ServiceSSOTokens[$key].Token
        $headers['Authorization'] = "Bearer ${token}"
        return $headers
    }

    # =========================================================================
    # TOKEN MODE
    # =========================================================================
    if ($AuthType -eq 'Token') {

        if ([string]::IsNullOrWhiteSpace($Service) -or [string]::IsNullOrWhiteSpace($Environment)) {
            throw "Token credential resolution requires both -Service and -Environment."
        }

        $key = New-ServiceKey -Service $Service -Environment $Environment

        # =====================================================================
        # VAULT PATH — when SecretManagement is available and not -SessionOnly
        # =====================================================================
        if ($script:ServiceApiHasSecretManagement -and -not $SessionOnly) {

            $vaultParams = @{
                Service     = $Service
                Environment = $Environment
                AuthType    = 'Token'
                Label       = $Label
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
                $headers['Authorization'] = "Bearer ${credSecret}"
            } else {
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
        if ($global:ServiceTokens.ContainsKey($key)) {
            $token = ConvertSecureStringToPlainText -SecureString $global:ServiceTokens[$key]
            $headers['Authorization'] = "Bearer ${token}"
            return $headers
        }

        # Token not found — prompt interactively
        Write-Verbose "No token found for [$key]. Prompting interactively."
        Set-ServiceCredential -Service $Service -Environment $Environment -AuthType Token -Label $Label

        if (-not $global:ServiceTokens.ContainsKey($key)) {
            throw "Token was not stored for [$key] after prompt. Aborting request."
        }

        $token = ConvertSecureStringToPlainText -SecureString $global:ServiceTokens[$key]
        $headers['Authorization'] = "Bearer ${token}"
        return $headers
    }

    # =========================================================================
    # BASIC AUTH MODE — default
    # =========================================================================
    $key = New-ServiceKey -Service $Service -Environment $Environment

    # =====================================================================
    # VAULT PATH — when SecretManagement is available and not -SessionOnly
    # =====================================================================
    if ($script:ServiceApiHasSecretManagement -and -not $SessionOnly) {

        $vaultParams = @{
            Service     = $Service
            Environment = $Environment
            AuthType    = 'Basic'
            Label       = $Label
        }
        if ($Endpoint) { $vaultParams['Endpoint'] = $Endpoint }
        if ($BaseUrl)  { $vaultParams['BaseUrl']  = $BaseUrl  }

        $resolved = Resolve-VaultCredential @vaultParams

        if ($null -ne $resolved) {
            $b64 = [Convert]::ToBase64String(
                [Text.Encoding]::ASCII.GetBytes(
                    "$($resolved.UserName):$($resolved.GetNetworkCredential().Password)"
                )
            )
            $headers['Authorization'] = "Basic $b64"
            $global:ServiceCredentials[$key] = $resolved
            return $headers
        }

        # Vault returned null — user cancelled
        throw "Credential resolution cancelled for [$key]."
    }

    # =====================================================================
    # NON-VAULT PATH — four-tier in-memory fallback then interactive prompt
    # =====================================================================
    $cred = $null

    # Tier 1: Exact service + environment match
    if ($Service -and $Environment -and $global:ServiceCredentials.ContainsKey($key)) {
        $cred = $global:ServiceCredentials[$key]

    # Tier 2: Service-global fallback
    } elseif ($Service) {
        $svcKey = New-ServiceKey -Service $Service
        if ($global:ServiceCredentials.ContainsKey($svcKey)) {
            $cred = $global:ServiceCredentials[$svcKey]
        }
    }

    # Tier 3: Any registered service matching the environment
    if (-not $cred -and $Environment) {
        foreach ($svc in $global:RegisteredServices) {
            $envKey = New-ServiceKey -Service $svc -Environment $Environment
            if ($global:ServiceCredentials.ContainsKey($envKey)) {
                $cred = $global:ServiceCredentials[$envKey]
                break
            }
        }
    }

    # Tier 4: Global fallback
    if (-not $cred) {
        $globalKey = New-ServiceKey -Global
        if ($global:ServiceCredentials.ContainsKey($globalKey)) {
            Write-Verbose "Using global credential fallback."
            $cred = $global:ServiceCredentials[$globalKey]
        }
    }

    # No credential resolved — prompt and store for future use
    if (-not $cred) {
        Write-Verbose "No stored Basic Auth credential for [$Service-$Environment]. Prompting."
        try {
            Set-ServiceCredential -Service $Service -Environment $Environment -AuthType Basic -Label $Label
        } catch {
            throw "Interactive credential prompt failed: $_"
        }

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
