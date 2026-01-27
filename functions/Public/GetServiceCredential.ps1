function Get-ServiceCredential {
    <#
    .SYNOPSIS
        Retrieves the appropriate Authorization header for an API service and environment.

    .DESCRIPTION
        Supports dynamic resolution of Basic Auth or Token authentication.
        If no -Service/-Environment is specified, returns global Basic Auth.
        Falls back to service-global or environment-wide credentials if specific combination is missing.
        If no stored credential is found, prompts the user and stores the result under the 'global' scope.

    .PARAMETER Service
        The API service name (e.g., jira, confluence, custom-api).

    .PARAMETER Environment
        (Optional) The environment to target: qa, prod, dev. Defaults to prod.

    .PARAMETER UseToken
        Use token-based authentication instead of Basic Auth.

    .EXAMPLE
        Get-ServiceCredential
        # Returns global Basic Auth headers

    .EXAMPLE
        Get-ServiceCredential -Service jira
        # Returns headers for jira with fallback resolution

    .EXAMPLE
        Get-ServiceCredential -Service custom-api -Environment prod -UseToken
        # Returns Bearer token headers for custom-api prod

    .NOTES
        Author      : Matthew Sillett
        Organisation: Australian Signals Directorate
        Version     : 2.0.0
        Date        : 27-JAN-26

        CHANGE LOG
        2.0.0 | 27JAN26 | Refactored from Get-AtlassianCredential to support generalised API services.
        1.2.4 | 24JUN25 | Fixed premature prompt bug; clarified global fallback behaviour.
        1.2.3 | 04JUN25 | Removed deprecated global variable check; unified fallback re-prompt via Set-ServiceCredential.
    #>

    [CmdletBinding()]
    param (
        [string]$Service,
        [string]$Environment = 'prod',
        [switch]$UseToken
    )

    # === Initialise standard headers using helper function ===
    $headers = New-StandardHeaders -Service $Service

    # === Token resolution ===
    if ($UseToken) {
        if ($Service -and $Environment -and $global:ServiceTokens.ContainsKey("$Service-$Environment")) {
            $secure = $global:ServiceTokens["$Service-$Environment"]
        } else {
            throw "Token not found for requested service/environment. No global fallback is allowed for tokens."
        }

        # Convert secure string to plaintext token using helper
        $token = ConvertSecureStringToPlainText -SecureString $secure

        $headers["Authorization"] = "Bearer $token"
        return $headers
    }

    # === Resolve Basic Auth Credential ===
    $cred = $null

    # Priority 1: Exact service + environment match
    $key = New-ServiceKey -Service $Service -Environment $Environment
    if ($Service -and $Environment -and $global:ServiceCredentials.ContainsKey($key)) {
        $cred = $global:ServiceCredentials[$key]

    # Priority 2: Service-global fallback
    } elseif ($Service) {
        $key = New-ServiceKey -Service $Service
        if ($global:ServiceCredentials.ContainsKey($key)) {
            $cred = $global:ServiceCredentials[$key]
        }
    }

    # Priority 3: Any service that matches the environment
    if (-not $cred -and $Environment) {
        foreach ($svc in $global:RegisteredServices) {
            $key = New-ServiceKey -Service $svc -Environment $Environment
            if ($global:ServiceCredentials.ContainsKey($key)) {
                $cred = $global:ServiceCredentials[$key]
                break
            }
        }
    }

    # Priority 4: Global fallback
    if (-not $cred) {
        $key = New-ServiceKey -Global
        if ($global:ServiceCredentials.ContainsKey($key)) {
            Write-Verbose "Using global credential fallback."
            $cred = $global:ServiceCredentials[$key]
        }
    }

    # Prompt only if no credential resolved
    if (-not $cred) {
        Write-Verbose "No stored credentials available for $Service-$Environment. Prompting for service-specific credential."
        try {
            # Prompt for service-specific credential, not global
            Set-ServiceCredential -Service $Service -Environment $Environment
        } catch {
            throw "Interactive credential prompt failed: $_"
        }

        # Try to retrieve the just-stored credential
        $key = New-ServiceKey -Service $Service -Environment $Environment
        if ($global:ServiceCredentials.ContainsKey($key)) {
            $cred = $global:ServiceCredentials[$key]
        } else {
            throw "Credential was not set for $Service-$Environment. Aborting request."
        }
    }

    # === Build Basic Auth Header ===
    $encoded = [Convert]::ToBase64String(
        [Text.Encoding]::ASCII.GetBytes(
            "$($cred.UserName):$($cred.GetNetworkCredential().Password)"
        )
    )
    $headers["Authorization"] = "Basic $encoded"

    return $headers
}
