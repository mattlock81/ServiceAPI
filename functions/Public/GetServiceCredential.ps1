function Get-ServiceCredential {
    <#
    .SYNOPSIS
        Resolves authentication headers for a registered service.

    .DESCRIPTION
        Resolves authentication headers for a registered service.
        Basic authentication is the default behavior and uses the existing fallback order. If no
        matching Basic credential is found, the function prompts and stores a service-specific
        credential before retrying resolution.

        When -UseToken is specified, the function switches to token-only resolution for the specified
        service and environment. In token mode, Basic fallback is not attempted, prompting is not
        performed, and missing token credentials cause an error.

    .PARAMETER Service
        The API service name (e.g., jira, confluence, custom-api).

    .PARAMETER Environment
        (Optional) The environment to target: qa, prod, dev. Defaults to prod.

    .PARAMETER UseToken
        Forces token-only credential lookup for the specified service and environment.
        Requires a stored token credential and does not allow Basic fallback.

    .EXAMPLE
        Get-ServiceCredential -Service jira -Environment prod
        Resolves Basic authentication headers for jira in prod.

    .EXAMPLE
        Get-ServiceCredential -Service cloudflare -Environment prod -UseToken
        Resolves Bearer token headers for cloudflare in prod without Basic fallback.

    .NOTES
        Author      : Matthew Sillett
        Organisation: Australian Signals Directorate
        Version     : 2.1.0
        Date        : 28-MAR-26

        CHANGE LOG
        2.1.0 | 28MAR26 | Enforced token-only credential resolution with no Basic fallback when -UseToken is specified.
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

    # === Token resolution is exclusive and does not fall back to Basic ===
    if ($UseToken) {
        if ([string]::IsNullOrWhiteSpace($Service) -or [string]::IsNullOrWhiteSpace($Environment)) {
            throw "Token-based credential resolution requires both -Service and -Environment."
        }

        $key = New-ServiceKey -Service $Service -Environment $Environment
        if (-not $global:ServiceTokens.ContainsKey($key)) {
            throw "Token credential not found for [$key]. Token mode does not support Basic fallback. Run Set-ServiceCredential -Service $Service -Environment $Environment -Token <token>."
        }

        $secure = $global:ServiceTokens[$key]

        # Convert secure string to plaintext token using helper
        $token = ConvertSecureStringToPlainText -SecureString $secure

        $headers["Authorization"] = "Bearer $token"
        return $headers
    }

    # === Resolve Basic Auth Credential using the existing fallback order ===
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
