
function Invoke-ServiceSsoRetry {
    <#
    .SYNOPSIS
        Decides whether an SSO request that received HTTP 403 can be helped by a token refresh,
        and retries it once when it can.

    .DESCRIPTION
        An HTTP 403 from Aria means authenticated but not authorised: the bearer is valid and
        the identity lacks permission. A 401 means the token is stale. A refresh can fix a 401
        and can never fix a 403, so refreshing on every 403 wastes a token exchange (and risks
        an interactive browser login) on a genuine permission denial.

        This function applies two guards so the refresh-and-retry only runs when it can
        plausibly change the outcome:

          Guard 1 - probe the current bearer. The existing bearer is tested against the service's
                    probe endpoint (Get-ServiceProbeEndpoint). A success proves the token is
                    valid, so the 403 is an authorisation denial and the refresh is skipped.
          Guard 2 - token-change check. After the refresh, if the bearer is unchanged a retry
                    would only repeat the 403, so it is skipped.

        When a guard cannot decide (no probe endpoint configured, or the probe itself fails),
        the function falls back to refresh-and-retry, which is never worse than refreshing on
        every 403. The retry is performed once, in place, with no recursion.

        The function does not write handled errors itself. It returns an Outcome and leaves
        error reporting to Invoke-APIRequest, so the module has one place that does that.

        Not exported.

    .PARAMETER Service
        The registered service name.

    .PARAMETER Environment
        The environment. Defaults to 'prod'.

    .PARAMETER BaseUrl
        The resolved service host root, used to build the probe request.

    .PARAMETER Uri
        The full URI of the request that was forbidden.

    .PARAMETER Method
        The HTTP method of the request that was forbidden.

    .PARAMETER Headers
        The headers of the request that was forbidden. The Authorization entry is replaced for
        the retry; the dictionary supplied is not modified.

    .PARAMETER Body
        The serialised request body, if the request had one.

    .OUTPUTS
        PSCustomObject with Outcome, Response and ErrorRecord. Outcome is one of:
        Retried, AuthorisationDenied, BearerUnchanged, RefreshFailed, RetryFailed.

    .EXAMPLE
        $retry = Invoke-ServiceSsoRetry -Service aihc -Environment prod -BaseUrl $resolvedBaseUrl `
            -Uri $uri -Method GET -Headers $mergedHeaders
        if ($retry.Outcome -eq 'Retried') { return $retry.Response }

        Retries a forbidden GET once after a token refresh, and returns the retried response.

    .EXAMPLE
        $retry = Invoke-ServiceSsoRetry -Service aihc -BaseUrl $baseUrl -Uri $uri -Method POST `
            -Headers $headers -Body $json
        $retry.Outcome

        Shows the decision for a POST. AuthorisationDenied means the probe succeeded and no
        refresh was made.

    .EXAMPLE
        $retry = Invoke-ServiceSsoRetry -Service aihc -BaseUrl $baseUrl -Uri $uri -Method GET `
            -Headers $headers -Verbose

        Shows which guard decided the outcome in the verbose output.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.1
        Date        : 06-OCT-26

        CHANGE LOG
        1.0.1 | 06OCT26 | Replaced em dashes with ASCII punctuation and reworded the affected
                          sentences, so the source is plain ASCII and loads on Windows PowerShell 5.1.
        1.0.0 | 06OCT26 | Initial version. The SSO 403 refresh-and-retry and its two guards,
                          extracted from Invoke-APIRequest so the decision logic is testable
                          on its own and the caller reports errors in one place.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Service,

        [string]$Environment = 'prod',

        [Parameter(Mandatory)]
        [string]$BaseUrl,

        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter(Mandatory)]
        [string]$Method,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Headers,

        [string]$Body
    )

    function New-RetryResult {
        param([string]$Outcome, $Response = $null, $ErrorRecord = $null)
        [PSCustomObject]@{ Outcome = $Outcome; Response = $Response; ErrorRecord = $ErrorRecord }
    }

    # === Guard 1: probe the current bearer before refreshing ===
    $probeEndpoint = Get-ServiceProbeEndpoint -Service $Service -Environment $Environment
    if ($probeEndpoint -and $Headers['Authorization']) {
        if (Test-ServiceBearer -BaseUrl $BaseUrl -Endpoint $probeEndpoint -Authorization ([string]$Headers['Authorization'])) {
            Write-Warning "SSO bearer is valid but the request was forbidden; this is an authorisation denial, not a token problem. Skipping refresh."
            return New-RetryResult -Outcome 'AuthorisationDenied'
        }
        Write-Verbose "SSO probe [$probeEndpoint] did not succeed with the current bearer; treating the 403 as possibly stale."
    }

    # === Refresh ===
    $oldToken = $null
    if ([string]$Headers['Authorization'] -match '^Bearer\s+(.+)$') { $oldToken = $Matches[1] }

    $ssoKey = New-ServiceKey -Service $Service -Environment $Environment

    try {
        Write-Verbose "Refreshing SSO token for [$ssoKey] after 403."
        Set-ServiceCredential -Service $Service -Environment $Environment -AuthType SSO -Force

        if (-not $global:ServiceSSOTokens.ContainsKey($ssoKey)) {
            throw "SSO token was not stored for [$ssoKey] after refresh."
        }
        $freshToken = ConvertSecureStringToPlainText -SecureString $global:ServiceSSOTokens[$ssoKey].Token
    } catch {
        return New-RetryResult -Outcome 'RefreshFailed' -ErrorRecord $_
    }

    # === Guard 2: only retry if the bearer actually changed ===
    if ($oldToken -and $freshToken -eq $oldToken) {
        Write-Warning "SSO refresh returned the same bearer; retrying would repeat the 403. Skipping retry."
        return New-RetryResult -Outcome 'BearerUnchanged'
    }

    # === Retry once, in place ===
    $retryHeaders = @{}
    foreach ($headerName in @($Headers.Keys)) { $retryHeaders[$headerName] = $Headers[$headerName] }
    $retryHeaders['Authorization'] = "Bearer ${freshToken}"

    $retryParams = @{ Method = $Method; Uri = $Uri; Headers = $retryHeaders; ErrorAction = 'Stop' }
    if ($Body) { $retryParams['Body'] = $Body }

    try {
        Write-Verbose "Retrying request after SSO token refresh."
        $response = Invoke-ServiceApiHttpRequest @retryParams
        return New-RetryResult -Outcome 'Retried' -Response $response
    } catch {
        return New-RetryResult -Outcome 'RetryFailed' -ErrorRecord $_
    }
}
