
function Test-ServiceBearer {
    <#
    .SYNOPSIS
        Tests whether a bearer token is currently accepted by a service.

    .DESCRIPTION
        Sends a GET request with the bearer to a cheap, read-only probe endpoint and reports
        whether it succeeded. The result never throws: a failure of any kind (401, 403, 5xx,
        a transport error) returns $false, with the HTTP status written to the verbose stream.

        The token is supplied either as a SecureString (-Token, sent as a Bearer header) or as
        a complete Authorization header value (-Authorization). Neither the token nor the
        header value is ever written to a stream.

        Used by Invoke-AriaOidcLogin to choose between the OIDC access token and the
        iaas/api/login token, and by Invoke-ServiceSsoRetry to decide whether a 403 is a
        stale token or an authorisation denial. Not exported.

    .PARAMETER BaseUrl
        The service host root.

    .PARAMETER Endpoint
        The relative probe endpoint, for example 'iaas/api/projects?$top=1'.

    .PARAMETER Token
        The bearer token as a SecureString.

    .PARAMETER Authorization
        A complete Authorization header value, for example 'Bearer abc123'.

    .PARAMETER TimeoutSec
        Seconds to wait for the probe. Defaults to 20.

    .EXAMPLE
        Test-ServiceBearer -BaseUrl 'https://aria.example.com' -Endpoint 'iaas/api/projects?$top=1' -Token $bearer

        Returns $true when the SecureString bearer is accepted by the IaaS API.

    .EXAMPLE
        Test-ServiceBearer -BaseUrl $resolvedBaseUrl -Endpoint $probe -Authorization $headers['Authorization']

        Tests the bearer already present in a request's headers.

    .EXAMPLE
        if (-not (Test-ServiceBearer -BaseUrl $baseUrl -Endpoint $probe -Token $token -Verbose)) {
            Write-Warning 'The token is stale or not authorised for the probe endpoint.'
        }

        Shows the verbose output, which records the HTTP status of a failed probe.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.0
        Date        : 06-OCT-26

        CHANGE LOG
        1.0.0 | 06OCT26 | Initial version. Replaces the duplicated bearer probes in
                          Invoke-APIRequest and Invoke-AriaOidcLogin.
    #>

    [CmdletBinding(DefaultParameterSetName = 'Token')]
    param (
        [Parameter(Mandatory)]
        [string]$BaseUrl,

        [Parameter(Mandatory)]
        [string]$Endpoint,

        [Parameter(Mandatory, ParameterSetName = 'Token')]
        [securestring]$Token,

        [Parameter(Mandatory, ParameterSetName = 'Header')]
        [string]$Authorization,

        [ValidateRange(1, 300)]
        [int]$TimeoutSec = 20
    )

    if ($PSCmdlet.ParameterSetName -eq 'Token') {
        $authorizationValue = 'Bearer ' + (ConvertSecureStringToPlainText -SecureString $Token)
    } else {
        $authorizationValue = $Authorization
    }

    $probeUri = '{0}/{1}' -f $BaseUrl.TrimEnd('/'), $Endpoint.TrimStart('/')

    try {
        $null = Invoke-ServiceApiHttpRequest -Method GET -Uri $probeUri `
            -Headers @{ Authorization = $authorizationValue; Accept = 'application/json' } `
            -TimeoutSec $TimeoutSec -ErrorAction Stop
        Write-Verbose "Bearer probe [$Endpoint] succeeded."
        return $true
    } catch {
        $status = 'no response'
        if ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response) {
            $status = [int]$_.Exception.Response.StatusCode
        }
        Write-Verbose "Bearer probe [$Endpoint] did not succeed (HTTP $status)."
        return $false
    }
}
