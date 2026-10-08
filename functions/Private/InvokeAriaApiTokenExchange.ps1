function Invoke-AriaApiTokenExchange {
    <#
    .SYNOPSIS
        Exchanges an Aria API token for a short-lived bearer token, trying each known call shape.

    .DESCRIPTION
        An Aria API token (created in the portal under My Account, API Tokens) is a long-lived
        credential that can be exchanged for a short-lived bearer without a browser. The call
        shape differs between Aria deployments, so this function tries a ladder in order and
        returns the first that yields a token:

            csp-authorize  POST <base>/csp/gateway/am/api/auth/api-tokens/authorize
                           form: refresh_token=<api token>            returns access_token
            oauth-tenant   POST <base>/oauth/tenant/<tenant>/token
                           form: grant_type=refresh_token&refresh_token=<api token>
                           (only when -Tenant is supplied)              returns access_token
            iaas-login     POST <base>/iaas/api/login
                           json: {"refreshToken": "<api token>"}        returns token

        The shape that worked is returned so the caller can cache it (-Mode) and try it first
        next time. A transport failure (no HTTP status: DNS, TLS, refused) stops the ladder at
        once. When every shape is refused the error lists the status and error of each, never
        the token.

        With -Probe every shape is tried and reported to the host, and every success is returned.

        The call shapes come from the Aria design notes and public documentation and have not
        been confirmed against a tenant by this module; Invoke-AriaApiTokenProbe reports which
        ones a tenant accepts.

    .PARAMETER BaseUrl
        The Aria host root, for example https://aria.example.com (no /tenant suffix).

    .PARAMETER ApiToken
        The API token as a SecureString.

    .PARAMETER Tenant
        Optional. The tenant name. Enables the oauth-tenant shape.

    .PARAMETER Mode
        Optional. The shape that worked last time. Tried first.

    .PARAMETER Only
        Optional. Try this one shape only (csp-authorize, oauth-tenant or iaas-login).

    .PARAMETER Probe
        Try every shape, write the outcome of each to the host, and return all successes.

    .EXAMPLE
        $result = Invoke-AriaApiTokenExchange -BaseUrl 'https://aria.example.com' -ApiToken $apiToken
        $result.Mode

        Exchanges the API token and shows which call shape worked.

    .EXAMPLE
        Invoke-AriaApiTokenExchange -BaseUrl 'https://aria.example.com' -ApiToken $apiToken `
            -Tenant 'aria-example' -Mode 'oauth-tenant'

        Tries the oauth-tenant shape first, then the others.

    .EXAMPLE
        Invoke-AriaApiTokenExchange -BaseUrl 'https://aria.example.com' -ApiToken $apiToken -Probe

        Reports the status of every shape without stopping at the first success.

    .OUTPUTS
        PSCustomObject with Mode, Kind (csp, oauth or iaas), Token (SecureString) and ExpiresIn
        (seconds). With -Probe, an array of the successful results.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.0
        Date        : 09-OCT-26

        CHANGE LOG
        1.0.0 | 09OCT26 | Initial version. AriaApiToken provider: API token exchange ladder.
                          Not yet verified against a tenant.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$BaseUrl,

        [Parameter(Mandatory)]
        [securestring]$ApiToken,

        [string]$Tenant,

        [string]$Mode,

        [ValidateSet('csp-authorize', 'oauth-tenant', 'iaas-login')]
        [string]$Only,

        [switch]$Probe
    )

    function Get-AriaApiTokenError {
        param($ErrorRecord)

        $status = $null
        try {
            if ($ErrorRecord.Exception.Response) { $status = [int]$ErrorRecord.Exception.Response.StatusCode }
        } catch { }

        $body = $null
        if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
            $body = $ErrorRecord.ErrorDetails.Message
        }

        $parsed = $null
        try { if ($body) { $parsed = $body | ConvertFrom-Json } } catch { }

        $code = $null
        if ($parsed) {
            if ($parsed.PSObject.Properties['error'] -and $parsed.error) { $code = [string]$parsed.error }
            elseif ($parsed.PSObject.Properties['message'] -and $parsed.message) { $code = [string]$parsed.message }
        }

        [PSCustomObject]@{
            Status    = $status
            Error     = $code
            Transport = ($null -eq $status)
            Message   = $ErrorRecord.Exception.Message
        }
    }

    $BaseUrl = $BaseUrl.TrimEnd('/')
    $tok     = ConvertSecureStringToPlainText -SecureString $ApiToken

    # Never let the token reach a message, even if a server echoes it back.
    $hide = { param($text) if ($text) { ([string]$text).Replace($tok, '***') } else { $text } }

    $ladder = [ordered]@{}
    $ladder['csp-authorize'] = @{
        Kind        = 'csp'
        Uri         = "$BaseUrl/csp/gateway/am/api/auth/api-tokens/authorize"
        ContentType = 'application/x-www-form-urlencoded'
        Body        = @{ refresh_token = $tok }
    }
    if ($Tenant) {
        $ladder['oauth-tenant'] = @{
            Kind        = 'oauth'
            Uri         = "$BaseUrl/oauth/tenant/$([uri]::EscapeDataString($Tenant))/token"
            ContentType = 'application/x-www-form-urlencoded'
            Body        = @{ grant_type = 'refresh_token'; refresh_token = $tok }
        }
    }
    $ladder['iaas-login'] = @{
        Kind        = 'iaas'
        Uri         = "$BaseUrl/iaas/api/login"
        ContentType = 'application/json'
        Body        = (@{ refreshToken = $tok } | ConvertTo-Json -Compress)
    }

    $order = @($ladder.Keys)
    if ($Only) {
        $order = @($order | Where-Object { $_ -eq $Only })
        if ($order.Count -eq 0) { throw "Call shape [$Only] is not available (oauth-tenant needs -Tenant)." }
    } elseif ($Mode -and $ladder.Contains($Mode)) {
        $order = @($Mode) + @($order | Where-Object { $_ -ne $Mode })
    }

    $failures  = @()
    $successes = @()

    foreach ($name in $order) {
        $shape = $ladder[$name]

        try {
            $resp = Invoke-ServiceApiHttpRequest -Method Post -Uri $shape.Uri `
                -ContentType $shape.ContentType -Body $shape.Body -ErrorAction Stop
        } catch {
            $err = Get-AriaApiTokenError -ErrorRecord $_

            if ($err.Transport) {
                $msg = & $hide $err.Message
                if ($Probe) {
                    Write-Host ('{0,-14} -> no response: {1}' -f $name, $msg) -ForegroundColor Yellow
                    $failures += [PSCustomObject]@{ Mode = $name; Status = 0; Error = 'no_response' }
                    continue
                }
                throw "Aria API token exchange could not reach the host ($name): $msg"
            }

            $failures += [PSCustomObject]@{ Mode = $name; Status = $err.Status; Error = (& $hide $err.Error) }
            if ($Probe) {
                Write-Host ('{0,-14} -> HTTP {1} {2}' -f $name, $err.Status, (& $hide $err.Error)) -ForegroundColor Yellow
            }
            continue
        }

        $value = if ($shape.Kind -eq 'iaas') { $resp.token } else { $resp.access_token }
        if ([string]::IsNullOrWhiteSpace($value)) {
            $failures += [PSCustomObject]@{ Mode = $name; Status = 200; Error = 'no_token_in_response' }
            if ($Probe) { Write-Host ('{0,-14} -> 200 but the response contained no token' -f $name) -ForegroundColor Yellow }
            continue
        }

        # Lifetime: expires_in when given; otherwise the JWT exp claim; otherwise a safe default.
        $ttl = 0
        if ($resp.PSObject.Properties['expires_in'] -and $resp.expires_in) {
            $ttl = [int]$resp.expires_in
        }
        $isJwt = $false
        try {
            $claims = ConvertFrom-JwtPayload -Jwt $value
            $isJwt  = $true
            if ($ttl -le 0 -and $claims.PSObject.Properties['exp'] -and $claims.exp) {
                $epoch = [DateTime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
                $ttl   = [int][Math]::Floor(($epoch.AddSeconds([double]$claims.exp) - [DateTime]::UtcNow).TotalSeconds)
            }
        } catch { }
        if ($ttl -lt 60) { $ttl = 1500 }

        $result = [PSCustomObject]@{
            Mode      = $name
            Kind      = $shape.Kind
            Token     = (ConvertTo-SecureString -String $value -AsPlainText -Force)
            ExpiresIn = $ttl
        }

        if ($Probe) {
            Write-Host ('{0,-14} -> 200 OK; expires in about {1} s; JWT: {2}' -f $name, $ttl, $isJwt) -ForegroundColor Green
            $successes += $result
            continue
        }
        return $result
    }

    if ($Probe) { return $successes }

    $detail = ($failures | ForEach-Object { '{0}={1}/{2}' -f $_.Mode, $_.Status, $_.Error }) -join '; '
    throw "Aria API token exchange was refused by every call shape tried: $detail. Check that the API token is current and was created for this tenant."
}
