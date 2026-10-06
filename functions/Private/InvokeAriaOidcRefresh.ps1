
function Invoke-AriaOidcRefresh {
    <#
    .SYNOPSIS
        Exchanges an Aria OIDC refresh token for a new access token, working out which call
        shape the token endpoint accepts.

    .DESCRIPTION
        OIDC discovery for the v9 tenant advertises client_secret_basic, client_secret_post and
        private_key_jwt for the token endpoint but not 'none', and 'tm_ui' (the scope the portal
        itself requests) is not an advertised scope. A bare refresh may therefore be refused, so
        the call is made as a ladder of shapes, tried in order:

          bare-tm_ui    no client authentication, scope=tm_ui (what the portal sends)
          bare          no client authentication, no scope
          client-body   client_id in the form body (needs -ClientId)
          client-basic  client_id as a Basic header with an empty secret (needs -ClientId)

        A shape is skipped on invalid_client, unauthorized_client, invalid_scope or
        invalid_request. The shape that worked is returned so the caller can cache it and try
        it first next time. invalid_grant on the cached shape means the session has ended; with
        no cached shape it means the same only if every shape says so.

        With -Probe every shape is tried and reported (status and OAuth error only — no tokens
        are ever written to the host) for diagnostics.

        Not exported.

    .PARAMETER BaseUrl
        The Aria Automation host root.

    .PARAMETER RefreshToken
        The refresh token (SecureString).

    .PARAMETER ClientId
        The portal's OIDC client id (the 'aud' claim of its access token). Enables the
        client-body and client-basic shapes.

    .PARAMETER Mode
        A shape that worked previously, tried first.

    .PARAMETER Probe
        Try every shape and report each result.

    .OUTPUTS
        PSCustomObject with Response (the token response) and Mode (the shape that worked);
        $null when the session has ended (invalid_grant). Throws on any other failure.

    .EXAMPLE
        $result = Invoke-AriaOidcRefresh -BaseUrl 'https://aria.example.com' -RefreshToken $refreshToken
        if ($result) { $result.Mode }

        Refreshes with a held refresh token. $result.Mode names the call shape that worked, for
        the caller to cache. A $null result means the session has ended.

    .EXAMPLE
        $result = Invoke-AriaOidcRefresh -BaseUrl 'https://aria.example.com' -RefreshToken $refreshToken `
            -ClientId $clientId -Mode 'client-body'

        Tries the cached 'client-body' shape first, then the others. The client id enables the
        client-body and client-basic shapes.

    .EXAMPLE
        Invoke-AriaOidcRefresh -BaseUrl 'https://aria.example.com' -RefreshToken $refreshToken -ClientId $clientId -Probe

        Diagnostic mode. Tries every call shape and writes the status and OAuth error of each to
        the host, without writing any token.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.2
        Date        : 06-OCT-26

        CHANGE LOG
        1.0.2 | 06OCT26 | Added the three help examples required by the CMF standard.
        1.0.1 | 06OCT26 | Replaced Invoke-RestMethod with Invoke-ServiceApiHttpRequest for the
                          token refresh call.
        1.0.0 | 01OCT26 | Initial version. Call-shape ladder derived from the standalone
                          verification harness.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$BaseUrl,

        [Parameter(Mandatory)]
        [securestring]$RefreshToken,

        [string]$ClientId,

        [string]$Mode,

        [switch]$Probe
    )

    function Get-AriaOidcError {
        param($ErrorRecord)

        $body = $null
        if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
            $body = $ErrorRecord.ErrorDetails.Message
        } elseif ($ErrorRecord.Exception.Response -and $ErrorRecord.Exception.Response.PSObject.Methods['GetResponseStream']) {
            try {
                $body = [IO.StreamReader]::new($ErrorRecord.Exception.Response.GetResponseStream()).ReadToEnd()
            } catch { }
        }

        $parsed = $null
        try { $parsed = $body | ConvertFrom-Json } catch { }

        [PSCustomObject]@{
            Status      = [int]$ErrorRecord.Exception.Response.StatusCode
            Error       = $parsed.error
            Description = $parsed.error_description
        }
    }

    $BaseUrl = $BaseUrl.TrimEnd('/')
    $uri     = "$BaseUrl/oidc/oauth2/token"
    $rt      = ConvertSecureStringToPlainText -SecureString $RefreshToken

    $ladder = [ordered]@{
        'bare-tm_ui' = @{ Headers = @{}; Body = @{ scope = 'tm_ui' } }
        'bare'       = @{ Headers = @{}; Body = @{} }
    }
    if ($ClientId) {
        $basic = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${ClientId}:"))
        $ladder['client-body']  = @{ Headers = @{}; Body = @{ client_id = $ClientId } }
        $ladder['client-basic'] = @{ Headers = @{ Authorization = $basic }; Body = @{} }
    }

    $order = @($ladder.Keys)
    $cachedModeValid = [bool]($Mode -and $ladder.Contains($Mode))
    if ($cachedModeValid) {
        $order = @($Mode) + @($order | Where-Object { $_ -ne $Mode })
    }

    $advanceOn = 'invalid_client', 'unauthorized_client', 'invalid_scope', 'invalid_request'
    $failures  = @()
    $success   = $null

    foreach ($name in $order) {
        $shape = $ladder[$name]
        $body  = @{ grant_type = 'refresh_token'; refresh_token = $rt } + $shape.Body

        try {
            $resp = Invoke-ServiceApiHttpRequest -Method Post -Uri $uri `
                -ContentType 'application/x-www-form-urlencoded' `
                -Headers $shape.Headers -Body $body -ErrorAction Stop

            if ($Probe) {
                Write-Host ('{0,-14} -> 200 OK; expires_in {1}; refresh token unchanged: {2}' -f $name, $resp.expires_in, ($resp.refresh_token -eq $rt)) -ForegroundColor Green
            }
            if (-not $success) {
                $success = [PSCustomObject]@{ Response = $resp; Mode = $name }
            }
            if (-not $Probe) { return $success }
        } catch {
            $err = Get-AriaOidcError -ErrorRecord $_
            $failures += [PSCustomObject]@{ Mode = $name; Status = $err.Status; Error = $err.Error }

            if ($Probe) {
                Write-Host ('{0,-14} -> {1} {2} {3}' -f $name, $err.Status, $err.Error, $err.Description) -ForegroundColor Yellow
                continue
            }

            # The shape that worked before now reports a dead session — no point trying others
            if ($err.Error -eq 'invalid_grant' -and $cachedModeValid -and $name -eq $Mode) {
                return $null
            }
            if ($err.Error -notin ($advanceOn + 'invalid_grant')) {
                throw "Aria OIDC refresh failed (HTTP $($err.Status), error '$($err.Error)') — $_"
            }
        }
    }

    if ($Probe) { return $success }

    # Every shape failed. All invalid_grant means the session has ended; anything else is a real fault.
    if (@($failures | Where-Object { $_.Error -ne 'invalid_grant' }).Count -eq 0) {
        return $null
    }

    $detail = ($failures | ForEach-Object { '{0}={1}/{2}' -f $_.Mode, $_.Status, $_.Error }) -join '; '
    throw "Aria OIDC refresh was refused by every call shape tried: $detail"
}
