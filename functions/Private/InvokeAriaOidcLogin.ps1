
function Invoke-AriaOidcLogin {
    <#
    .SYNOPSIS
        Obtains a working bearer token, and the refresh token behind it, for an Aria / VCF
        Automation v9 tenant through the portal's own OIDC session.

    .DESCRIPTION
        Orchestrates the AriaOidc provider:

        1. Silent refresh: when -RefreshToken is held, Invoke-AriaOidcRefresh exchanges it at
           /oidc/oauth2/token (the refresh token is opaque, non-rotating and valid for the
           browser session, about 8 hours). Only a dead session (invalid_grant) falls through
           to a browser login.
        2. Browser login: Wait-AriaCourierToken starts a loopback listener on 127.0.0.1 and
           the portal is opened in the default browser. The courier userscript (rendered by
           Get-AriaCourierScript and served by the listener for a one-time install) forwards the
           SPA's own token response to the listener. Nothing is required from the platform.
        3. Bearer selection: the token Invoke-APIRequest will send is chosen by test rather
           than assumption: the OIDC access token if the IaaS API accepts it, otherwise the
           token iaas/api/login issues for the OIDC refresh token (the pre-v9 step 2),
           otherwise the OIDC access token with a warning.

        Returns the bearer and the state the caller must cache. Not exported. The browser path
        needs a person at the keyboard and is not suitable for unattended automation.

    .PARAMETER BaseUrl
        The Aria Automation host root (no /tenant/... suffix).

    .PARAMETER Tenant
        The tenant name, as it appears after 'service=tenant:' in the portal login redirect.

    .PARAMETER RefreshToken
        Optional. A cached refresh token (SecureString) to try first.

    .PARAMETER ClientId
        Optional. The portal's OIDC client id, cached from an earlier login.

    .PARAMETER RefreshMode
        Optional. The refresh call shape that worked previously (see Invoke-AriaOidcRefresh).

    .PARAMETER ProbeEndpoint
        The relative endpoint used to test whether a bearer is accepted. Defaults to
        'iaas/api/projects?$top=1'. Set-ServiceCredential supplies the service's registered
        ProbeEndpoint when there is one (see Get-ServiceProbeEndpoint).

    .PARAMETER ListenerPort
        Loopback port shared with the courier script. Defaults to 47811.

    .PARAMETER TimeoutSeconds
        Maximum time to wait for the browser login. Defaults to 300.

    .OUTPUTS
        PSCustomObject with Bearer (SecureString), BearerMode ('oidc' or 'iaas'), RefreshToken
        (SecureString), ExpiresIn (int, seconds), ClientId (string) and RefreshMode (string).

    .EXAMPLE
        $login = Invoke-AriaOidcLogin -BaseUrl 'https://aria.example.com' -Tenant 'my-tenant'
        Opens the portal and waits for the courier to deliver a token pair.

    .EXAMPLE
        $login = Invoke-AriaOidcLogin -BaseUrl 'https://aria.example.com' -Tenant 'my-tenant' `
            -RefreshToken $cached.RefreshToken -ClientId $cached.ClientId -RefreshMode $cached.RefreshMode

        Silently exchanges a cached refresh token. The browser opens only if the session has ended.

    .EXAMPLE
        $login = Invoke-AriaOidcLogin -BaseUrl 'https://aria.example.com' -Tenant 'my-tenant' `
            -ProbeEndpoint 'iaas/api/projects?$top=1' -Verbose
        $login.BearerMode

        Names the endpoint used to test each candidate bearer. BearerMode is 'oidc' when the OIDC
        access token was accepted and 'iaas' when the iaas/api/login token was used instead.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.4.0
        Date        : 08-OCT-26

        CHANGE LOG
        1.4.0 | 08OCT26 | Linux support: opens the portal through Open-ServiceApiBrowser, with a message when
                          no browser can be launched (headless Linux).
        1.3.1 | 06OCT26 | Replaced em dashes with ASCII punctuation and reworded the affected
                          sentences, so the source is plain ASCII and loads on Windows PowerShell 5.1.
        1.3.0 | 06OCT26 | The bearer test now uses the shared Test-ServiceBearer, with the probe
                          endpoint supplied through -ProbeEndpoint, so the login and the SSO 403
                          retry agree on what proves a bearer is valid. Added two help examples.
        1.2.0 | 06OCT26 | Replaced Invoke-RestMethod with Invoke-ServiceApiHttpRequest for the
                          IaaS bearer probe and iaas/api/login.
        1.1.0 | 01OCT26 | Reworked as an orchestrator over Invoke-AriaOidcRefresh,
                          Get-AriaCourierScript and Wait-AriaCourierToken. Adds client id and
                          refresh call-shape caching and verified bearer selection.
        1.0.0 | 01OCT26 | Initial version.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$BaseUrl,

        [Parameter(Mandatory)]
        [string]$Tenant,

        [securestring]$RefreshToken,

        [string]$ClientId,

        [string]$RefreshMode,

        [string]$ProbeEndpoint = 'iaas/api/projects?$top=1',

        [ValidateRange(1024, 65535)]
        [int]$ListenerPort = 47811,

        [ValidateRange(30, 1800)]
        [int]$TimeoutSeconds = 300
    )

    $BaseUrl    = $BaseUrl.TrimEnd('/')
    $origin     = ([uri]$BaseUrl).GetLeftPart([UriPartial]::Authority)
    $courierKey = 'aria-oidc-courier'   # must match the key rendered into the courier script

    function ConvertTo-AriaTokenSet {
        param($Response, [securestring]$FallbackRefreshToken, [string]$ClientId, [string]$RefreshMode)

        if ([string]::IsNullOrWhiteSpace($Response.access_token)) {
            throw "Aria OIDC token response contained no access_token."
        }

        $refresh = $FallbackRefreshToken
        if ($Response.PSObject.Properties['refresh_token'] -and $Response.refresh_token) {
            $refresh = ConvertTo-SecureString -String $Response.refresh_token -AsPlainText -Force
        }
        if (-not $refresh) {
            throw "Aria OIDC token response contained no refresh_token."
        }

        $ttl = 3600
        if ($Response.PSObject.Properties['expires_in'] -and $Response.expires_in) {
            $ttl = [int]$Response.expires_in
        }

        # The access token's 'aud' claim is the portal's own OIDC client id, needed by the
        # refresh call shapes that identify the client.
        if (-not $ClientId) {
            try {
                $claims   = ConvertFrom-JwtPayload -Jwt $Response.access_token
                $ClientId = if ($claims.aud -is [array]) { [string]$claims.aud[0] } else { [string]$claims.aud }
            } catch {
                $ClientId = $null
            }
        }

        [PSCustomObject]@{
            Access      = ConvertTo-SecureString -String $Response.access_token -AsPlainText -Force
            Refresh     = $refresh
            ExpiresIn   = $ttl
            ClientId    = $ClientId
            RefreshMode = $RefreshMode
        }
    }

    $tokens = $null

    # -------------------------------------------------------------------------
    # Path 1: silent refresh with a held refresh token
    # -------------------------------------------------------------------------
    if ($RefreshToken) {
        $refreshed = Invoke-AriaOidcRefresh -BaseUrl $BaseUrl -RefreshToken $RefreshToken `
            -ClientId $ClientId -Mode $RefreshMode

        if ($refreshed) {
            $tokens = ConvertTo-AriaTokenSet -Response $refreshed.Response `
                -FallbackRefreshToken $RefreshToken -ClientId $ClientId -RefreshMode $refreshed.Mode
        } else {
            Write-Verbose "Aria OIDC refresh token rejected (invalid_grant). Session has ended; starting browser login."
        }
    }

    # -------------------------------------------------------------------------
    # Path 2: browser login; the courier forwards the SPA's token response
    # -------------------------------------------------------------------------
    if (-not $tokens) {
        $scriptText = Get-AriaCourierScript -BaseUrl $BaseUrl -Port $ListenerPort -Key $courierKey
        $installUrl = "http://127.0.0.1:$ListenerPort/aria-oidc-courier.user.js"
        $portalUrl  = "$BaseUrl/tenant/$Tenant/automation/"

        $payload = Wait-AriaCourierToken -Origin $origin -ScriptText $scriptText `
            -Port $ListenerPort -Key $courierKey -TimeoutSeconds $TimeoutSeconds -AfterStart {
                Write-Host "Aria login: sign in to the portal that is opening. Waiting up to $TimeoutSeconds seconds..." -ForegroundColor Cyan
                Write-Host "First time on this browser? Install the courier by opening $installUrl, then reload the portal tab." -ForegroundColor Cyan
                if (-not (Open-ServiceApiBrowser -Url $portalUrl)) {
                    Write-Host "No browser could be opened on this host. Open $portalUrl in a browser on this same host (the courier posts to 127.0.0.1)." -ForegroundColor Yellow
                }
            }.GetNewClosure()

        $tokens = ConvertTo-AriaTokenSet -Response $payload -FallbackRefreshToken $null `
            -ClientId $ClientId -RefreshMode $null
    }

    # -------------------------------------------------------------------------
    # Bearer selection: verified against the IaaS API, not assumed
    # -------------------------------------------------------------------------
    $bearer     = $tokens.Access
    $bearerMode = 'oidc'

    if (-not (Test-ServiceBearer -BaseUrl $BaseUrl -Endpoint $ProbeEndpoint -Token $tokens.Access)) {
        try {
            $iaas = Invoke-ServiceApiHttpRequest -Method Post -Uri "$BaseUrl/iaas/api/login" `
                -ContentType 'application/json' `
                -Body (@{ refreshToken = (ConvertSecureStringToPlainText -SecureString $tokens.Refresh) } | ConvertTo-Json -Compress) `
                -ErrorAction Stop

            if ($iaas.token) {
                $candidate = ConvertTo-SecureString -String $iaas.token -AsPlainText -Force
                if (Test-ServiceBearer -BaseUrl $BaseUrl -Endpoint $ProbeEndpoint -Token $candidate) {
                    $bearer     = $candidate
                    $bearerMode = 'iaas'
                }
            }
        } catch {
            Write-Verbose "iaas/api/login did not accept the OIDC refresh token: $($_.Exception.Message)"
        }

        if ($bearerMode -eq 'oidc') {
            Write-Warning "Neither the OIDC access token nor an iaas/api/login token was accepted by the IaaS API. Using the OIDC access token; endpoints that accept it will still work."
        }
    }

    [PSCustomObject]@{
        Bearer       = $bearer
        BearerMode   = $bearerMode
        RefreshToken = $tokens.Refresh
        ExpiresIn    = $tokens.ExpiresIn
        ClientId     = $tokens.ClientId
        RefreshMode  = $tokens.RefreshMode
    }
}
