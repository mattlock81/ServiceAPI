function Invoke-PingFederateLogin {
    <#
    .SYNOPSIS
        Obtains an access token, and the refresh token behind it, from PingFederate with the
        OpenID Connect authorization code grant.

    .DESCRIPTION
        Orchestrates the PingFederate provider for a confidential client (client id and secret,
        PKCE not used):

        1. Silent refresh: when -RefreshToken is held, it is exchanged at the token endpoint. Only
           a dead session (invalid_grant) falls through to a browser login.
        2. Browser login: the authorization URL is opened in the default browser with fresh state
           and nonce values, and Wait-PingFederateCallback receives the redirect on a loopback
           listener. The code is exchanged at the token endpoint with the client secret.
        3. Validation: the id_token, when returned, is checked for issuer, audience, expiry and
           (on a browser login) nonce. Its signature is not verified: it was received directly
           from the token endpoint over TLS, which OpenID Connect Core 3.1.3.7 accepts.

        Returns the bearer and the state the caller must cache. Not exported. The browser path
        needs a person at the keyboard and is not suitable for unattended automation; when the
        session is non-interactive it throws instead of waiting.

    .PARAMETER Authority
        The PingFederate base URL, for example https://pf.example.com:9031.

    .PARAMETER ClientId
        The OAuth client id.

    .PARAMETER ClientSecret
        The OAuth client secret, as a SecureString. Required for -ClientAuth secret.

    .PARAMETER ClientAuth
        How the client authenticates at the token endpoint: secret (default), private_key_jwt (a
        signed client assertion; needs -SigningCertificate) or tls_client_auth (mutual TLS; needs a
        certificate in -TransportOptions).

    .PARAMETER SigningCertificate
        The opened client certificate (Get-ServiceClientCertificate) whose private key signs the
        assertion for private_key_jwt.

    .PARAMETER TransportOptions
        Optional. The transport, client certificate and CA bundle for every call to PingFederate
        (see Resolve-ServiceTransportOptions).

    .PARAMETER Scope
        The requested scopes. Passed through Resolve-PingFederateScope. Defaults to
        'openid profile ad'.

    .PARAMETER RedirectUri
        The redirect URI registered on the client. Must be an http loopback address. Defaults to
        http://127.0.0.1:47812/callback.

    .PARAMETER RefreshToken
        Optional. A cached refresh token (SecureString) to try first.

    .PARAMETER AuthMode
        Optional. The client authentication method that worked previously ('basic' or 'post').

    .PARAMETER TimeoutSeconds
        Maximum time to wait for the browser login. Defaults to 300.

    .EXAMPLE
        $login = Invoke-PingFederateLogin -Authority 'https://pf.example.com:9031' -ClientId $id -ClientSecret $secret
        Opens the browser, waits for the redirect and returns the token set.

    .EXAMPLE
        $login = Invoke-PingFederateLogin -Authority $authority -ClientId $id -ClientSecret $secret `
            -RefreshToken $cached.RefreshToken -AuthMode $cached.AuthMode
        Silently exchanges a cached refresh token. The browser opens only if the session has ended.

    .EXAMPLE
        $login = Invoke-PingFederateLogin -Authority $authority -ClientId $id -ClientSecret $secret `
            -Scope 'openid profile ad rel' -RedirectUri 'http://127.0.0.1:47900/callback' -Verbose
        Requests the 'rel' scope as well and uses another loopback port.

    .OUTPUTS
        PSCustomObject with Bearer (SecureString), RefreshToken (SecureString or $null), ExpiresIn
        (int, seconds), AuthMode (string), Scope (string, as granted), Claims (hashtable of the
        id_token claims, or $null) and Source ('refresh' or 'browser').

    .NOTES
        Author      : Matthew Sillett
        Version     : 2.0.0
        Date        : 16-OCT-26

        CHANGE LOG
        2.0.0 | 16OCT26 | Added -ClientAuth (secret, private_key_jwt, tls_client_auth), -SigningCertificate and
                          -TransportOptions. -ClientSecret is optional (required only for secret). The
                          assertion audience is the token endpoint and the issuer. AuthMode now also reports
                          'jwt' and 'tls'. No change for callers that omit the new parameters.
        1.0.0 | 15OCT26 | Initial version. PingFederate provider: authorization code login with
                          silent refresh. Not yet verified against a PingFederate server.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Authority,

        [Parameter(Mandatory)]
        [string]$ClientId,

        [securestring]$ClientSecret,

        [ValidateSet('secret', 'private_key_jwt', 'tls_client_auth')]
        [string]$ClientAuth = 'secret',

        [object]$SigningCertificate,

        [hashtable]$TransportOptions,

        [string[]]$Scope = @('openid', 'profile', 'ad'),

        [string]$RedirectUri = 'http://127.0.0.1:47812/callback',

        [securestring]$RefreshToken,

        [ValidateSet('basic', 'post', 'jwt', 'tls', '')]
        [string]$AuthMode,

        [ValidateRange(30, 1800)]
        [int]$TimeoutSeconds = 300
    )

    $Authority = $Authority.TrimEnd('/')
    $scopeText = Resolve-PingFederateScope -Scope $Scope
    $endpointParams = @{ Authority = $Authority }
    if ($TransportOptions) { $endpointParams['TransportOptions'] = $TransportOptions }
    $endpoint  = Get-PingFederateEndpoint @endpointParams
    Write-Verbose "PingFederate endpoints from [$($endpoint.Source)]: token endpoint [$($endpoint.TokenEndpoint)]."

    function New-RandomToken {
        $bytes = New-Object byte[] 32
        $rng   = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
        [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    }

    # What the token endpoint call needs to authenticate the client, whichever method is in use
    $tokenAuth = @{ ClientId = $ClientId; ClientAuth = $ClientAuth }
    if ($TransportOptions) { $tokenAuth['TransportOptions'] = $TransportOptions }
    switch ($ClientAuth) {
        'secret' {
            if (-not $ClientSecret) { throw "ClientAuth secret needs the client secret. Store it with Set-ServiceCredential -AuthType Basic -Label oidcclient." }
            $tokenAuth['ClientSecret'] = $ClientSecret
        }
        'private_key_jwt' {
            if (-not $SigningCertificate) { throw "ClientAuth private_key_jwt needs a client certificate. Register one with Register-CustomService -ClientCertificate." }
            $tokenAuth['SigningCertificate'] = $SigningCertificate
            $tokenAuth['Audience']           = @($endpoint.TokenEndpoint, $endpoint.Issuer | Select-Object -Unique)
        }
        'tls_client_auth' {
            if (-not ($TransportOptions -and $TransportOptions['Certificate'])) { throw "ClientAuth tls_client_auth needs a client certificate. Register one with Register-CustomService -ClientCertificate." }
        }
    }

    $response = $null
    $source   = $null
    $nonce    = $null
    $mode     = if ($ClientAuth -eq 'secret' -and $AuthMode -in @('basic', 'post')) { $AuthMode } else { '' }

    # -------------------------------------------------------------------------
    # Path 1: silent refresh with a held refresh token
    # -------------------------------------------------------------------------
    if ($RefreshToken) {
        $refreshBody = @{
            grant_type    = 'refresh_token'
            refresh_token = (ConvertSecureStringToPlainText -SecureString $RefreshToken)
        }
        $refreshed = Invoke-PingFederateTokenRequest -TokenEndpoint $endpoint.TokenEndpoint @tokenAuth `
            -Body $refreshBody -AuthMode $mode -NullOnInvalidGrant

        if ($refreshed) {
            $response = $refreshed.Response
            $mode     = $refreshed.AuthMode
            $source   = 'refresh'
        } else {
            Write-Verbose "PingFederate refresh token rejected (invalid_grant). Session has ended; starting browser login."
        }
    }

    # -------------------------------------------------------------------------
    # Path 2: browser login with the authorization code grant
    # -------------------------------------------------------------------------
    if (-not $response) {
        if (-not (Test-ServiceApiInteractive)) {
            throw "PingFederate needs an interactive browser login and this session is non-interactive. Run Set-ServiceCredential -AuthType SSO once from an interactive session; the refresh token it caches is then used silently."
        }

        $state = New-RandomToken
        $nonce = New-RandomToken

        $authQuery = @(
            'response_type=code'
            'client_id='     + [uri]::EscapeDataString($ClientId)
            'redirect_uri='  + [uri]::EscapeDataString($RedirectUri)
            'scope='         + [uri]::EscapeDataString($scopeText)
            'state='         + [uri]::EscapeDataString($state)
            'nonce='         + [uri]::EscapeDataString($nonce)
        ) -join '&'
        $authUrl = "$($endpoint.AuthorizationEndpoint)?$authQuery"

        $code = Wait-PingFederateCallback -RedirectUri $RedirectUri -State $state -TimeoutSeconds $TimeoutSeconds -AuthorizationUrl $authUrl

        $exchanged = Invoke-PingFederateTokenRequest -TokenEndpoint $endpoint.TokenEndpoint @tokenAuth `
            -AuthMode $mode -Body @{
                grant_type   = 'authorization_code'
                code         = $code
                redirect_uri = $RedirectUri
            }

        $response = $exchanged.Response
        $mode     = $exchanged.AuthMode
        $source   = 'browser'
    }

    if ([string]::IsNullOrWhiteSpace($response.access_token)) {
        throw "PingFederate token response contained no access_token."
    }

    # -------------------------------------------------------------------------
    # id_token checks (signature not verified; see the description)
    # -------------------------------------------------------------------------
    $claims = $null
    if ($response.PSObject.Properties['id_token'] -and $response.id_token) {
        $payload = ConvertFrom-JwtPayload -Jwt $response.id_token

        $audiences = @($payload.aud)
        if ($ClientId -notin $audiences) {
            throw "The PingFederate id_token audience does not include client [$ClientId]; refusing the token."
        }
        if ($payload.iss -and $endpoint.Issuer -and ([string]$payload.iss).TrimEnd('/') -ne $endpoint.Issuer.TrimEnd('/')) {
            throw "The PingFederate id_token issuer [$($payload.iss)] does not match the expected issuer [$($endpoint.Issuer)]; refusing the token."
        }
        if ($payload.exp -and [DateTimeOffset]::FromUnixTimeSeconds([long]$payload.exp) -lt [DateTimeOffset]::UtcNow.AddMinutes(-2)) {
            throw "The PingFederate id_token has already expired; refusing the token."
        }
        if ($nonce -and $payload.nonce -ne $nonce) {
            throw "The PingFederate id_token nonce does not match this login; refusing the token."
        }

        $claims = @{}
        foreach ($property in $payload.PSObject.Properties) { $claims[$property.Name] = $property.Value }
    }

    $refresh = $RefreshToken
    if ($response.PSObject.Properties['refresh_token'] -and $response.refresh_token) {
        $refresh = ConvertTo-SecureString -String $response.refresh_token -AsPlainText -Force
    }
    if ($source -eq 'browser' -and -not ($response.PSObject.Properties['refresh_token'] -and $response.refresh_token)) {
        $refresh = $null
        Write-Verbose "PingFederate issued no refresh token (refresh_token grant not enabled on the client?). The browser login repeats when the access token expires."
    }

    $ttl = 3600
    if ($response.PSObject.Properties['expires_in'] -and $response.expires_in) { $ttl = [int]$response.expires_in }

    $granted = $scopeText
    if ($response.PSObject.Properties['scope'] -and $response.scope) {
        $granted = [string]$response.scope
        $missing = @($scopeText -split ' ' | Where-Object { $_ -and ($granted -split '\s+') -notcontains $_ })
        if ($missing.Count -gt 0) {
            Write-Warning "PingFederate did not grant the scope(s): $($missing -join ', '). Granted: $granted."
        }
    }

    [PSCustomObject]@{
        Bearer       = ConvertTo-SecureString -String $response.access_token -AsPlainText -Force
        RefreshToken = $refresh
        ExpiresIn    = $ttl
        AuthMode     = $mode
        Scope        = $granted
        Claims       = $claims
        Source       = $source
    }
}
