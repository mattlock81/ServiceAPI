function Invoke-PingFederateTokenRequest {
    <#
    .SYNOPSIS
        Sends a grant to a PingFederate token endpoint, authenticating the client.

    .DESCRIPTION
        Posts the grant as application/x-www-form-urlencoded. The client authenticates one of three
        ways (-ClientAuth):

          secret           client_secret_basic first (PingFederate's default), falling back to
                           client_secret_post when the server answers invalid_client. The method
                           that worked is returned so the caller can try it first next time.
          private_key_jwt  A fresh signed client assertion (New-ServiceClientAssertion) is sent as
                           client_assertion. No secret is involved.
          tls_client_auth  Only the client_id is sent; the client is identified by the client
                           certificate presented on the TLS connection (-TransportOptions).

        An invalid_grant answer (refresh token or authorization code no longer valid) returns
        $null when -NullOnInvalidGrant is set, so a caller can fall back to a browser login.
        Every other failure throws. No secret, assertion or grant value is written to a stream; the
        error carries the HTTP status, the OAuth error and its description.

    .PARAMETER TokenEndpoint
        The token endpoint URL (see Get-PingFederateEndpoint).

    .PARAMETER ClientId
        The OAuth client id.

    .PARAMETER ClientSecret
        The OAuth client secret, as a SecureString. Required for -ClientAuth secret.

    .PARAMETER ClientAuth
        secret (default), private_key_jwt or tls_client_auth.

    .PARAMETER SigningCertificate
        The opened client certificate (Get-ServiceClientCertificate) whose private key signs the
        assertion. Required for private_key_jwt.

    .PARAMETER Audience
        Audience values for the assertion. Defaults to the token endpoint.

    .PARAMETER Body
        The grant parameters (grant_type and its companions) as a hashtable.

    .PARAMETER AuthMode
        Optional. The secret-based method that worked previously ('basic' or 'post'). Empty or
        omitted tries basic first. Ignored for the certificate methods.

    .PARAMETER TransportOptions
        Optional. The transport, client certificate and CA bundle for the HTTP call (see
        Resolve-ServiceTransportOptions). Required for tls_client_auth, where it carries the
        certificate presented on the connection.

    .PARAMETER NullOnInvalidGrant
        Returns $null instead of throwing when the server answers invalid_grant.

    .EXAMPLE
        $r = Invoke-PingFederateTokenRequest -TokenEndpoint $ep.TokenEndpoint -ClientId $id `
            -ClientSecret $secret -Body @{ grant_type = 'refresh_token'; refresh_token = $rt } `
            -NullOnInvalidGrant
        Exchanges a refresh token; $r is $null when the session has ended.

    .EXAMPLE
        $r = Invoke-PingFederateTokenRequest -TokenEndpoint $ep.TokenEndpoint -ClientId $id `
            -ClientAuth private_key_jwt -SigningCertificate $resolved -Audience $ep.TokenEndpoint, $ep.Issuer `
            -Body @{ grant_type = 'authorization_code'; code = $code; redirect_uri = $uri }
        Exchanges an authorization code, proving the client with a signed assertion.

    .EXAMPLE
        $r = Invoke-PingFederateTokenRequest -TokenEndpoint $ep.TokenEndpoint -ClientId $id `
            -ClientAuth tls_client_auth -TransportOptions $options -Body @{ grant_type = 'refresh_token'; refresh_token = $rt }
        $r.AuthMode

        Refreshes over mutual TLS; AuthMode is 'tls'.

    .OUTPUTS
        PSCustomObject with Response (the token response) and AuthMode ('basic', 'post', 'jwt' or
        'tls'), or $null.

    .NOTES
        Author      : Matthew Sillett
        Version     : 2.0.0
        Date        : 16-OCT-26

        CHANGE LOG
        2.0.0 | 16OCT26 | Added -ClientAuth (secret, private_key_jwt, tls_client_auth), -SigningCertificate,
                          -Audience and -TransportOptions. -ClientSecret is optional (required only for
                          secret). Behaviour for the secret method is unchanged.
        1.0.0 | 15OCT26 | Initial version. PingFederate provider: token endpoint call with client
                          authentication fallback.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$TokenEndpoint,

        [Parameter(Mandatory)]
        [string]$ClientId,

        [securestring]$ClientSecret,

        [ValidateSet('secret', 'private_key_jwt', 'tls_client_auth')]
        [string]$ClientAuth = 'secret',

        [object]$SigningCertificate,

        [string[]]$Audience,

        [Parameter(Mandatory)]
        [hashtable]$Body,

        # Empty means nothing is cached yet: basic is tried first
        [ValidateSet('basic', 'post', '')]
        [string]$AuthMode,

        [hashtable]$TransportOptions,

        [switch]$NullOnInvalidGrant
    )

    $httpOptions = @{}
    if ($TransportOptions) { $httpOptions['TransportOptions'] = $TransportOptions }

    $readError = {
        param($ErrorRecord)
        $text = $null
        if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
            $text = $ErrorRecord.ErrorDetails.Message
        } elseif ($ErrorRecord.Exception.Response -and $ErrorRecord.Exception.Response.PSObject.Methods['GetResponseStream']) {
            try { $text = [IO.StreamReader]::new($ErrorRecord.Exception.Response.GetResponseStream()).ReadToEnd() } catch { }
        }
        $parsed = $null
        try { $parsed = $text | ConvertFrom-Json } catch { }
        $status = 0
        try { $status = [int]$ErrorRecord.Exception.Response.StatusCode } catch { }
        [pscustomobject]@{
            Status = $status
            Code   = $(if ($parsed -and $parsed.PSObject.Properties['error']) { [string]$parsed.error } else { $null })
            Desc   = $(if ($parsed -and $parsed.PSObject.Properties['error_description']) { [string]$parsed.error_description } else { $null })
            Failed = ($status -eq 0)
            Record = $ErrorRecord
        }
    }

    # --- certificate methods: one attempt ---------------------------------------------------
    if ($ClientAuth -ne 'secret') {
        $form = @{} + $Body
        $form['client_id'] = $ClientId
        if ($ClientAuth -eq 'private_key_jwt') {
            if (-not $SigningCertificate) {
                throw "ClientAuth private_key_jwt needs a client certificate to sign the assertion. Register one with Register-CustomService -ClientCertificate."
            }
            $aud = if ($Audience) { $Audience } else { @($TokenEndpoint) }
            $form['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            $form['client_assertion']      = New-ServiceClientAssertion -Certificate $SigningCertificate -ClientId $ClientId -Audience $aud
            $mode = 'jwt'
        } else {
            if (-not ($TransportOptions -and $TransportOptions['Certificate'])) {
                throw "ClientAuth tls_client_auth needs a client certificate to present on the connection. Register one with Register-CustomService -ClientCertificate."
            }
            $mode = 'tls'
        }

        try {
            $response = Invoke-ServiceApiHttpRequest -Method Post -Uri $TokenEndpoint `
                -ContentType 'application/x-www-form-urlencoded' -Body $form @httpOptions -ErrorAction Stop
            return [PSCustomObject]@{ Response = $response; AuthMode = $mode }
        } catch {
            $e = & $readError $_
            if ($e.Code -eq 'invalid_grant' -and $NullOnInvalidGrant) { return $null }
            if ($e.Failed) { throw }   # a transport failure: keep its own message
            $hint = if ($e.Code -eq 'invalid_client') {
                if ($ClientAuth -eq 'private_key_jwt') { ' Check that the client is registered with this certificate (or its JWKS) and that the assertion audience is accepted.' }
                else { ' Check that the client is set to mutual TLS client authentication and that the certificate is trusted and matches the client.' }
            } else { '' }
            throw "PingFederate token request failed (HTTP $($e.Status), error '$($e.Code)'$(if ($e.Desc) { ", $($e.Desc)" })).$hint"
        }
    }

    # --- secret: client_secret_basic, then client_secret_post --------------------------------
    if (-not $ClientSecret) {
        throw "ClientAuth secret needs the client secret. Store it with Set-ServiceCredential -AuthType Basic -Label oidcclient."
    }
    $secret = ConvertSecureStringToPlainText -SecureString $ClientSecret
    $order  = @('basic', 'post')
    if ($AuthMode -eq 'post') { $order = @('post', 'basic') }

    $lastError = $null
    foreach ($mode in $order) {
        $headers = @{}
        $form    = @{} + $Body

        if ($mode -eq 'basic') {
            $pair = '{0}:{1}' -f [uri]::EscapeDataString($ClientId), [uri]::EscapeDataString($secret)
            $headers['Authorization'] = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($pair))
        } else {
            $form['client_id']     = $ClientId
            $form['client_secret'] = $secret
        }

        try {
            $response = Invoke-ServiceApiHttpRequest -Method Post -Uri $TokenEndpoint `
                -ContentType 'application/x-www-form-urlencoded' -Headers $headers -Body $form @httpOptions -ErrorAction Stop

            return [PSCustomObject]@{ Response = $response; AuthMode = $mode }
        } catch {
            $e = & $readError $_
            if ($e.Code -eq 'invalid_grant' -and $NullOnInvalidGrant) { return $null }
            if ($e.Failed) { throw }   # a transport failure (no HTTP response): keep its own message

            $lastError = "PingFederate token request failed (HTTP $($e.Status), error '$($e.Code)'$(if ($e.Desc) { ", $($e.Desc)" }))."

            # Only a client authentication failure is worth retrying with the other method
            if ($e.Code -ne 'invalid_client') { throw $lastError }
            Write-Verbose "Client authentication method [$mode] was refused (invalid_client)."
        }
    }

    throw "$lastError Both client_secret_basic and client_secret_post were refused; check the client id and secret and that the client is a confidential client."
}
