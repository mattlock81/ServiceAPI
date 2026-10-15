function Invoke-PingFederateTokenRequest {
    <#
    .SYNOPSIS
        Sends a grant to a PingFederate token endpoint, authenticating the client with its secret.

    .DESCRIPTION
        Posts the grant as application/x-www-form-urlencoded. The client authenticates with
        client_secret_basic first (PingFederate's default) and falls back to client_secret_post
        when the server answers invalid_client. The method that worked is returned so the caller
        can try it first next time.

        An invalid_grant answer (refresh token or authorization code no longer valid) returns
        $null when -NullOnInvalidGrant is set, so a caller can fall back to a browser login.
        Every other failure throws. The client secret and the grant values are never written to
        a stream; the error message carries the HTTP status, the OAuth error and its description.

    .PARAMETER TokenEndpoint
        The token endpoint URL (see Get-PingFederateEndpoint).

    .PARAMETER ClientId
        The OAuth client id.

    .PARAMETER ClientSecret
        The OAuth client secret, as a SecureString.

    .PARAMETER Body
        The grant parameters (grant_type and its companions) as a hashtable.

    .PARAMETER AuthMode
        Optional. The client authentication method that worked previously ('basic' or 'post').
        Empty or omitted tries basic first.

    .PARAMETER NullOnInvalidGrant
        Returns $null instead of throwing when the server answers invalid_grant.

    .EXAMPLE
        $r = Invoke-PingFederateTokenRequest -TokenEndpoint $ep.TokenEndpoint -ClientId $id `
            -ClientSecret $secret -Body @{ grant_type = 'refresh_token'; refresh_token = $rt } `
            -NullOnInvalidGrant
        Exchanges a refresh token; $r is $null when the session has ended.

    .EXAMPLE
        $r = Invoke-PingFederateTokenRequest -TokenEndpoint $ep.TokenEndpoint -ClientId $id `
            -ClientSecret $secret -Body @{ grant_type = 'authorization_code'; code = $code; redirect_uri = $uri } `
            -AuthMode 'post'
        Exchanges an authorization code, trying client_secret_post first.

    .EXAMPLE
        $r.AuthMode
        Shows which client authentication method PingFederate accepted.

    .OUTPUTS
        PSCustomObject with Response (the token response) and AuthMode, or $null.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.0
        Date        : 15-OCT-26

        CHANGE LOG
        1.0.0 | 15OCT26 | Initial version. PingFederate provider: token endpoint call with client
                          authentication fallback.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$TokenEndpoint,

        [Parameter(Mandatory)]
        [string]$ClientId,

        [Parameter(Mandatory)]
        [securestring]$ClientSecret,

        [Parameter(Mandatory)]
        [hashtable]$Body,

        # Empty means nothing is cached yet: basic is tried first
        [ValidateSet('basic', 'post', '')]
        [string]$AuthMode,

        [switch]$NullOnInvalidGrant
    )

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
                -ContentType 'application/x-www-form-urlencoded' -Headers $headers -Body $form -ErrorAction Stop

            return [PSCustomObject]@{ Response = $response; AuthMode = $mode }
        } catch {
            $text = $null
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                $text = $_.ErrorDetails.Message
            } elseif ($_.Exception.Response -and $_.Exception.Response.PSObject.Methods['GetResponseStream']) {
                try { $text = [IO.StreamReader]::new($_.Exception.Response.GetResponseStream()).ReadToEnd() } catch { }
            }

            $parsed = $null
            try { $parsed = $text | ConvertFrom-Json } catch { }

            $status = 0
            try { $status = [int]$_.Exception.Response.StatusCode } catch { }
            $code = if ($parsed -and $parsed.PSObject.Properties['error']) { [string]$parsed.error } else { $null }
            $desc = if ($parsed -and $parsed.PSObject.Properties['error_description']) { [string]$parsed.error_description } else { $null }

            if ($code -eq 'invalid_grant' -and $NullOnInvalidGrant) { return $null }

            $lastError = "PingFederate token request failed (HTTP $status, error '$code'$(if ($desc) { ", $desc" }))."

            # Only a client authentication failure is worth retrying with the other method
            if ($code -ne 'invalid_client') { throw $lastError }
            Write-Verbose "Client authentication method [$mode] was refused (invalid_client)."
        }
    }

    throw "$lastError Both client_secret_basic and client_secret_post were refused; check the client id and secret and that the client is a confidential client."
}
