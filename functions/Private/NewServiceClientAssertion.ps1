function New-ServiceClientAssertion {
    <#
    .SYNOPSIS
        Builds a signed JWT client assertion (RFC 7523) for private_key_jwt client authentication.

    .DESCRIPTION
        Creates the assertion a client sends in place of a client secret: a JWT whose issuer and
        subject are the client id, whose audience names the authorization server, and which is
        signed with the private key of the client certificate. Each call has a new jti and a short
        lifetime, so an assertion is single use.

        The algorithm follows the key: RS256 for an RSA key, ES256, ES384 or ES512 for an ECDSA key
        on P-256, P-384 or P-521. The header carries the certificate's SHA-1 thumbprint as x5t so
        the server can match the registered certificate. The private key is used in place and is
        never exported.

        Not exported.

    .PARAMETER Certificate
        An opened client certificate from Get-ServiceClientCertificate (with its X509Certificate2).

    .PARAMETER ClientId
        The OAuth client id, used as both issuer and subject.

    .PARAMETER Audience
        One or more audience values: normally the token endpoint URL and the issuer.

    .PARAMETER LifetimeSeconds
        How long the assertion is valid. Defaults to 120.

    .EXAMPLE
        $jwt = New-ServiceClientAssertion -Certificate $resolved -ClientId 'my-client' -Audience 'https://pf.example.com:9031/as/token.oauth2'
        Builds an assertion for one token request.

    .EXAMPLE
        $jwt = New-ServiceClientAssertion -Certificate $resolved -ClientId $id -Audience $endpoint.TokenEndpoint, $endpoint.Issuer
        $jwt.Split('.').Count

        Names both the token endpoint and the issuer as audience; the result has three segments.

    .EXAMPLE
        & (Get-Module ServiceAPI) { ConvertFrom-JwtPayload -Jwt (New-ServiceClientAssertion -Certificate $r -ClientId 'c' -Audience 'https://as.example.com').ToString() }

        Reads the claims back, to check issuer, subject, audience, jti and expiry.

    .OUTPUTS
        System.String - the compact JWT.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.0
        Date        : 16-OCT-26

        CHANGE LOG
        1.0.0 | 16OCT26 | Initial version. private_key_jwt client assertion signed with RSA or ECDSA keys.
                          Not yet verified against a real PingFederate server.
    #>

    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory)]
        [object]$Certificate,

        [Parameter(Mandatory)]
        [string]$ClientId,

        [Parameter(Mandatory)]
        [string[]]$Audience,

        [ValidateRange(10, 3600)]
        [int]$LifetimeSeconds = 120
    )

    $x509 = $Certificate.Certificate
    if (-not $x509) {
        throw "Signing a client assertion needs the opened certificate and its private key; the certificate was not loaded (a PEM pair needs PowerShell 7 for this)."
    }

    $b64url = {
        param([byte[]]$Bytes)
        [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    }
    $json = { param($Object) & $b64url ([Text.Encoding]::UTF8.GetBytes(($Object | ConvertTo-Json -Compress -Depth 5))) }

    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try { $x5t = & $b64url $sha1.ComputeHash($x509.RawData) } finally { $sha1.Dispose() }

    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($x509)
    $ec  = $null
    if (-not $rsa) { $ec = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($x509) }
    if (-not $rsa -and -not $ec) {
        throw "The client certificate [$($x509.Subject)] has no RSA or ECDSA private key that can sign a client assertion."
    }

    if ($rsa) {
        $alg  = 'RS256'
        $hash = [System.Security.Cryptography.HashAlgorithmName]::SHA256
    } else {
        switch ($ec.KeySize) {
            256     { $alg = 'ES256'; $hash = [System.Security.Cryptography.HashAlgorithmName]::SHA256 }
            384     { $alg = 'ES384'; $hash = [System.Security.Cryptography.HashAlgorithmName]::SHA384 }
            521     { $alg = 'ES512'; $hash = [System.Security.Cryptography.HashAlgorithmName]::SHA512 }
            default { throw "The ECDSA key size $($ec.KeySize) is not supported for a client assertion (P-256, P-384 and P-521 are)." }
        }
    }

    $now    = [DateTimeOffset]::UtcNow
    $header = [ordered]@{ alg = $alg; typ = 'JWT'; x5t = $x5t }
    $claims = [ordered]@{
        iss = $ClientId
        sub = $ClientId
        aud = $(if ($Audience.Count -eq 1) { $Audience[0] } else { @($Audience) })
        jti = [guid]::NewGuid().ToString()
        iat = $now.ToUnixTimeSeconds()
        exp = $now.AddSeconds($LifetimeSeconds).ToUnixTimeSeconds()
    }

    $signingInput = "$(& $json $header).$(& $json $claims)"
    $inputBytes   = [Text.Encoding]::ASCII.GetBytes($signingInput)

    try {
        if ($rsa) {
            $signature = $rsa.SignData($inputBytes, $hash, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        } else {
            $signature = $ec.SignData($inputBytes, $hash)   # IEEE P1363 (r||s), the JWS format
        }
    } finally {
        if ($rsa) { $rsa.Dispose() }
        if ($ec)  { $ec.Dispose() }
    }

    return "$signingInput.$(& $b64url $signature)"
}
