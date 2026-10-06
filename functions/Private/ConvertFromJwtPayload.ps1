
function ConvertFrom-JwtPayload {
    <#
    .SYNOPSIS
        Decodes the payload (claims) of a JWT without verifying its signature.

    .DESCRIPTION
        Splits the token, base64url-decodes the second segment and returns it as an object.
        No signature, issuer or expiry validation is performed — callers use the claims for
        non-security decisions only (for example reading the 'aud' claim to learn the OIDC
        client id). Not exported.

    .PARAMETER Jwt
        The JWT as a plain string.

    .OUTPUTS
        PSCustomObject of the token claims.

    .EXAMPLE
        $claims = ConvertFrom-JwtPayload -Jwt $accessToken
        $claims.exp

        Decodes an access token and reads its expiry claim (seconds since the Unix epoch).

    .EXAMPLE
        $claims = ConvertFrom-JwtPayload -Jwt $response.access_token
        $clientId = if ($claims.aud -is [array]) { [string]$claims.aud[0] } else { [string]$claims.aud }

        Reads the 'aud' claim, which for the Aria portal token is the OIDC client id. The claim
        is a string or an array, so both shapes are handled.

    .EXAMPLE
        try {
            ConvertFrom-JwtPayload -Jwt 'not-a-token'
        } catch {
            Write-Warning $_.Exception.Message
        }

        A value without at least two dot-separated segments throws, so a caller can fall back
        when a token is opaque rather than a JWT.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.1
        Date        : 06-OCT-26

        CHANGE LOG
        1.0.1 | 06OCT26 | Added the three help examples required by the CMF standard.
        1.0.0 | 01OCT26 | Initial version, for the AriaOidc provider.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Jwt
    )

    $parts = $Jwt.Split('.')
    if ($parts.Count -lt 2) {
        throw "Value is not a JWT (expected at least two dot-separated segments)."
    }

    $segment = $parts[1].Replace('-', '+').Replace('_', '/')
    switch ($segment.Length % 4) {
        2 { $segment += '==' }
        3 { $segment += '=' }
    }

    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($segment)) | ConvertFrom-Json
}
