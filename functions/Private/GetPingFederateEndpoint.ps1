function Get-PingFederateEndpoint {
    <#
    .SYNOPSIS
        Resolves the OIDC endpoints of a PingFederate server, by discovery with a default fallback.

    .DESCRIPTION
        Requests {Authority}/.well-known/openid-configuration and returns the issuer and the
        authorization, token and userinfo endpoints. When discovery fails (not published, or not
        reachable without a session) the PingFederate default paths are used instead:
        /as/authorization.oauth2, /as/token.oauth2 and /idp/userinfo.openid. Source says which
        was used. A discovered endpoint is used only when it is on the same host as the
        authority, so a tampered discovery document cannot redirect the client secret elsewhere.

    .PARAMETER Authority
        The PingFederate base URL, for example https://pf.example.com:9031 (no trailing path).

    .PARAMETER TransportOptions
        Optional. The transport, client certificate and CA bundle for the discovery request (see
        Resolve-ServiceTransportOptions).

    .EXAMPLE
        Get-PingFederateEndpoint -Authority 'https://pf.example.com:9031'
        Returns the endpoints and Source 'discovery' or 'default'.

    .EXAMPLE
        (Get-PingFederateEndpoint -Authority 'https://pf.example.com:9031' -Verbose).TokenEndpoint
        Shows why discovery was or was not used and returns the token endpoint.

    .EXAMPLE
        $ep = Get-PingFederateEndpoint -Authority $authority
        $ep.Source
        Shows whether discovery or the default paths supplied the endpoints.

    .OUTPUTS
        PSCustomObject with Issuer, AuthorizationEndpoint, TokenEndpoint, UserInfoEndpoint,
        AuthMethods (string[]) and Source.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.1.0
        Date        : 16-OCT-26

        CHANGE LOG
        1.1.0 | 16OCT26 | Added -TransportOptions for the discovery request.
        1.0.0 | 15OCT26 | Initial version. PingFederate provider: discovery with default fallback.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Authority,

        [hashtable]$TransportOptions
    )

    $Authority     = $Authority.TrimEnd('/')
    $authorityHost = ([uri]$Authority).Authority

    $result = [PSCustomObject]@{
        Issuer                = $Authority
        AuthorizationEndpoint = "$Authority/as/authorization.oauth2"
        TokenEndpoint         = "$Authority/as/token.oauth2"
        UserInfoEndpoint      = "$Authority/idp/userinfo.openid"
        AuthMethods           = @()
        Source                = 'default'
    }

    try {
        $docParams = @{ Method = 'Get'; Uri = "$Authority/.well-known/openid-configuration"; ErrorAction = 'Stop' }
        if ($TransportOptions) { $docParams['TransportOptions'] = $TransportOptions }
        $doc = Invoke-ServiceApiHttpRequest @docParams

        $onHost = {
            param($u)
            $u -and ([uri]$u).Authority -eq $authorityHost
        }

        if ((& $onHost $doc.authorization_endpoint) -and (& $onHost $doc.token_endpoint)) {
            $result.AuthorizationEndpoint = [string]$doc.authorization_endpoint
            $result.TokenEndpoint         = [string]$doc.token_endpoint
            if ($doc.issuer) { $result.Issuer = [string]$doc.issuer }
            if (& $onHost $doc.userinfo_endpoint) { $result.UserInfoEndpoint = [string]$doc.userinfo_endpoint }
            if ($doc.token_endpoint_auth_methods_supported) {
                $result.AuthMethods = @($doc.token_endpoint_auth_methods_supported)
            }
            $result.Source = 'discovery'
        } else {
            Write-Verbose "OIDC discovery for [$Authority] named endpoints on a different host or none at all; using the PingFederate default paths."
        }
    } catch {
        Write-Verbose "OIDC discovery for [$Authority] failed ($($_.Exception.Message)); using the PingFederate default paths."
    }

    return $result
}
