function Resolve-PingFederateRedirectUri {
    <#
    .SYNOPSIS
        Works out the redirect URI for a PingFederate login from a URI, a port, or neither.

    .DESCRIPTION
        The PingFederate provider receives its authorization code on a loopback listener, and the
        redirect URI must match the one registered on the PingFederate client exactly. The port is
        normally assigned to each application when its client is registered, so it can be given on
        its own.

        Rules:
          Neither given   http://127.0.0.1:8080/callback
          Port only       http://127.0.0.1:<port>/callback
          URI only        The URI as given, unchanged.
          Both            The URI with its port set to the given port. If the URI already names a
                          different port the call is refused, unless -PortOverridesUri is set, which
                          lets the port win (a later setting deliberately replacing a saved one).

        Only the text of the URI is rewritten, so the scheme, host, path and query keep the exact
        spelling registered on the client. No loopback check is made here; Wait-PingFederateCallback
        does that.

        Not exported.

    .PARAMETER RedirectUri
        Optional. The redirect URI registered on the client.

    .PARAMETER RedirectPort
        Optional. The loopback port assigned to the application (1 to 65535).

    .PARAMETER PortOverridesUri
        Optional. Lets -RedirectPort replace a different port named in -RedirectUri instead of being
        refused.

    .EXAMPLE
        Resolve-PingFederateRedirectUri
        Returns http://127.0.0.1:8080/callback.

    .EXAMPLE
        Resolve-PingFederateRedirectUri -RedirectPort 9443
        Returns http://127.0.0.1:9443/callback.

    .EXAMPLE
        Resolve-PingFederateRedirectUri -RedirectUri 'http://localhost:47900/callback' -RedirectPort 9443
        Throws: the URI names port 47900 but port 9443 was also given.

    .EXAMPLE
        Resolve-PingFederateRedirectUri -RedirectUri 'http://localhost:47900/callback' -RedirectPort 9443 -PortOverridesUri
        Returns http://localhost:9443/callback.

    .OUTPUTS
        System.String - the redirect URI.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.0
        Date        : 21-OCT-26

        CHANGE LOG
        1.0.0 | 21OCT26 | Initial version. One place for the default redirect port (8080) and for
                          combining a saved URI with a port assigned to the application.
    #>

    [CmdletBinding()]
    [OutputType([string])]
    param (
        [string]$RedirectUri,

        [ValidateRange(1, 65535)]
        [int]$RedirectPort,

        [switch]$PortOverridesUri
    )

    $defaultPort = 8080
    $hasPort     = $PSBoundParameters.ContainsKey('RedirectPort')

    if ([string]::IsNullOrWhiteSpace($RedirectUri)) {
        $port = if ($hasPort) { $RedirectPort } else { $defaultPort }
        return ('http://127.0.0.1:{0}/callback' -f $port)
    }

    if (-not $hasPort) { return $RedirectUri }

    $parts = [regex]::Match($RedirectUri, '^(?<scheme>[A-Za-z][A-Za-z0-9+.-]*://)(?<host>\[[^\]]+\]|[^:/?#]+)(?::(?<port>\d*))?(?<rest>.*)$')
    if (-not $parts.Success) {
        throw "The redirect URI [$RedirectUri] could not be read, so port $RedirectPort cannot be applied to it."
    }

    $existing = $parts.Groups['port'].Value
    if ($existing -and ([int]$existing -ne $RedirectPort) -and -not $PortOverridesUri) {
        throw "The redirect URI [$RedirectUri] names port $existing but port $RedirectPort was also given. Give one of them, or make them agree."
    }

    return ($parts.Groups['scheme'].Value + $parts.Groups['host'].Value + ':' + $RedirectPort + $parts.Groups['rest'].Value)
}