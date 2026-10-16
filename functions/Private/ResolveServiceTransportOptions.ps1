function Resolve-ServiceTransportOptions {
    <#
    .SYNOPSIS
        Combines a request's transport settings with the service's defaults.

    .DESCRIPTION
        Returns the options Invoke-ServiceApiHttpRequest takes in -TransportOptions: the transport
        (DotNet or Curl), the opened client certificate, and the CA bundle for the curl transport.
        A value passed for this request wins; otherwise the registered service's default is used;
        otherwise the built-in default applies (DotNet, no certificate, no extra CA bundle).

        The client certificate is opened here, once per request, so a missing file or a wrong
        password fails before any network call. Not exported.

    .PARAMETER Service
        Optional. The registered service whose defaults apply.

    .PARAMETER Environment
        The environment. Defaults to prod.

    .PARAMETER Transport
        Optional. DotNet or Curl for this request.

    .PARAMETER ClientCertificate
        Optional. A descriptor from New-ServiceClientCertificate for this request.

    .PARAMETER CaBundle
        Optional. A PEM file of trusted CA certificates, used by the curl transport.

    .PARAMETER Vault
        Optional. The registered vault holding the certificate password.

    .PARAMETER RequireCertificate
        Throws when no client certificate is available. Used by AuthType Certificate.

    .PARAMETER SkipCertificate
        Returns the transport and CA bundle without opening a client certificate. Used when the
        certificate is not presented on the connection (for example PingFederate with a client
        secret), so no password prompt is triggered for nothing.

    .EXAMPLE
        $opts = Resolve-ServiceTransportOptions -Service partner
        $opts.Transport

        Returns the service's defaults ('DotNet' when none are registered).

    .EXAMPLE
        $opts = Resolve-ServiceTransportOptions -Service partner -Transport Curl -CaBundle ./roots.pem

        Overrides the transport and CA bundle for one request.

    .EXAMPLE
        $opts = Resolve-ServiceTransportOptions -Service partner -RequireCertificate

        Throws unless a client certificate is passed or registered.

    .OUTPUTS
        Hashtable with Transport (string), Certificate (resolved certificate or $null) and
        CaBundle (string or $null).

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.1.0
        Date        : 16-OCT-26

        CHANGE LOG
        1.1.0 | 16OCT26 | Added -SkipCertificate.
        1.0.0 | 16OCT26 | Initial version. Merges per-request transport settings with the registered
                          service's defaults.
    #>

    [CmdletBinding()]
    param (
        [string]$Service,

        [string]$Environment = 'prod',

        [ValidateSet('DotNet', 'Curl')]
        [string]$Transport,

        [object]$ClientCertificate,

        [string]$CaBundle,

        [string]$Vault,

        [switch]$RequireCertificate,

        [switch]$SkipCertificate
    )

    $entry = $null
    if ($Service -and $global:ServiceRegistry.ContainsKey($Service) -and
        $global:ServiceRegistry[$Service].ContainsKey($Environment)) {
        $entry = $global:ServiceRegistry[$Service][$Environment]
    }

    $effectiveTransport = $Transport
    if (-not $effectiveTransport -and $entry -and $entry.Transport) { $effectiveTransport = $entry.Transport }
    if (-not $effectiveTransport) { $effectiveTransport = 'DotNet' }

    $effectiveSpec = $ClientCertificate
    if (-not $effectiveSpec -and $entry -and $entry.ClientCertificate) { $effectiveSpec = $entry.ClientCertificate }

    $effectiveCa = $CaBundle
    if (-not $effectiveCa -and $entry -and $entry.CaBundle) { $effectiveCa = $entry.CaBundle }
    if ($effectiveCa -and -not (Test-Path -LiteralPath $effectiveCa -PathType Leaf)) {
        throw "The CA bundle [$effectiveCa] was not found."
    }

    $resolved = $null
    if ($effectiveSpec -and -not $SkipCertificate) {
        $resolved = Get-ServiceClientCertificate -Certificate $effectiveSpec -Service $Service -Environment $Environment -Vault $Vault -ForCurl:($effectiveTransport -eq 'Curl')
    } elseif ($RequireCertificate -and -not $SkipCertificate) {
        throw "AuthType Certificate needs a client certificate. Pass -ClientCertificate (see New-ServiceClientCertificate) or register one with Register-CustomService -ClientCertificate."
    }

    return @{
        Transport   = $effectiveTransport
        Certificate = $resolved
        CaBundle    = $effectiveCa
    }
}
