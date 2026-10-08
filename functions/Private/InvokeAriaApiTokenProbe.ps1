function Invoke-AriaApiTokenProbe {
    <#
    .SYNOPSIS
        Reports which API token exchange shapes and which bearers an Aria tenant accepts.

    .DESCRIPTION
        A diagnostic for the AriaApiToken provider. It reads the stored API token (label
        'apitoken'), tries every exchange call shape (Invoke-AriaApiTokenExchange -Probe),
        and sends each resulting bearer to the probe endpoint to show which one the tenant
        accepts. It writes the outcome to the host and changes nothing: no token is cached and
        no token value is ever written to any stream.

        Run it inside the module scope, once, when setting up a tenant:

            & (Get-Module ServiceAPI) { Invoke-AriaApiTokenProbe -Service aria }

        Read the output as follows. A shape reporting 200 OK works on this tenant. A bearer
        reported as accepted is what the module will use (the first accepted, in the order the
        shapes are listed). If no shape works, the status of each shows why: 404 or 405 means
        the shape does not exist on this deployment; 400 or 401 usually means the API token
        is expired, revoked or from another tenant.

    .PARAMETER Service
        A service registered with -SSOProvider AriaApiToken.

    .PARAMETER Environment
        The environment. Defaults to prod.

    .PARAMETER Vault
        Optional. The registered vault holding the API token.

    .EXAMPLE
        & (Get-Module ServiceAPI) { Invoke-AriaApiTokenProbe -Service aria }

        Probes the aria-prod registration.

    .EXAMPLE
        & (Get-Module ServiceAPI) { Invoke-AriaApiTokenProbe -Service aria -Environment qa }

        Probes the aria-qa registration.

    .EXAMPLE
        & (Get-Module ServiceAPI) { Invoke-AriaApiTokenProbe -Service aria -Vault automation }

        Reads the API token from the 'automation' vault.

    .OUTPUTS
        None. Writes a report to the host.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.0
        Date        : 09-OCT-26

        CHANGE LOG
        1.0.0 | 09OCT26 | Initial version. AriaApiToken provider: exchange and bearer diagnostic.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Service,

        [string]$Environment = 'prod',

        [string]$Vault
    )

    $entry = $null
    if ($global:ServiceRegistry.ContainsKey($Service) -and
        $global:ServiceRegistry[$Service].ContainsKey($Environment)) {
        $entry = $global:ServiceRegistry[$Service][$Environment]
    }
    if (-not $entry -or $entry.SSOProvider -ne 'AriaApiToken') {
        throw "[$Service-$Environment] is not registered with -SSOProvider AriaApiToken."
    }

    $baseUrl = $entry.BaseUrl.TrimEnd('/')
    $tenant  = $entry.SSOTenant
    $probe   = Get-ServiceProbeEndpoint -Service $Service -Environment $Environment

    Write-Host "Aria API token probe for [$Service-$Environment] at $baseUrl" -ForegroundColor Cyan
    if ($tenant) {
        Write-Host "Tenant: $tenant" -ForegroundColor Cyan
    } else {
        Write-Host 'Tenant: (none registered; the oauth-tenant shape is skipped)' -ForegroundColor Yellow
    }
    Write-Host "Probe endpoint: $probe" -ForegroundColor Cyan

    $apiToken = Get-AriaApiToken -Service $Service -Environment $Environment -Vault $Vault

    Write-Host "`nExchange shapes:" -ForegroundColor Cyan
    $results = @(Invoke-AriaApiTokenExchange -BaseUrl $baseUrl -ApiToken $apiToken -Tenant $tenant -Probe)

    if ($results.Count -eq 0) {
        Write-Host "`nNo exchange shape produced a token. See the status of each above." -ForegroundColor Red
        return
    }

    Write-Host "`nBearer acceptance at [$probe]:" -ForegroundColor Cyan
    $firstAccepted = $null
    foreach ($result in $results) {
        $ok = Test-ServiceBearer -BaseUrl $baseUrl -Endpoint $probe -Token $result.Token
        $colour = if ($ok) { 'Green' } else { 'Yellow' }
        Write-Host ('{0,-14} ({1,-5}) -> {2}' -f $result.Mode, $result.Kind, $(if ($ok) { 'accepted' } else { 'rejected' })) -ForegroundColor $colour
        if ($ok -and -not $firstAccepted) { $firstAccepted = $result }
    }

    if ($firstAccepted) {
        Write-Host "`nThe module will use the [$($firstAccepted.Mode)] bearer ($($firstAccepted.Kind))." -ForegroundColor Green
    } else {
        Write-Host "`nNo bearer was accepted by the probe endpoint. Check the endpoint is valid for this identity, or register another with -ProbeEndpoint." -ForegroundColor Red
    }
}
